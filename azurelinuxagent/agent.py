# Microsoft Azure Linux Agent
#
# Copyright 2018 Microsoft Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Requires Python 2.6+ and Openssl 1.0+
#

"""
Module agent
"""

from __future__ import print_function

import glob
import os
import re
import stat
import subprocess
import sys
import tarfile
import threading
import traceback
from shutil import copy

import azurelinuxagent.common.conf as conf
import azurelinuxagent.common.event as event
import azurelinuxagent.common.logger as logger
from azurelinuxagent.common.osutil import get_osutil
from azurelinuxagent.common.utils import fileutil, shellutil
from azurelinuxagent.common.version import AGENT_NAME, AGENT_LONG_VERSION, \
    DISTRO_NAME, DISTRO_VERSION, \
    PY_VERSION_MAJOR, PY_VERSION_MINOR, \
    PY_VERSION_MICRO, GOAL_STATE_AGENT_VERSION


class Agent(object):
    def __init__(self, verbose, conf_file_path=None):
        """
        Initialize agent running environment.
        """
        self.conf_file_path = conf_file_path
        self.osutil = get_osutil()

        #Init stdout log
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.STDOUT, level)

        #Init config
        conf_file_path = self.conf_file_path \
                if self.conf_file_path is not None \
                    else self.osutil.get_agent_conf_file_path()
        conf.load_conf_from_file(conf_file_path)

        #Init log
        verbose = verbose or conf.get_logs_verbose()
        level = logger.LogLevel.VERBOSE if verbose else logger.LogLevel.INFO
        logger.add_logger_appender(logger.AppenderType.FILE, level,
                                   path=conf.get_agent_log_file())
        if conf.get_logs_console():
            logger.add_logger_appender(logger.AppenderType.CONSOLE, level,
                                       path="/dev/console")

        if event.send_logs_to_telemetry():
            logger.add_logger_appender(logger.AppenderType.TELEMETRY,
                                       logger.LogLevel.WARNING,
                                       path=event.add_log_event)

        ext_log_dir = conf.get_ext_log_dir()
        try:
            if os.path.isfile(ext_log_dir):
                raise Exception("{0} is a file".format(ext_log_dir))
            if not os.path.isdir(ext_log_dir):
                fileutil.mkdir(ext_log_dir, mode=0o755, owner="root")
        except Exception as e:
            logger.error(
                "Exception occurred while creating extension "
                "log directory {0}: {1}".format(ext_log_dir, e))

        # Init event reporter
        # Note that the reporter is not fully initialized here yet. Some telemetry fields are filled with data
        # originating from the goal state or IMDS, which requires a WireProtocol instance. Once a protocol
        # has been established, those fields must be explicitly initialized using
        # initialize_event_logger_vminfo_common_parameters(). Any events created before that initialization
        # will contain dummy values on those fields.
        event.init_event_status(conf.get_lib_dir())
        event_dir = os.path.join(conf.get_lib_dir(), event.EVENTS_DIRECTORY)
        event.init_event_logger(event_dir)
        event.enable_unhandled_err_dump("WALA")

    def daemon(self):
        """
        Run agent daemon
        """
        logger.set_prefix("Daemon")
        threading.current_thread().setName("Daemon")
        child_args = None \
            if self.conf_file_path is None \
                else "-configuration-path:{0}".format(self.conf_file_path)

        from azurelinuxagent.daemon import get_daemon_handler
        daemon_handler = get_daemon_handler()
        daemon_handler.run(child_args=child_args)

    def provision(self):
        """
        Run provision command
        """
        from azurelinuxagent.pa.provision import get_provision_handler
        provision_handler = get_provision_handler()
        provision_handler.run()

    def deprovision(self, force=False, deluser=False):
        """
        Run deprovision command
        """
        from azurelinuxagent.pa.deprovision import get_deprovision_handler
        deprovision_handler = get_deprovision_handler()
        deprovision_handler.run(force=force, deluser=deluser)

    def register_service(self):
        """
        Register agent as a service
        """
        print("Register {0} service".format(AGENT_NAME))
        self.osutil.register_agent_service()
        print("Stop {0} service".format(AGENT_NAME))
        self.osutil.stop_agent_service()
        print("Start {0} service".format(AGENT_NAME))
        self.osutil.start_agent_service()

    def run_exthandlers(self, debug=False):
        """
        Run the update and extension handler
        """
        logger.set_prefix("ExtHandler")
        threading.current_thread().setName("ExtHandler")
        from azurelinuxagent.ga.update import get_update_handler
        update_handler = get_update_handler()
        update_handler.run(debug)

    def show_configuration(self):
        configuration = conf.get_configuration()
        for k in sorted(configuration.keys()):
            print("{0} = {1}".format(k, configuration[k]))


def check_venv_exists(venv_name):
    return os.path.exists("/var/lib/waagent/{0}".format(venv_name))


def download_and_setup_agent_py_interpreter(agent_py_path):
    # py_38_download_link = "https://www.python.org/ftp/python/3.8.5/Python-3.8.5.tgz"
    # Assuming the tar file is already present in the box
    py_version = "Python-3.8.5"
    py_dir = os.path.join(agent_py_path, py_version)
    tar_file = os.path.join(agent_py_path, "{0}.tgz".format(py_version))
    if not os.path.exists(tar_file):
        raise IOError("Tar file {0} not found".format(tar_file))

    setup_py_file_name = "setup_python.sh"
    copy(os.path.join(os.path.dirname(os.path.abspath(__file__)), setup_py_file_name), py_dir)

    os.chmod(os.path.join(py_dir, setup_py_file_name), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    if not os.path.exists(py_dir):
        with tarfile.open(tar_file) as tf:
            tf.extractall(path=agent_py_path)

    rc, stdout = shellutil.run_get_output(os.path.join(py_dir, setup_py_file_name), chk_err=True)
    logger.info("Python setup output RC: {0} - {1}".format(rc, stdout))
    if rc != 0:
        raise Exception("Python interpreter setup failed")


def download_and_setup_venv(venv_path, agent_py_exe_path):
    # File link - https://files.pythonhosted.org/packages/15/cd/9bbb31845faec1e3848edcc4645411952a9a2a91a21c5c0fb6b84d929c5f/virtualenv-20.0.28.tar.gz
    # Assuming already there in the path
    venv_version = "virtualenv-20.0.28"
    tar_file = os.path.join(venv_path, "{0}.tar.gz".format(venv_version))
    if not os.path.exists(tar_file):
        raise IOError("Tar file {0} not found".format(tar_file))

    if not os.path.exists(os.path.join(venv_path, venv_version)):
        with tarfile.open(tar_file) as tf:
            tf.extractall(path=venv_path)

    stdout = shellutil.run_command([agent_py_exe_path, glob.glob(os.path.join(venv_path, "*", "setup.py"))[0], "install"], log_error=True)
    logger.info("Setting up virtualenv output - {0}".format(stdout))


def try_setup_venv(venv_name):
    agent_venv_path = "/var/lib/waagent/{0}".format(venv_name)
    agent_py_path = "/var/lib/waagent/agent_python/python/"
    installed_venv_path = "/var/lib/waagent/agent_python/virtualenv"
    installed_venv_exe_path = os.path.join(installed_venv_path, "bin", "virtualenv")
    agent_py_exe_path = os.path.join(agent_py_path, "bin", "python3.8")
    # Check if agent interpreter exists
    if not os.path.exists(agent_py_exe_path):
        download_and_setup_agent_py_interpreter(agent_py_path)

    # Check if virtualenv exists
    if not os.path.exists(installed_venv_exe_path):
        download_and_setup_venv(installed_venv_path, agent_py_exe_path)

    # Finally create a new virtual environment with the agent interpreter and virtualenv
    command = [installed_venv_exe_path, agent_venv_path, "--python", agent_py_exe_path]
    stdout = shellutil.run_command(command, log_error=True)
    logger.info("Creating venv = {0}".format(stdout))

    # Activate the virtualenv for the daemon
    activate_this = os.path.join(agent_venv_path, "bin", "activate_this.py")
    with open(activate_this) as f:
        code = compile(f.read(), activate_this, 'exec')
        exec (code, dict(__file__=activate_this))

    logger.info("Activated the virtual env for this process. Test python version: {0}".format(sys.version_info))


def ensure_venv_setup(venv_name="waagent-venv"):
    # Check if venv already exists in /var/lib/waagent/agent-venv. If not try setting it up.
    # If anything fails, let it go and let it start normally
    try:
        if check_venv_exists(venv_name):
            logger.info("{0} already exists! Not resetting it.".format(venv_name))
            return
        try_setup_venv(venv_name)
    except Exception as e:
        logger.error("Error when trying to setup {0}. Error: {1}".format(venv_name, e))
        logger.warn("Using system python instead")


def main(args=[]):
    """
    Parse command line arguments, exit with usage() on error.
    Invoke different methods according to different command
    """

    # Before doing anything else, check to see if venv already setup or not. If not, then try setting it up.
    ensure_venv_setup()
    if len(args) <= 0:
        args = sys.argv[1:]
    command, force, verbose, debug, conf_file_path = parse_args(args)
    if command == "version":
        version()
    elif command == "help":
        print(usage())
    elif command == "start":
        start(conf_file_path=conf_file_path)
    else:
        try:
            agent = Agent(verbose, conf_file_path=conf_file_path)
            if command == "deprovision+user":
                agent.deprovision(force, deluser=True)
            elif command == "deprovision":
                agent.deprovision(force, deluser=False)
            elif command == "provision":
                agent.provision()
            elif command == "register-service":
                agent.register_service()
            elif command == "daemon":
                agent.daemon()
            elif command == "run-exthandlers":
                agent.run_exthandlers(debug)
            elif command == "show-configuration":
                agent.show_configuration()
        except Exception:
            logger.error(u"Failed to run '{0}': {1}",
                         command,
                         traceback.format_exc())

def parse_args(sys_args):
    """
    Parse command line arguments
    """
    cmd = "help"
    force = False
    verbose = False
    debug = False
    conf_file_path = None
    for a in sys_args:
        m = re.match("^(?:[-/]*)configuration-path:([\w/\.\-_]+)", a)
        if not m is None:
            conf_file_path = m.group(1)
            if not os.path.exists(conf_file_path):
                print("Error: Configuration file {0} does not exist".format(
                        conf_file_path), file=sys.stderr)
                usage()
                sys.exit(1)
        
        elif re.match("^([-/]*)deprovision\\+user", a):
            cmd = "deprovision+user"
        elif re.match("^([-/]*)deprovision", a):
            cmd = "deprovision"
        elif re.match("^([-/]*)daemon", a):
            cmd = "daemon"
        elif re.match("^([-/]*)start", a):
            cmd = "start"
        elif re.match("^([-/]*)register-service", a):
            cmd = "register-service"
        elif re.match("^([-/]*)run-exthandlers", a):
            cmd = "run-exthandlers"
        elif re.match("^([-/]*)version", a):
            cmd = "version"
        elif re.match("^([-/]*)verbose", a):
            verbose = True
        elif re.match("^([-/]*)debug", a):
            debug = True
        elif re.match("^([-/]*)force", a):
            force = True
        elif re.match("^([-/]*)show-configuration", a):
            cmd = "show-configuration"
        elif re.match("^([-/]*)(help|usage|\\?)", a):
            cmd = "help"
        else:
            cmd = "help"
            break

    return cmd, force, verbose, debug, conf_file_path


def version():
    """
    Show agent version
    """
    print(("{0} running on {1} {2}".format(AGENT_LONG_VERSION,
                                           DISTRO_NAME,
                                           DISTRO_VERSION)))
    print("Python: {0}.{1}.{2}".format(PY_VERSION_MAJOR,
                                       PY_VERSION_MINOR,
                                       PY_VERSION_MICRO))
    print("Goal state agent: {0}".format(GOAL_STATE_AGENT_VERSION))

def usage():
    """
    Return agent usage message
    """
    s  = "\n"
    s += ("usage: {0} [-verbose] [-force] [-help] "
           "-configuration-path:<path to configuration file>"
           "-deprovision[+user]|-register-service|-version|-daemon|-start|"
           "-run-exthandlers|-show-configuration]"
           "").format(sys.argv[0])
    s += "\n"
    return s

def start(conf_file_path=None):
    """
    Start agent daemon in a background process and set stdout/stderr to
    /dev/null
    """
    devnull = open(os.devnull, 'w')
    args = [sys.argv[0], '-daemon']
    if conf_file_path is not None:
        args.append('-configuration-path:{0}'.format(conf_file_path))
    subprocess.Popen(args, stdout=devnull, stderr=devnull)

if __name__ == '__main__' :
    main()
