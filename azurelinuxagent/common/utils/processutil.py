# Microsoft Azure Linux Agent
#
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#
# You may not use this file except in compliance with the License.
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
import os
import azurelinuxagent.common.logger as logger

from azurelinuxagent.common.exception import ExtensionError
from azurelinuxagent.common.future import ustr

TELEMETRY_MESSAGE_MAX_LEN = 3200


def format_stdout_stderr(stdout, stderr, max_len=TELEMETRY_MESSAGE_MAX_LEN):
    """
    Format stdout and stderr's output to make it suitable in telemetry.
    The goal is to maximize the amount of output given the constraints
    of telemetry.

    For example, if there is more stderr output than stdout output give
    more buffer space to stderr.

    :param str stdout: characters captured from stdout
    :param str stderr: characters captured from stderr
    :param int max_len: maximum length of the string to return

    :return: a string formatted with stdout and stderr that is less than
    or equal to max_len.
    :rtype: str
    """
    template = "[stdout]\n{0}\n\n[stderr]\n{1}"
    # +6 == len("{0}") + len("{1}")
    max_len_each = int((max_len - len(template) + 6) / 2)

    if max_len_each <= 0:
        return ''

    def to_s(captured_stdout, stdout_offset, captured_stderr, stderr_offset):
        s = template.format(captured_stdout[stdout_offset:], captured_stderr[stderr_offset:])
        return s

    if len(stdout) + len(stderr) < max_len:
        return to_s(stdout, 0, stderr, 0)
    elif len(stdout) < max_len_each:
        bonus = max_len_each - len(stdout)
        stderr_len = min(max_len_each + bonus, len(stderr))
        return to_s(stdout, 0, stderr, -1*stderr_len)
    elif len(stderr) < max_len_each:
        bonus = max_len_each - len(stderr)
        stdout_len = min(max_len_each + bonus, len(stdout))
        return to_s(stdout, -1*stdout_len, stderr, 0)
    else:
        return to_s(stdout, -1*max_len_each, stderr, -1*max_len_each)


def update_agent_capabilities():
    from azurelinuxagent.common.event import add_event, WALAEventOperation

    uid = os.getuid()
    gid = os.getgid()

    add_event("WALinuxAgent",
              op=WALAEventOperation.AgentEnabled,
              is_success=True,
              message="ExtHandler Running as - UID: %s and GID: %s" % (uid, gid))

    report_ids("Status after agent starts")
    return


# Promote - set real and effective Id as root
def promote_process():

    r_uid, r_gid = 0, 0

    os.setregid(r_gid, r_gid)
    os.setreuid(r_uid, r_uid)

    report_ids("After process promotion")


# Demote - set real and effective Id as the saved user
def demote_process():

    nr_uid, nr_gid = 1000, 1000

    os.setregid(nr_gid, nr_gid)
    os.setreuid(nr_uid, nr_uid)
    report_ids("after process demotion")


def report_ids(msg="Current IDs"):
    # print_current_capabilities()
    logger.info('%s - (ruid, euid, suid) = %s; (rgid, egid, sgid) = %s' % (msg, os.getresuid(), os.getresgid()))


def get_ext_handler_capabilities():
    capabilities = ['cap_dac_override', 'cap_setgid', 'cap_setuid', 'cap_setpcap', 'cap_chown', 'cap_fowner',
                    'cap_net_admin', 'cap_net_raw']
    return capabilities


def print_current_capabilities():
    import azurelinuxagent.common.utils.shellutil as shellutil

    cmd = "capsh --print | grep -e 'Current set =' -e 'uid='"
    # os.system(cmd)
    rc, out = shellutil.run_get_output(cmd)
    logger.info("RC: %s; Output: %s" % (rc, out))


# Set the IDs of the current process - RUID - ROOT, Effective+saved = user-id
def initialize_ids(user_id=1000, user_gid=1000):
    # Enable capabilities check
    # https://stackoverflow.com/questions/31883010/unable-to-get-cap-chown-and-cap-dac-override-working-for-regular-user/31891700#31891700

    current_uid = os.getuid()
    current_gid = os.getgid()

    os.setgroups([user_gid])
    # Order is important as we would loose privilege to change GID the other way round
    os.setresgid(user_gid, user_gid, current_gid)
    os.setresuid(user_id, user_id, current_uid)
    # initialize_ids(1000, 1000)

    # prctl.cap_effective.setuid = True
    # prctl.cap_effective.setgid = True
    # prctl.cap_effective.dac_override = True
    # # prctl.cap_effective.dac_read_search = True
    # # prctl.cap_effective.setfcap = True
    # prctl.cap_effective.setpcap = True
    # prctl.cap_effective.chown = True
    # prctl.cap_effective.fowner = True
    # prctl.cap_effective.net_admin = True
    # prctl.cap_effective.net_raw = True
    # prctl.cap_effective.net_bind_service = True
    # prctl.cap_effective.net_broadcast = True

    # prctl.cap_effective.audit_control = True
    # prctl.cap_effective.audit_write = True
    # prctl.cap_effective.chown = True
    # prctl.cap_effective.dac_override = True
    # prctl.cap_effective.dac_read_search = True
    # prctl.cap_effective.fowner = True
    # prctl.cap_effective.fsetid = True
    # prctl.cap_effective.ipc_lock = True
    # prctl.cap_effective.ipc_owner = True
    # prctl.cap_effective.kill = True
    # prctl.cap_effective.lease = True
    # prctl.cap_effective.linux_immutable = True
    # prctl.cap_effective.mac_admin = True
    # prctl.cap_effective.mac_override = True
    # prctl.cap_effective.mknod = True
    # prctl.cap_effective.net_admin = True
    # prctl.cap_effective.net_bind_service = True
    # prctl.cap_effective.net_broadcast = True
    # prctl.cap_effective.net_raw = True
    # prctl.cap_effective.setfcap = True
    # prctl.cap_effective.setgid = True
    # prctl.cap_effective.setpcap = True
    # prctl.cap_effective.setuid = True
    # prctl.cap_effective.sys_admin = True
    # prctl.cap_effective.sys_boot = True
    # prctl.cap_effective.sys_chroot = True
    # prctl.cap_effective.sys_module = True
    # prctl.cap_effective.sys_nice = True
    # prctl.cap_effective.sys_pacct = True
    # prctl.cap_effective.sys_ptrace = True
    # prctl.cap_effective.sys_rawio = True
    # prctl.cap_effective.sys_resource = True
    # prctl.cap_effective.sys_time = True
    # prctl.cap_effective.sys_tty_config = True
    # prctl.cap_effective.syslog = True
    # prctl.cap_effective.wake_alarm = True
