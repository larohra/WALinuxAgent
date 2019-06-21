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
import prctl
import signal
from errno import ESRCH

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


# Demote - set effective Id as the saved Id
def promote_process():
    _, _, suid = os.getresuid()
    _, _, sgid = os.getresgid()

    os.setegid(sgid)
    os.seteuid(suid)


# Promote - set effective Id as the Real Id
def demote_process():
    os.seteuid(os.getuid())
    os.setegid(os.getgid())


# Set the IDs of the current process - RUID - ROOT, Effective+saved = user-id
def initialize_ids(user_id=1000, user_gid=1000):
    # Enable capabilities check
    # https://stackoverflow.com/questions/31883010/unable-to-get-cap-chown-and-cap-dac-override-working-for-regular-user/31891700#31891700
    prctl.securebits.keep_caps = True

    current_uid = os.getuid()
    current_gid = os.getgid()

    os.setgroups([user_gid])
    # Order is important as we would loose privilege to change GID the other way round
    os.setresgid(user_gid, user_gid, current_gid)
    os.setresuid(user_id, user_id, current_uid)

    # Set the capabilities of the process
    # prctl.cap_permitted.limit(prctl.CAP_SETFCAP, prctl.CAP_DAC_OVERRIDE)
    # prctl.cap_inheritable.dac_override = True
    # prctl.cap_inheritable.setfcap = True

    # return (current_uid, user_id, user_id), (current_gid, user_gid, user_gid)


def update_agent_capabilities():
    initialize_ids(1000, 1000)
    # report_ids("After initilialization")

    # subprocess.Popen()

    prctl.cap_effective.dac_override = True
    prctl.cap_effective.dac_read_search = True
    prctl.cap_effective.setfcap = True
    prctl.cap_effective.setpcap = True
    prctl.cap_effective.chown = True
    prctl.cap_effective.fowner = True
    prctl.cap_effective.net_admin = True
    prctl.cap_effective.net_raw = True
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
