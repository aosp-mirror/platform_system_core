#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
import subprocess


class FindDeviceError(RuntimeError):
    pass


class DeviceNotFoundError(FindDeviceError):
    def __init__(self, serial):
        self.serial = serial
        super(DeviceNotFoundError, self).__init__(
            'No device with serial {}'.format(serial))


class NoUniqueDeviceError(FindDeviceError):
    def __init__(self):
        super(NoUniqueDeviceError, self).__init__('No unique device')


def get_devices():
    with open(os.devnull, 'wb') as devnull:
        subprocess.check_call(['adb', 'start-server'], stdout=devnull,
                              stderr=devnull)
    out = subprocess.check_output(['adb', 'devices']).splitlines()

    # The first line of `adb devices` just says "List of attached devices", so
    # skip that.
    devices = []
    for line in out[1:]:
        if not line.strip():
            continue
        if 'offline' in line:
            continue

        serial, _ = re.split(r'\s+', line, maxsplit=1)
        devices.append(serial)
    return devices


def _get_unique_device(product=None):
    devices = get_devices()
    if len(devices) != 1:
        raise NoUniqueDeviceError()
    return AndroidDevice(devices[0], product)


def _get_device_by_serial(serial, product=None):
    for device in get_devices():
        if device == serial:
            return AndroidDevice(serial, product)
    raise DeviceNotFoundError(serial)


def get_device(serial=None, product=None):
    """Get a uniquely identified AndroidDevice if one is available.

    Raises:
        DeviceNotFoundError:
            The serial specified by `serial` or $ANDROID_SERIAL is not
            connected.

        NoUniqueDeviceError:
            Neither `serial` nor $ANDROID_SERIAL was set, and the number of
            devices connected to the system is not 1. Having 0 connected
            devices will also result in this error.

    Returns:
        An AndroidDevice associated with the first non-None identifier in the
        following order of preference:

        1) The `serial` argument.
        2) The environment variable $ANDROID_SERIAL.
        3) The single device connnected to the system.
    """
    if serial is not None:
        return _get_device_by_serial(serial, product)

    android_serial = os.getenv('ANDROID_SERIAL')
    if android_serial is not None:
        return _get_device_by_serial(android_serial, product)

    return _get_unique_device(product)


class AndroidDevice(object):
    def __init__(self, serial, product=None):
        self.serial = serial
        self.product = product
        self.adb_cmd = ['adb']
        if self.serial is not None:
            self.adb_cmd.extend(['-s', serial])
        if self.product is not None:
            self.adb_cmd.extend(['-p', product])
        self._linesep = None
        self._shell_result_pattern = None

    @property
    def linesep(self):
        if self._linesep is None:
            self._linesep = subprocess.check_output(['adb', 'shell', 'echo'])
        return self._linesep

    def _make_shell_cmd(self, user_cmd):
        # Follow any shell command with `; echo; echo $?` to get the exit
        # status of a program since this isn't propagated by adb.
        #
        # The leading newline is needed because `printf 1; echo $?` would print
        # "10", and we wouldn't be able to distinguish the exit code.
        rc_probe = '; echo "\n$?"'
        return self.adb_cmd + ['shell'] + user_cmd + [rc_probe]

    def _parse_shell_output(self, out):  # pylint: disable=no-self-use
        search_text = out
        max_result_len = len('{0}255{0}'.format(self.linesep))
        if len(search_text) > max_result_len:
            # We don't want to regex match over massive amounts of data when we
            # know the part we want is right at the end.
            search_text = search_text[-max_result_len:]
        if self._shell_result_pattern is None:
            self._shell_result_pattern = re.compile(
                r'({0}\d+{0})$'.format(self.linesep), re.MULTILINE)
        m = self._shell_result_pattern.search(search_text)
        if m is None:
            raise RuntimeError('Could not find exit status in shell output.')

        result_text = m.group(1)
        result = int(result_text.strip())
        out = out[:-len(result_text)]  # Trim the result text from the output.
        return result, out

    def _simple_call(self, cmd):
        return subprocess.check_output(
            self.adb_cmd + cmd, stderr=subprocess.STDOUT)

    def shell(self, cmd):
        cmd = self._make_shell_cmd(cmd)
        out = subprocess.check_output(cmd)
        rc, out = self._parse_shell_output(out)
        if rc != 0:
            error = subprocess.CalledProcessError(rc, cmd)
            error.out = out
            raise error
        return out

    def shell_nocheck(self, cmd):
        cmd = self._make_shell_cmd(cmd)
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = p.communicate()
        return self._parse_shell_output(out)

    def install(self, filename):
        return self._simple_call(['install', filename])

    def push(self, local, remote):
        return self._simple_call(['push', local, remote])

    def pull(self, remote, local):
        return self._simple_call(['pull', remote, local])

    def sync(self, directory=None):
        cmd = ['sync']
        if directory is not None:
            cmd.append(directory)
        return self._simple_call(cmd)

    def forward(self, local, remote):
        return self._simple_call(['forward', local, remote])

    def tcpip(self, port):
        return self._simple_call(['tcpip', port])

    def usb(self):
        return self._simple_call(['usb'])

    def root(self):
        return self._simple_call(['root'])

    def unroot(self):
        return self._simple_call(['unroot'])

    def forward_remove(self, local):
        return self._simple_call(['forward', '--remove', local])

    def forward_remove_all(self):
        return self._simple_call(['forward', '--remove-all'])

    def connect(self, host):
        return self._simple_call(['connect', host])

    def disconnect(self, host):
        return self._simple_call(['disconnect', host])

    def reverse(self, remote, local):
        return self._simple_call(['reverse', remote, local])

    def reverse_remove_all(self):
        return self._simple_call(['reverse', '--remove-all'])

    def reverse_remove(self, remote):
        return self._simple_call(['reverse', '--remove', remote])

    def wait(self):
        return self._simple_call(['wait-for-device'])

    def get_prop(self, prop_name):
        output = self.shell(['getprop', prop_name]).splitlines()
        if len(output) != 1:
            raise RuntimeError('Too many lines in getprop output:\n' +
                               '\n'.join(output))
        value = output[0]
        if not value.strip():
            return None
        return value

    def set_prop(self, prop_name, value):
        self.shell(['setprop', prop_name, value])
