#!/usr/bin/python
#
# Copyright 2022 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test cases for Trusty Linux Driver."""

import os
import unittest

def ReadFile(file_path):
    with open(file_path, 'r') as f:
        # Strip all trailing spaces, newline and null characters.
        return f.read().rstrip(' \n\x00')

def WriteFile(file_path, s):
    with open(file_path, 'w') as f:
        f.write(s)

def IsTrustySupported():
    return os.path.exists("/dev/trusty-ipc-dev0")

@unittest.skipIf(not IsTrustySupported(), "Device does not support Trusty")
class TrustyDriverTest(unittest.TestCase):
    def testIrqDriverBinding(self):
        WriteFile("/sys/bus/platform/drivers/trusty-irq/unbind", "trusty:irq")
        WriteFile("/sys/bus/platform/drivers/trusty-irq/bind", "trusty:irq")

    def testLogDriverBinding(self):
        WriteFile("/sys/bus/platform/drivers/trusty-log/unbind", "trusty:log")
        WriteFile("/sys/bus/platform/drivers/trusty-log/bind", "trusty:log")

    @unittest.skip("TODO(b/142275662): virtio remove currently hangs")
    def testVirtioDriverBinding(self):
        WriteFile("/sys/bus/platform/drivers/trusty-virtio/unbind",
                  "trusty:virtio")
        WriteFile("/sys/bus/platform/drivers/trusty-virtio/bind",
                  "trusty:virtio")

    @unittest.skip("TODO(b/142275662): virtio remove currently hangs")
    def testTrustyDriverBinding(self):
        WriteFile("/sys/bus/platform/drivers/trusty/unbind", "trusty")
        WriteFile("/sys/bus/platform/drivers/trusty/bind", "trusty")

    def testTrustyDriverVersion(self):
        ver = ReadFile("/sys/bus/platform/devices/trusty/trusty_version")
        self.assertTrue(ver.startswith("Project:"))

    def testUntaintedLinux(self):
        tainted = ReadFile("/proc/sys/kernel/tainted")
        self.assertEqual(tainted, "0")

    # stdcall test with shared memory buffers.
    # Each test run takes up to 4 arguments:
    # <obj_size>,<obj_count=1>,<repeat_share=1>,<repeat_access=3>
    #
    # Test single 4K shared memory object.
    # Test 10 8MB objects, shared twice, each accessed twice. (8MB non-
    # contiguous object is large enough to need several 4KB messages to
    # describe)
    # Test sharing 2 8MB objects 100 times without accessing it.
    # Test 10 4K shared memory objects, shared 10 times, each accessed
    # 10 times.
    def testStdCall(self):
        test = "/sys/devices/platform/trusty/trusty:test/trusty_test_run"
        args = "0x1000 0x800000,10,2,2 0x800000,2,100,0 0x1000,10,10,10"
        WriteFile(test, args)

if __name__ == '__main__':
  unittest.main()
