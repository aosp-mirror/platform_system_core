#!/usr/bin/env python
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
"""Tests for the adb program itself.

This differs from things in test_device.py in that there is no API for these
things. Most of these tests involve specific error messages or the help text.
"""
from __future__ import print_function

import random
import subprocess
import unittest

import adb


class NonApiTest(unittest.TestCase):
    """Tests for ADB that aren't a part of the AndroidDevice API."""

    def test_help(self):
        """Make sure we get _something_ out of help."""
        out = subprocess.check_output(
            ['adb', 'help'], stderr=subprocess.STDOUT)
        self.assertGreater(len(out), 0)

    def test_version(self):
        """Get a version number out of the output of adb."""
        lines = subprocess.check_output(['adb', 'version']).splitlines()
        version_line = lines[0]
        self.assertRegexpMatches(
            version_line, r'^Android Debug Bridge version \d+\.\d+\.\d+$')
        if len(lines) == 2:
            # Newer versions of ADB have a second line of output for the
            # version that includes a specific revision (git SHA).
            revision_line = lines[1]
            self.assertRegexpMatches(
                revision_line, r'^Revision [0-9a-f]{12}-android$')

    def test_tcpip_error_messages(self):
        p = subprocess.Popen(['adb', 'tcpip'], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        out, _ = p.communicate()
        self.assertEqual(1, p.returncode)
        self.assertIn('help message', out)

        p = subprocess.Popen(['adb', 'tcpip', 'foo'], stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        out, _ = p.communicate()
        self.assertEqual(1, p.returncode)
        self.assertIn('error', out)


def main():
    random.seed(0)
    if len(adb.get_devices()) > 0:
        suite = unittest.TestLoader().loadTestsFromName(__name__)
        unittest.TextTestRunner(verbosity=3).run(suite)
    else:
        print('Test suite must be run with attached devices')


if __name__ == '__main__':
    main()
