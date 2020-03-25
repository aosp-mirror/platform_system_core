#!/usr/bin/env python
#
# Copyright (C) 2020 The Android Open Source Project
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

"""Unittests for parsing files in zip64 format"""

import os
import subprocess
import tempfile
import unittest
import zipfile
import time

class Zip64Test(unittest.TestCase):
  @staticmethod
  def _AddEntriesToZip(output_zip, entries_dict=None):
    for name, size in entries_dict.items():
      contents = name[0] * 1024
      file_path = tempfile.NamedTemporaryFile()
      with open(file_path.name, 'w') as f:
        for it in range(0, size):
          f.write(contents)
      output_zip.write(file_path.name, arcname = name)

  def _getEntryNames(self, zip_name):
    cmd = ['ziptool', 'zipinfo', '-1', zip_name]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, _ = proc.communicate()
    self.assertEquals(0, proc.returncode)
    self.assertNotEqual(None, output)
    return output.split()

  def _ExtractEntries(self, zip_name):
    temp_dir = tempfile.mkdtemp()
    cmd = ['ziptool', 'unzip', '-d', temp_dir, zip_name]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    proc.communicate()
    self.assertEquals(0, proc.returncode)

  def test_entriesSmallerThan2G(self):
    zip_path = tempfile.NamedTemporaryFile(suffix='.zip')
    # Add a few entries with each of them smaller than 2GiB. But the entire zip file is larger
    # than 4GiB in size.
    with zipfile.ZipFile(zip_path, 'w', allowZip64=True) as output_zip:
      entry_dict = {'a.txt': 1025 * 1024, 'b.txt': 1025 * 1024, 'c.txt': 1025 * 1024,
                    'd.txt': 1025 * 1024, 'e.txt': 1024}
      self._AddEntriesToZip(output_zip, entry_dict)

    read_names = self._getEntryNames(zip_path.name)
    self.assertEquals(sorted(entry_dict.keys()), sorted(read_names))
    self._ExtractEntries(zip_path.name)


  def test_largeNumberOfEntries(self):
    zip_path = tempfile.NamedTemporaryFile(suffix='.zip')
    entry_dict = {}
    # Add 100k entries (more than 65535|UINT16_MAX).
    for num in range(0, 100 * 1024):
      entry_dict[str(num)] = 50

    with zipfile.ZipFile(zip_path, 'w', allowZip64=True) as output_zip:
      self._AddEntriesToZip(output_zip, entry_dict)

    read_names = self._getEntryNames(zip_path.name)
    self.assertEquals(sorted(entry_dict.keys()), sorted(read_names))
    self._ExtractEntries(zip_path.name)


  def test_largeCompressedEntries(self):
    zip_path = tempfile.NamedTemporaryFile(suffix='.zip')
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED,
                         allowZip64=True) as output_zip:
      # Add entries close to 4GiB in size. Somehow the python library will put the (un)compressed
      # sizes in the extra field. Test if our ziptool should be able to parse it.
      entry_dict = {'e.txt': 4095 * 1024, 'f.txt': 4095 * 1024}
      self._AddEntriesToZip(output_zip, entry_dict)

    read_names = self._getEntryNames(zip_path.name)
    self.assertEquals(sorted(entry_dict.keys()), sorted(read_names))
    self._ExtractEntries(zip_path.name)


if __name__ == '__main__':
  testsuite = unittest.TestLoader().discover(
      os.path.dirname(os.path.realpath(__file__)))
  unittest.TextTestRunner(verbosity=2).run(testsuite)
