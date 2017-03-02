#!/bin/bash

# Copyright 2017, The Android Open Source Project
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

# Execute ADB test scripts and output zipped logs
# output to $1/adb_tests/ where $1 is DIST_DIR
# The command exits with code 0 only if all test scripts exit with code 0 and
# zip file successfuly created
# All test scripts are expected to exit with code 0, even if the test fails

set -e
LOG_DIR="$1"/adb_tests/
mkdir -p $LOG_DIR
# 2> because TextTestRunner() outputs to std.stderr
/usr/bin/python system/core/adb/test_adb.py 2> $LOG_DIR/test_adb_out.txt
/usr/bin/python system/core/adb/test_device.py 2> $LOG_DIR/test_device_out.txt
zip -j $LOG_DIR/test_all_adb_out.zip $LOG_DIR/*.txt
rm $LOG_DIR/*.txt
