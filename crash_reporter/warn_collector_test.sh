#! /bin/bash

# Copyright (C) 2013 The Android Open Source Project
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

# Test for warn_collector.  Run the warn collector in the background, emulate
# the kernel by appending lines to the log file "messages", and observe the log
# of the (fake) crash reporter each time is run by the warn collector daemon.

set -e

fail() {
  printf '[ FAIL ] %b\n' "$*"
  exit 1
}

if [[ -z ${SYSROOT} ]]; then
  fail "SYSROOT must be set for this test to work"
fi
: ${OUT:=${PWD}}
cd "${OUT}"
PATH=${OUT}:${PATH}
TESTLOG="${OUT}/warn-test-log"

echo "Testing: $(which warn_collector)"

cleanup() {
  # Kill daemon (if started) on exit
  kill %
}

check_log() {
  local n_expected=$1
  if [[ ! -f ${TESTLOG} ]]; then
    fail "${TESTLOG} was not created"
  fi
  if [[ $(wc -l < "${TESTLOG}") -ne ${n_expected} ]]; then
    fail "expected ${n_expected} lines in ${TESTLOG}, found this instead:
$(<"${TESTLOG}")"
  fi
  if egrep -qv '^[0-9a-f]{8}' "${TESTLOG}"; then
    fail "found bad lines in ${TESTLOG}:
$(<"${TESTLOG}")"
  fi
}

rm -f "${TESTLOG}"
cp "${SRC}/warn_collector_test_reporter.sh" .
cp "${SRC}/TEST_WARNING" .
cp TEST_WARNING messages

# Start the collector daemon.  With the --test option, the daemon reads input
# from ./messages, writes the warning into ./warning, and invokes
# ./warn_collector_test_reporter.sh to report the warning.
warn_collector --test &
trap cleanup EXIT

# After a while, check that the first warning has been collected.
sleep 1
check_log 1

# Add the same warning to messages, verify that it is NOT collected
cat TEST_WARNING >> messages
sleep 1
check_log 1

# Add a slightly different warning to messages, check that it is collected.
sed s/intel_dp.c/intel_xx.c/ < TEST_WARNING >> messages
sleep 1
check_log 2

# Emulate log rotation, add a warning, and check.
mv messages messages.1
sed s/intel_dp.c/intel_xy.c/ < TEST_WARNING > messages
sleep 2
check_log 3

# Success!
exit 0
