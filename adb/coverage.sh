#!/bin/bash
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

set -euxo pipefail

ADB_TESTS="adbd_test adb_crypto_test adb_pairing_auth_test adb_pairing_connection_test adb_tls_connection_test"

TRACEDIR=`mktemp -d`

adb root

### Run the adb unit tests and fetch traces from them.
mkdir "$TRACEDIR"/test_traces
adb shell rm -rf /data/local/tmp/adb_coverage
adb shell mkdir /data/local/tmp/adb_coverage

for TEST in $ADB_TESTS; do
  adb shell LLVM_PROFILE_FILE=/data/local/tmp/adb_coverage/$TEST.profraw /data/nativetest64/$TEST/$TEST
  adb pull /data/local/tmp/adb_coverage/$TEST.profraw "$TRACEDIR"/test_traces/
done

adb pull /data/local/tmp/adb_coverage "$TRACEDIR"/test_traces

### Run test_device.py, and fetch traces from adbd itself.
adb shell logcat -c -G128M
adb shell setprop persist.adb.trace_mask 1
adb shell killall adbd

# TODO: Add `adb transport-id` and wait-for-offline on it.
sleep 5

adb wait-for-device shell rm -rf "/data/misc/trace/*" /data/local/tmp/adb_coverage/

./test_device.py

# Dump traces from the currently running adbd.
adb shell killall -37 adbd

echo Waiting for adbd to finish dumping traces
sleep 5

adb pull /data/misc/trace "$TRACEDIR"/
echo Pulled traces to $TRACEDIR

# Identify which of the trace files are actually adbd, in case something else exited simultaneously.
ADBD_PIDS=$(adb shell "logcat -d -s adbd --format=process | grep 'adbd started' | cut -c 3-7 | tr -d ' ' | sort | uniq")
mkdir "$TRACEDIR"/adbd_traces

adb shell 'setprop persist.adb.trace_mask 0; killall adbd'

IFS=$'\n'
for PID in $ADBD_PIDS; do
  cp "$TRACEDIR"/trace/clang-$PID-*.profraw "$TRACEDIR"/adbd_traces 2>/dev/null || true
done
unset IFS

ADB_TEST_BINARIES=""
for TEST in $ADB_TESTS; do
  ADB_TEST_BINARIES="--object=$ANDROID_PRODUCT_OUT/data/nativetest64/$TEST/$TEST $ADB_TEST_BINARIES"
done

### Merge the traces and generate a report.
llvm-profdata merge --output="$TRACEDIR"/adbd.profdata "$TRACEDIR"/adbd_traces/* "$TRACEDIR"/test_traces/*

cd $ANDROID_BUILD_TOP
llvm-cov report --instr-profile="$TRACEDIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  --show-region-summary=false \
  /proc/self/cwd/system/core/adb \
  $ADB_TEST_BINARIES

llvm-cov show --instr-profile="$TRACEDIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  --format=html \
  /proc/self/cwd/system/core/adb \
  $ADB_TEST_BINARIES > $TRACEDIR/report.html
