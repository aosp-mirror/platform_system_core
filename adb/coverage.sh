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

adb root
adb shell logcat -c -G128M
adb shell setprop persist.adb.trace_mask 1
adb shell killall adbd

# TODO: Add `adb transport-id` and wait-for-offline on it.
sleep 5

adb wait-for-device shell rm "/data/misc/trace/*"

./test_device.py

# Dump traces from the currently running adbd.
adb shell killall -37 adbd

echo Waiting for adbd to finish dumping traces
sleep 5

TRACEDIR=`mktemp -d`
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

llvm-profdata merge --output="$TRACEDIR"/adbd.profdata "$TRACEDIR"/adbd_traces/*

cd $ANDROID_BUILD_TOP
llvm-cov report --instr-profile="$TRACEDIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  --show-region-summary=false \
  /proc/self/cwd/system/core/adb

llvm-cov show --instr-profile="$TRACEDIR"/adbd.profdata \
  $ANDROID_PRODUCT_OUT/apex/com.android.adbd/bin/adbd \
  --format=html \
  /proc/self/cwd/system/core/adb > $TRACEDIR/report.html
