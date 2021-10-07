#!/bin/bash

set -e

if [ -z "$FAIL_RATE" ]; then
    FAIL_RATE=5.0
fi
if [ ! -z "$ANDROID_SERIAL" ]; then
    DEVICE_ARGS=-s $ANDROID_SERIAL
else
    DEVICE_ARGS=
fi

TEST_BIN=/data/nativetest64/snapshot_power_test/snapshot_power_test

while :
do
    adb $DEVICE_ARGS wait-for-device
    adb $DEVICE_ARGS root
    adb $DEVICE_ARGS shell rm $TEST_BIN
    adb $DEVICE_ARGS sync data
    set +e
    output=$(adb $DEVICE_ARGS shell $TEST_BIN merge $FAIL_RATE 2>&1)
    set -e
    if [[ "$output" == *"Merge completed"* ]]; then
        echo "Merge completed."
        break
    fi
    if [[ "$output" == *"Unexpected error"* ]]; then
        echo "Unexpected error."
        exit 1
    fi
done

adb $DEVICE_ARGS shell $TEST_BIN check $1
