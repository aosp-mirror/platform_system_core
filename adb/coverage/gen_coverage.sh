#!/bin/bash

set -euxo pipefail

OUTPUT_DIR=$(dirname "$0")
. "$OUTPUT_DIR"/include.sh

TRACEDIR=`mktemp -d`

### Make sure we can connect to the device.

# Get the device's wlan0 address.
IP_ADDR=$(adb shell ip route get 0.0.0.0 oif wlan0 | sed -En -e 's/.*src (\S+)\s.*/\1/p')
REMOTE_PORT=5555
REMOTE=$IP_ADDR:$REMOTE_PORT
LOCAL_SERIAL=$(adb shell getprop ro.serialno)

# Check that we can connect to it.
adb disconnect

TRANSPORT_ID=$(adb transport-id)
adb tcpip $REMOTE_PORT
adb -t $TRANSPORT_ID wait-for-disconnect

adb connect $REMOTE

REMOTE_FETCHED_SERIAL=$(adb -s $REMOTE shell getprop ro.serialno)

if [[ "$LOCAL_SERIAL" != "$REMOTE_FETCHED_SERIAL" ]]; then
  echo "Mismatch: local serial = $LOCAL_SERIAL, remote serial = $REMOTE_FETCHED_SERIAL"
  exit 1
fi

# Back to USB, and make sure adbd is root.
adb -s $REMOTE usb
adb disconnect $REMOTE

adb wait-for-device root
adb root
adb wait-for-device

TRANSPORT_ID=$(adb transport-id)
adb usb
adb -t $TRANSPORT_ID wait-for-disconnect

adb wait-for-device

### Run the adb unit tests and fetch traces from them.
mkdir "$TRACEDIR"/test_traces
adb shell rm -rf /data/local/tmp/adb_coverage
adb shell mkdir /data/local/tmp/adb_coverage

for TEST in $ADB_TESTS; do
  adb shell LLVM_PROFILE_FILE=/data/local/tmp/adb_coverage/$TEST.profraw /data/nativetest64/$TEST/$TEST
  adb pull /data/local/tmp/adb_coverage/$TEST.profraw "$TRACEDIR"/test_traces/
done

adb pull /data/local/tmp/adb_coverage "$TRACEDIR"/test_traces

# Clear logcat and increase the buffer to something ridiculous so we can fetch the pids of adbd later.
adb shell logcat -c -G128M

# Turn on extremely verbose logging so as to not count debug logging against us.
adb shell setprop persist.adb.trace_mask 1

### Run test_device.py over USB.
TRANSPORT_ID=$(adb transport-id)
adb shell killall adbd
adb -t $TRANSPORT_ID wait-for-disconnect

adb wait-for-device shell rm -rf "/data/misc/trace/*" /data/local/tmp/adb_coverage/
"$OUTPUT_DIR"/../test_device.py

# Do a usb reset to exercise the disconnect code.
adb_usbreset
adb wait-for-device

# Dump traces from the currently running adbd.
adb shell killall -37 adbd

echo Waiting for adbd to finish dumping traces
sleep 5

# Restart adbd in tcp mode.
TRANSPORT_ID=$(adb transport-id)
adb tcpip $REMOTE_PORT
adb -t $TRANSPORT_ID wait-for-disconnect

adb connect $REMOTE
adb -s $REMOTE wait-for-device

# Instead of running test_device.py again, which takes forever, do some I/O back and forth instead.
dd if=/dev/zero bs=1024 count=10240 | adb -s $REMOTE raw sink:10485760
adb -s $REMOTE raw source:10485760 | dd of=/dev/null bs=1024 count=10240

# Dump traces again.
adb disconnect $REMOTE
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

### Merge the traces.
llvm-profdata merge --output="$OUTPUT_DIR"/adbd.profdata "$TRACEDIR"/adbd_traces/* "$TRACEDIR"/test_traces/*
