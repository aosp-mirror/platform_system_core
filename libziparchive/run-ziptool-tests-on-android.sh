#!/bin/bash

# Copy the tests across.
adb shell rm -rf /data/local/tmp/ziptool-tests/
adb shell mkdir /data/local/tmp/ziptool-tests/
adb push cli-tests/ /data/local/tmp/ziptool-tests/
#adb push cli-test /data/local/tmp/ziptool-tests/

if tty -s; then
  dash_t="-t"
else
  dash_t=""
fi

exec adb shell $dash_t cli-test /data/local/tmp/ziptool-tests/cli-tests/*.test
