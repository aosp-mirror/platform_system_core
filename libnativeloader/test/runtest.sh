#!/bin/bash
adb root
adb remount
adb sync
adb shell stop
adb shell start
sleep 5 # wait until device reboots
adb logcat -c;
adb shell am start -n android.test.app.system/android.test.app.TestActivity
adb shell am start -n android.test.app.vendor/android.test.app.TestActivity
adb logcat | grep android.test.app
