#!/system/bin/sh

# Detect host or AOSP.
getprop ro.build.version.sdk > /dev/null 2>&1
if [ $? -eq 0 ]; then
    cmd_prefix=""
    local_root=""
else
    cmd_prefix="adb shell"
    local_root="${ANDROID_PRODUCT_OUT}"
    set -e
    set -x
    adb root
    adb sync data
    set +x
    set +e
fi

testpath64="/data/nativetest64/vts_libsnapshot_test/vts_libsnapshot_test"
testpath32="/data/nativetest/vts_libsnapshot_test/vts_libsnapshot_test"
if [ -f "${local_root}/${testpath64}" ]; then
    testpath="${testpath64}"
elif [ -f "${local_root}/${testpath32}" ]; then
    testpath="${testpath32}"
else
    echo "ERROR: vts_libsnapshot_test not found." 1>&2
    echo "Make sure to build vts_libsnapshot_test or snapshot_tests first." 1>&2
    exit 1
fi

# Verbose, error on failure.
set -x
set -e

time ${cmd_prefix} ${testpath}
