set -e

if ! [ -e $ANDROID_BUILD_TOP/external/chromium-trace/systrace.py ]; then
    echo "error: can't find systrace.py at \$ANDROID_BUILD_TOP/external/chromium-trace/systrace.py"
    exit 1
fi

adb shell "sleep 1; atrace -b 65536 --async_start adb sched power freq idle disk mmc load"
adb shell killall adbd
adb wait-for-device
echo "press enter to finish..."
read
TRACE_TEMP=`mktemp /tmp/trace.XXXXXX`
echo Saving trace to ${TRACE_TEMP}, html file to ${TRACE_TEMP}.html
adb shell atrace --async_stop -z > ${TRACE_TEMP}
$ANDROID_BUILD_TOP/external/chromium-trace/systrace.py --from-file=${TRACE_TEMP} -o ${TRACE_TEMP}.html
chrome ${TRACE_TEMP}.html
