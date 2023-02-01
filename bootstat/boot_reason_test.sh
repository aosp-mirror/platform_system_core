#! /bin/bash
#
# Bootstat boot reason tests
#
# throughout testing:
# - manual tests can only run on eng/userdebug builds
# - watch adb logcat -b all -d -s bootstat
# - watch adb logcat -b all -d | audit2allow
# - wait until screen is up, boot has completed, can mean wait for
#   sys.boot_completed=1 and sys.bootstat.first_boot_completed=1 to be true
#
# All test frames, and nothing else, must be function names prefixed and
# specifiged with the pattern 'test_<test>() {' as this is also how the
# script discovers the full list of tests by inspecting its own code.
#

# Helper variables

SPACE=" "
ESCAPE=""
TAB="	"
GREEN="${ESCAPE}[38;5;40m"
RED="${ESCAPE}[38;5;196m"
NORMAL="${ESCAPE}[0m"
# Best guess to an average device's reboot time, refined as tests return
DURATION_DEFAULT=45
STOP_ON_FAILURE=false
progname="${0##*/}"
progpath="${0%${progname}}"

# Helper functions

[ "USAGE: inFastboot

Returns: true if device is in fastboot mode" ]
inFastboot() {
  fastboot devices | grep "^${ANDROID_SERIAL}[${SPACE}${TAB}]" > /dev/null
}

[ "USAGE: inAdb

Returns: true if device is in adb mode" ]
inAdb() {
  adb devices | grep -v 'List of devices attached' | grep "^${ANDROID_SERIAL}[${SPACE}${TAB}]" > /dev/null
}

[ "USAGE: adb_sh <commands> </dev/stdin >/dev/stdout 2>/dev/stderr

Returns: true if the command succeeded" ]
adb_sh() {
  local args=
  for i in "${@}"; do
    [ -z "${args}" ] || args="${args} "
    if [ X"${i}" != X"${i#\'}" ]; then
      args="${args}${i}"
    elif [ X"${i}" != X"${i#*\\}" ]; then
      args="${args}`echo ${i} | sed 's/\\\\/\\\\\\\\/g'`"
    elif [ X"${i}" != X"${i#* }" ]; then
      args="${args}'${i}'"
    elif [ X"${i}" != X"${i#*${TAB}}" ]; then
      args="${args}'${i}'"
    else
      args="${args}${i}"
    fi
  done
  adb shell "${args}"
}

[ "USAGE: adb_su <commands> </dev/stdin >/dev/stdout 2>/dev/stderr

Returns: true if the command running as root succeeded" ]
adb_su() {
  adb_sh su root "${@}"
}

[ "USAGE: hasPstore

Returns: true if device (likely) has pstore data" ]
hasPstore() {
  if inAdb && [ 0 -eq `adb_su ls /sys/fs/pstore </dev/null | wc -l` ]; then
    false
  fi
}

[ "USAGE: get_property <prop>

Returns the property value" ]
get_property() {
  adb_sh getprop ${1} 2>&1 </dev/null
}

[ "USAGE: isDebuggable

Returns: true if device is (likely) a debug build" ]
isDebuggable() {
  if inAdb && [ 1 -ne `get_property ro.debuggable` ]; then
    false
  fi
}

[ "USAGE: checkDebugBuild [--noerror]

Returns: true if device is a userdebug or eng release" ]
checkDebugBuild() {
  if isDebuggable; then
    echo "INFO: '${TEST}' test requires userdebug build"
  elif [ -n "${1}" ]; then
    echo "WARNING: '${TEST}' test requires userdebug build"
    false
  else
    echo "ERROR: '${TEST}' test requires userdebug build, skipping FAILURE"
    duration_prefix="~"
    duration_estimate=1
    false
  fi >&2
}

[ "USAGE: setBootloaderBootReason [value]

Returns: true if device supports and set boot reason injection" ]
setBootloaderBootReason() {
  inAdb || ( echo "ERROR: device not in adb mode." >&2 ; false ) || return 1
  if [ -z "`adb_sh ls /etc/init/bootstat-debug.rc 2>/dev/null </dev/null`" ]; then
    echo "ERROR: '${TEST}' test requires /etc/init/bootstat-debug.rc" >&2
    return 1
  fi
  checkDebugBuild || return 1
  if adb_su "cat /proc/cmdline | tr '\\0 ' '\\n\\n'" </dev/null |
     grep '^androidboot[.]bootreason=[^ ]' >/dev/null; then
    echo "ERROR: '${TEST}' test requires a device with a bootloader that" >&2
    echo "       does not set androidboot.bootreason kernel parameter." >&2
    return 1
  fi
  adb_su setprop persist.test.boot.reason "'${1}'" 2>/dev/null </dev/null
  test_reason="`get_property persist.test.boot.reason`"
  if [ X"${test_reason}" != X"${1}" ]; then
    echo "ERROR: can not set persist.test.boot.reason to '${1}'." >&2
    return 1
  fi
}

[ "USAGE: enterPstore

Prints a warning string requiring functional pstore

Returns: pstore_ok variable set to true or false" ]
enterPstore() {
  if hasPstore; then
    echo "INFO: '${TEST}' test requires functional and reliable pstore"
    pstore_ok=true
  else
    echo "WARNING: '${TEST}' test requires functional pstore"
    pstore_ok=false
  fi >&2
  ${pstore_ok}
}

[ "USAGE: exitPstore

Prints an error string requiring functional pstore

Returns: clears error if pstore dysfunctional" ]
exitPstore() {
  save_ret=${?}
  if [ ${save_ret} != 0 ]; then
    if hasPstore; then
      return ${save_ret}
    fi
    if [ true = ${pstore_ok} ]; then
      echo "WARNING: '${TEST}' test requires functional pstore"
      return ${save_ret}
    fi
    echo "ERROR: '${TEST}' test requires functional pstore, skipping FAILURE"
    duration_prefix="~"
    duration_estimate=1
  fi >&2
}

[ "USAGE: format_duration <seconds>

human readable output whole seconds, whole minutes or mm:ss" ]
format_duration() {
  if [ -z "${1}" ]; then
    echo unknown
    return
  fi
  seconds=`expr ${1} % 60`
  minutes=`expr ${1} / 60`
  if [ 0 -eq ${minutes} ]; then
    if [ 1 -eq ${1} ]; then
      echo 1 second
      return
    fi
    echo ${1} seconds
    return
  elif [ 60 -eq ${1} ]; then
    echo 1 minute
    return
  elif [ 0 -eq ${seconds} ]; then
    echo ${minutes} minutes
    return
  fi
  echo ${minutes}:`expr ${seconds} / 10``expr ${seconds} % 10`
}

wait_for_screen_timeout=900
[ "USAGE: wait_for_screen [-n] [TIMEOUT]

-n - echo newline at exit
TIMEOUT - default `format_duration ${wait_for_screen_timeout}`" ]
wait_for_screen() {
  exit_function=true
  if [ X"-n" = X"${1}" ]; then
    exit_function=echo
    shift
  fi
  timeout=${wait_for_screen_timeout}
  if [ ${#} -gt 0 ]; then
    timeout=${1}
    shift
  fi
  counter=0
  while true; do
    if inFastboot; then
      fastboot reboot
    elif inAdb; then
      if [ 0 != ${counter} ]; then
        adb wait-for-device </dev/null >/dev/null 2>/dev/null
      fi
      if [ -n "`get_property sys.boot.reason`" ]
      then
        vals=`get_property |
              sed -n 's/[[]sys[.]\(boot_completed\|logbootcomplete\|bootstat[.]first_boot_completed\)[]]: [[]\([01]\)[]]$/\1=\2/p'`
        if [ X"${vals}" != X"${vals##*boot_completed=1}" ]; then
          if [ X"${vals}" != X"${vals##*logbootcomple=1}" ]; then
            sleep 1
            break
          fi
          if [ X"${vals}" != X"${vals##*bootstat.first_boot_completed=1}" ]; then
            sleep 1
            break
          fi
        fi
      fi
    fi
    counter=`expr ${counter} + 1`
    if [ ${counter} -gt ${timeout} ]; then
      ${exit_function}
      echo "ERROR: wait_for_screen() timed out (`format_duration ${timeout}`)" >&2
      return 1
    fi
    sleep 1
  done
  ${exit_function}
}

[ "USAGE: EXPECT_EQ <lval> <rval> [message]

Returns true if (regex) lval matches rval" ]
EXPECT_EQ() {
  lval="${1}"
  rval="${2}"
  shift 2
  if ! ( echo X"${rval}" | grep '^X'"${lval}"'$' >/dev/null 2>/dev/null ); then
    if [ `echo ${lval}${rval}${*} | wc -c` -gt 50 -o "${rval}" != "${rval%
*}" ]; then
      echo "ERROR: expected \"${lval}\"" >&2
      echo "       got \"${rval}\"" |
        sed ': again
             N
             s/\(\n\)\([^ ]\)/\1             \2/
             t again' >&2
      if [ -n "${*}" ] ; then
        echo "       ${*}" >&2
      fi
    else
      echo "ERROR: expected \"${lval}\" got \"${rval}\" ${*}" >&2
    fi
    return 1
  fi
  if [ -n "${*}" ] ; then
    if [ X"${lval}" != X"${rval}" ]; then
      if [ `echo ${lval}${rval}${*} | wc -c` -gt 60 -o "${rval}" != "${rval%
*}" ]; then
        echo "INFO: ok \"${lval}\"" >&2
        echo "       = \"${rval}\"" |
          sed ': again
               N
               s/\(\n\)\([^ ]\)/\1          \2/
               t again' >&2
        if [ -n "${*}" ] ; then
          echo "      ${*}" >&2
        fi
      else
        echo "INFO: ok \"${lval}\" = \"${rval}\" ${*}" >&2
      fi
    else
      echo "INFO: ok \"${lval}\" ${*}" >&2
    fi
  fi
  return 0
}

BAD_BOOTLOADER_REASON=

[ "USAGE: EXPECT_PROPERTY <prop> <value> [--allow_failure]

Returns true (0) if current return (regex) value is true and the result matches
and the incoming return value is true as well (wired-or)" ]
EXPECT_PROPERTY() {
  save_ret=${?}
  property="${1}"
  value="${2}"
  shift 2
  val=`get_property ${property}`
  EXPECT_EQ "${value}" "${val}" for Android property ${property}
  local_ret=${?}
  if [ 0 != ${local_ret} -a "ro.boot.bootreason" = "${property}" ]; then
    if [ -z "${BAD_BOOTLOADER_REASON}" ]; then
      BAD_BOOTLOADER_REASON=${val}
    elif [ X"${BAD_BOOTLOADER_REASON}" = X"${val}" ]; then
      local_ret=0
    fi
  fi
  if [ 0 != ${local_ret} ]; then
    if [ -z "${1}" ] ; then
      save_ret=${local_ret}
    fi
  fi
  return ${save_ret}
}

[ "USAGE: adb_date >/dev/stdout

Returns: report device epoch time (suitable for logcat -t)" ]
adb_date() {
  adb_sh date +%s.%N </dev/null
}

[ "USAGE: report_bootstat_logs [-t<timestamp>] <expected> ...

if not prefixed with a minus (-), <expected> will become a series of expected
matches:

    bootstat: Canonical boot reason: <expected_property_value>

If prefixed with a minus, <expected> will look for an exact match after
removing the minux prefix.  All expected content is _dropped_ from the output
and in essence forms a known blacklist, unexpected content will show.

Report any logs, minus a known blacklist, preserve the current exit status" ]
report_bootstat_logs() {
  save_ret=${?}
  match=
  timestamp=-d
  for i in "${@}"; do
    if [ X"${i}" != X"${i#-t}" ]; then
      timestamp="${i}"
    elif [ X"${i}" != X"${i#-}" ]; then
      match="${match}
${i#-}"
    else
      match="${match}
bootstat: Canonical boot reason: ${i}"
    fi
  done
  adb logcat -b all ${timestamp} |
  grep bootstat[^e] |
  grep -v -F "bootstat: Service started: /system/bin/bootstat --record_boot_complete${match}
bootstat: Service started: /system/bin/bootstat --record_boot_reason
bootstat: Service started: /system/bin/bootstat --set_system_boot_reason
bootstat: Service started: /system/bin/bootstat --record_time_since_factory_reset
bootstat: Service started: /system/bin/bootstat -l
bootstat: Service started: /system/bin/bootstat --set_system_boot_reason --record_boot_complete --record_boot_reason --record_time_since_factory_reset -l
bootstat: Battery level at shutdown 100%
bootstat: Battery level at startup 100%
init    : Parsing file /system/etc/init/bootstat.rc...
init    : Parsing file /system/etc/init/bootstat-debug.rc...
init    : processing action (persist.test.boot.reason=*) from (/system/etc/init/bootstat-debug.rc:
init    : Command 'setprop ro.boot.bootreason \${persist.test.boot.reason}' action=persist.test.boot.reason=* (/system/etc/init/bootstat-debug.rc:
init    : processing action (post-fs-data) from (/system/etc/init/bootstat.rc
init    : processing action (boot) from (/system/etc/init/bootstat.rc
init    : processing action (ro.boot.bootreason=*) from (/system/etc/init/bootstat.rc
init    : processing action (ro.boot.bootreason=* && post-fs) from (/system/etc/init/bootstat.rc
init    : processing action (sys.bootstat.first_zygote_start=0 && zygote-start) from (/system/etc/init/bootstat.rc
init    : processing action (sys.boot_completed=1 && sys.bootstat.first_boot_completed=0) from (/system/etc/init/bootstat.rc
 (/system/bin/bootstat --record_boot_complete --record_boot_reason --record_time_since_factory_reset -l)'
 (/system/bin/bootstat --set_system_boot_reason --record_boot_complete --record_boot_reason --record_time_since_factory_reset -l)'
init    : Command 'exec - system log -- /system/bin/bootstat --record_boot_complete' action=sys.boot_completed=1 && sys.bootstat.first_boot_completed=0 (/system/etc/init/bootstat.rc:
init    : Command 'exec - system log -- /system/bin/bootstat --record_boot_reason' action=sys.boot_completed=1 && sys.bootstat.first_boot_completed=0 (/system/etc/init/bootstat.rc:
init    : Command 'exec - system log -- /system/bin/bootstat --record_time_since_factory_reset' action=sys.boot_completed=1 && sys.bootstat.first_boot_completed=0 (/system/etc/init/bootstat.rc:
init    : Command 'exec_background - system log -- /system/bin/bootstat --set_system_boot_reason --record_boot_complete --record_boot_reason --record_time_since_factory_reset -l' action=sys.boot_completed=1 && sys.bootstat.first_boot_completed=0 (/system/etc/init/bootstat.rc
 (/system/bin/bootstat --record_boot_complete)'...
 (/system/bin/bootstat --record_boot_complete)' (pid${SPACE}
 (/system/bin/bootstat --record_boot_reason)'...
 (/system/bin/bootstat --record_boot_reason)' (pid${SPACE}
 (/system/bin/bootstat --record_time_since_factory_reset)'...
 (/system/bin/bootstat --record_time_since_factory_reset)' (pid${SPACE}
 (/system/bin/bootstat --set_system_boot_reason)'...
 (/system/bin/bootstat --set_system_boot_reason)' (pid${SPACE}
 (/system/bin/bootstat -l)'...
 (/system/bin/bootstat -l)' (pid " |
  grep -v 'bootstat: Unknown boot reason: $' # Hikey Special
  return ${save_ret}
}

[ "USAGE: start_test [message]

Record start of test, preserve exit status" ]
start_test() {
  save_ret=${?}
  duration_prefix="~"
  duration_estimate=1
  START=`date +%s`
  echo "${GREEN}[ RUN      ]${NORMAL} ${TEST} ${*}"
  return ${save_ret}
}

duration_sum_diff=0
duration_num=0
[ "USAGE: duration_test [[prefix]seconds]

Report the adjusted and expected test duration" ]
duration_test() {
  duration_prefix=${1%%[0123456789]*}
  if [ -z "${duration_prefix}" ]; then
    duration_prefix="~"
  fi
  duration_estimate="${1#${duration_prefix}}"
  if [ -z "${duration_estimate}" ]; then
    duration_estimate="${DURATION_DEFAULT}"
  fi
  duration_new_estimate="${duration_estimate}"
  if [ 0 -ne ${duration_num} ]; then
    duration_new_estimate=`expr ${duration_new_estimate} + \
      \( ${duration_num} / 2 + ${duration_sum_diff} \) / ${duration_num}`
    # guard against catastrophe
    if [ -z "${duration_new_estimate}" ]; then
      duration_new_estimate=${duration_estimate}
    fi
  fi
  # negative values are so undignified
  if [ 0 -ge ${duration_new_estimate} ]; then
    duration_new_estimate=1
  fi
  echo "INFO: expected duration of '${TEST}' test" \
       "${duration_prefix}`format_duration ${duration_new_estimate}`" >&2
}

[ "USAGE: end_test [message]

Document duration and success of test, preserve exit status" ]
end_test() {
  save_ret=${?}
  END=`date +%s`
  duration=`expr ${END} - ${START} 2>/dev/null`
  [ 0 -ge ${duration} ] ||
    echo "INFO: '${TEST}' test duration `format_duration ${duration}`" >&2
  if [ ${save_ret} = 0 ]; then
    if [ 0 -lt ${duration} -a 0 -lt ${duration_estimate} -a \( \
           X"~" = X"${duration_prefix}" -o \
           ${duration_estimate} -gt ${duration} \) ]; then
      duration_sum_diff=`expr ${duration_sum_diff} + \
                              ${duration} - ${duration_estimate}`
      duration_num=`expr ${duration_num} + 1`
    fi
    echo "${GREEN}[       OK ]${NORMAL} ${TEST} ${*}"
  else
    echo "${RED}[  FAILED  ]${NORMAL} ${TEST} ${*}"
    if ${STOP_ON_FAILURE}; then
      exit ${save_ret}
    fi
  fi
  return ${save_ret}
}

[ "USAGE: wrap_test <test> [message]

All tests below are wrapped with this helper" ]
wrap_test() {
  if [ -z "${1}" -o X"nothing" = X"${1}" ]; then
    return
  fi
  TEST=${1}
  shift
  start_test ${1}
  eval test_${TEST}
  end_test ${2}
}

[ "USAGE: validate_reason <value>

Check property for CTS compliance with our expectations. Return a cleansed
string representing what is acceptable.

NB: must also roughly match heuristics in system/core/bootstat/bootstat.cpp" ]
validate_reason() {
  var=`echo -n ${*} |
       tr '[A-Z]' '[a-z]' |
       tr ' \f\t\r\n' '_____'`
  case ${var} in
    watchdog | watchdog,?* ) ;;
    kernel_panic | kernel_panic,?* ) ;;
    recovery | recovery,?* ) ;;
    bootloader | bootloader,?* ) ;;
    cold | cold,?* ) ;;
    hard | hard,?* ) ;;
    warm | warm,?* ) ;;
    shutdown | shutdown,?* ) ;;
    reboot,reboot | reboot,reboot,* )     var=${var#reboot,} ; var=${var%,} ;;
    reboot,cold | reboot,cold,* )         var=${var#reboot,} ; var=${var%,} ;;
    reboot,hard | reboot,hard,* )         var=${var#reboot,} ; var=${var%,} ;;
    reboot,warm | reboot,warm,* )         var=${var#reboot,} ; var=${var%,} ;;
    reboot,recovery | reboot,recovery,* ) var=${var#reboot,} ; var=${var%,} ;;
    reboot,bootloader | reboot,bootloader,* ) var=${var#reboot,} ; var=${var%,} ;;
    reboot | reboot,?* ) ;;
    # Aliases and Heuristics
    *wdog* | *watchdog* )                                    var="watchdog" ;;
    *powerkey* | *power_on_key* | *power_key* | *PowerKey* ) var="cold,powerkey" ;;
    *panic* | *kernel_panic* )                               var="kernel_panic" ;;
    *thermal* )                                              var="shutdown,thermal" ;;
    *s3_wakeup* )                                            var="warm,s3_wakeup" ;;
    *hw_reset* )                                             var="hard,hw_reset" ;;
    *usb* | *power_on_cable* )                               var="cold,charger" ;;
    *rtc* )                                                  var="cold,rtc" ;;
    *2sec_reboot* )                                          var="cold,rtc,2sec" ;;
    *wdt_by_pass_pwk* )                                      var="warm" ;;
    wdt )                                                    var="reboot" ;;
    *tool_by_pass_pwk* )                                     var="reboot,tool" ;;
    *bootloader* )                                           var="bootloader" ;;
    * )                                                      var="reboot" ;;
  esac
  echo ${var}
}

[ "USAGE: validate_property <property>

Check property for CTS compliance with our expectations. Return a cleansed
string representing what is acceptable.

NB: must also roughly match heuristics in system/core/bootstat/bootstat.cpp" ]
validate_property() {
  val=`get_property ${1}`
  ret=`validate_reason "${val}"`
  if [ "reboot" = "${ret}" ]; then
    ret=`validate_reason "reboot,${val}"`
  fi
  echo ${ret}
}

[ "USAGE: check_boilerblate_properties

Check for common property values" ]
check_boilerplate_properties() {
  EXPECT_PROPERTY persist.sys.boot.reason ""
  save_ret=${?}
  reason=`validate_property sys.boot.reason`
  ( exit ${save_ret} )  # because one can not just do ?=${save_ret}
  EXPECT_PROPERTY persist.sys.boot.reason.history "${reason},[1-9][0-9]*\(\|[^0-9].*\)"
}

#
# Actual test frames
#

[ "USAGE: test_properties

properties test
- (wait until screen is up, boot has completed)
- adb shell getprop ro.boot.bootreason (bootloader reason)
- adb shell getprop persist.sys.boot.reason (last reason)
- adb shell getprop sys.boot.reason.last (last last reason)
- adb shell getprop sys.boot.reason (system reason)
- NB: all should have a value that is compliant with our known set." ]
test_properties() {
  duration_test 1
  wait_for_screen
  retval=0
  # sys.boot.reason is last for a reason
  check_set="ro.boot.bootreason sys.boot.reason.last sys.boot.reason"
  bootloader=""
  # NB: this test could fail if performed _after_ optional_factory_reset test
  # and will report
  #  ERROR: expected "reboot" got ""
  #        for Android property sys.boot.reason.last
  # following is mitigation for the persist.sys.boot.reason, skip it
  if [ "reboot,factory_reset" = "`validate_property ro.boot_bootreason`" ]; then
    check_set="ro.boot.bootreason sys.boot.reason"
    bootloader="bootloader"
  fi
  for prop in ${check_set}; do
    reason=`validate_property ${prop}`
    EXPECT_PROPERTY ${prop} ${reason} || retval=${?}
  done
  check_boilerplate_properties || retval=${?}
  report_bootstat_logs ${reason} ${bootloader}
  return ${retval}
}

[ "USAGE: test_ota

ota test
- rm out/.kati_stamp-* out/build_date.txt out/build_number.txt
- rm out/target/product/*/*/*.prop
- rm -r out/target/product/*/obj/ETC/system_build_prop_intermediates
- m
- NB: ro.build.date.utc should update
- fastboot flashall
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report ota

Decision to change the build itself rather than trick bootstat by
rummaging through its data files was made." ]
test_ota() {
  duration_test ">300"
  echo "      extended by build and flashing times" >&2
  if [ -z "${TARGET_PRODUCT}" -o \
       -z "${ANDROID_PRODUCT_OUT}" -o \
       -z "${ANDROID_BUILD_TOP}" -o \
       -z "${TARGET_BUILD_VARIANT}" ]; then
    echo "ERROR: Missing envsetup.sh and lunch" >&2
    return 1
  fi
  rm ${ANDROID_PRODUCT_OUT%/out/*}/out/.kati_stamp-* ||
    true
  rm ${ANDROID_PRODUCT_OUT%/out/*}/out/build_date.txt ||
    true
  rm ${ANDROID_PRODUCT_OUT%/out/*}/out/build_number.txt ||
    true
  rm ${ANDROID_PRODUCT_OUT}/*/*.prop ||
    true
  rm -r ${ANDROID_PRODUCT_OUT}/obj/ETC/system_build_prop_intermediates ||
    true
  pushd ${ANDROID_BUILD_TOP} >&2
  build/soong/soong_ui.bash --make-mode >&2
  if [ ${?} != 0 ]; then
    popd >&2
    return 1
  fi
  if ! inFastboot; then
    adb reboot-bootloader >&2
  fi
  fastboot flashall >&2
  popd >&2
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason "\(reboot,ota\|bootloader\)"
  EXPECT_PROPERTY sys.boot.reason.last bootloader
  check_boilerplate_properties
  report_bootstat_logs reboot,ota bootloader
}

[ "USAGE: test_optional_ota

fast and fake (touch build_date on device to make it different)" ]
test_optional_ota() {
  checkDebugBuild || return
  duration_test
  adb_su touch /data/misc/bootstat/build_date >&2 </dev/null
  adb reboot ota
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason reboot,ota
  EXPECT_PROPERTY sys.boot.reason.last reboot,ota
  check_boilerplate_properties
  report_bootstat_logs reboot,ota
}

[ "USAGE: [TEST=<test>] blind_reboot_test

Simple tests helper
- adb reboot <test>
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report <test>, or reboot,<test> depending on canonical rules

We interleave the simple reboot tests between the hard/complex ones
as a means of checking sanity and any persistent side effect of the
other tests." ]
blind_reboot_test() {
  duration_test
  case ${TEST} in
    bootloader | recovery | cold | hard | warm ) reason=${TEST} ;;
    *)                                           reason=reboot,${TEST#optional_} ;;
  esac
  adb reboot ${TEST#optional_}
  wait_for_screen
  bootloader_reason=`validate_property ro.boot.bootreason`
  EXPECT_PROPERTY ro.boot.bootreason ${bootloader_reason}
  # to make sys.boot.reason report user friendly
  reasons=${reason}
  if [ "${bootloader_reason}" != "${reason}" -a -n "${bootloader_reason}" ]; then
    reasons="\(${reason}\|${bootloader_reason}\)"
  fi
  EXPECT_PROPERTY sys.boot.reason ${reasons}
  EXPECT_PROPERTY sys.boot.reason.last ${reason}
  check_boilerplate_properties
  report_bootstat_logs ${reason} ${bootloader_reason}
}

[ "USAGE: test_cold

cold test
- adb reboot cold
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report cold" ]
test_cold() {
  blind_reboot_test
}

[ "USAGE: test_factory_reset

factory_reset test
- adb shell su root rm /data/misc/bootstat/build_date
- adb reboot
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report factory_reset

Decision to rummage through bootstat data files was made as
a _real_ factory_reset is too destructive to the device." ]
test_factory_reset() {
  checkDebugBuild || return
  duration_test
  adb_su rm /data/misc/bootstat/build_date >&2 </dev/null
  adb reboot >&2
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason reboot,factory_reset
  EXPECT_PROPERTY sys.boot.reason.last "reboot,.*"
  check_boilerplate_properties
  report_bootstat_logs reboot,factory_reset reboot, reboot,adb \
    "-bootstat: Failed to read /data/misc/bootstat/build_date: No such file or directory" \
    "-bootstat: Failed to parse boot time record: /data/misc/bootstat/build_date"
}

[ "USAGE: test_optional_factory_reset

factory_reset test
- adb reboot-bootloader
- fastboot format userdata
- fastboot reboot
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report factory_reset

For realz, and disruptive" ]
test_optional_factory_reset() {
  duration_test 60
  if ! inFastboot; then
    adb reboot-bootloader
  fi
  fastboot format userdata >&2
  save_ret=${?}
  if [ 0 != ${save_ret} ]; then
    echo "ERROR: fastboot can not format userdata" >&2
  fi
  fastboot reboot >&2
  wait_for_screen
  ( exit ${save_ret} )  # because one can not just do ?=${save_ret}
  EXPECT_PROPERTY sys.boot.reason reboot,factory_reset
  EXPECT_PROPERTY sys.boot.reason.last "\(\|bootloader\)"
  check_boilerplate_properties
  report_bootstat_logs reboot,factory_reset bootloader \
    "-bootstat: Failed to read /data/misc/bootstat/last_boot_time_utc: No such file or directory" \
    "-bootstat: Failed to parse boot time record: /data/misc/bootstat/last_boot_time_utc" \
    "-bootstat: Failed to read /data/misc/bootstat/build_date: No such file or directory" \
    "-bootstat: Failed to parse boot time record: /data/misc/bootstat/build_date" \
    "-bootstat: Failed to read /data/misc/bootstat/factory_reset: No such file or directory" \
    "-bootstat: Failed to parse boot time record: /data/misc/bootstat/factory_reset"
}

[ "USAGE: test_hard

hard test:
- adb reboot hard
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report hard" ]
test_hard() {
  blind_reboot_test
}

[ "USAGE: test_battery

battery test (trick):
- echo healthd: battery l=2<space> | adb shell su root tee /dev/kmsg
- adb reboot cold
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,battery, unless healthd managed to log
  before reboot in above trick.

- Bonus points (manual extras)
- Make sure the following is added to the /init.rc file in post-fs
  section before logd is started:
    +    setprop logd.kernel false
    +    rm /sys/fs/pstore/console-ramoops
    +    rm /sys/fs/pstore/console-ramoops-0
    +    write /dev/kmsg \"healthd: battery l=2${SPACE}
    +\"
- adb reboot fs
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,battery
- (replace set logd.kernel true to the above, and retry test)" ]
test_battery() {
  checkDebugBuild || return
  duration_test 120
  enterPstore
  # Send it _many_ times to combat devices with flakey pstore
  for i in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
    echo 'healthd: battery l=2 ' | adb_su tee /dev/kmsg >/dev/null
  done
  adb reboot cold >&2
  adb wait-for-device
  wait_for_screen
  adb_su </dev/null \
    cat /proc/fs/pstore/console-ramoops \
        /proc/fs/pstore/console-ramoops-0 2>/dev/null |
    grep 'healthd: battery l=' |
    tail -1 |
    grep 'healthd: battery l=2 ' >/dev/null || (
      if ! EXPECT_PROPERTY sys.boot.reason reboot,battery >/dev/null 2>/dev/null; then
        # retry
        for i in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
          echo 'healthd: battery l=2 ' | adb_su tee /dev/kmsg >/dev/null
        done
        adb reboot cold >&2
        adb wait-for-device
        wait_for_screen
      fi
    )

  EXPECT_PROPERTY sys.boot.reason shutdown,battery
  EXPECT_PROPERTY sys.boot.reason.last cold
  check_boilerplate_properties
  report_bootstat_logs shutdown,battery "-bootstat: Battery level at shutdown 2%"
  exitPstore
}

[ "USAGE: test_optional_battery

battery shutdown test:
- adb shell setprop sys.powerctl shutdown,battery
- (power up the device)
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report shutdown,battery" ]
test_optional_battery() {
  duration_test ">60"
  echo "      power on request" >&2
  adb_sh setprop sys.powerctl shutdown,battery </dev/null
  sleep 5
  echo -n "WARNING: Please power device back up, waiting ... " >&2
  wait_for_screen -n >&2
  EXPECT_PROPERTY sys.boot.reason shutdown,battery
  EXPECT_PROPERTY sys.boot.reason.last shutdown,battery
  check_boilerplate_properties
  report_bootstat_logs shutdown,battery
}

[ "USAGE: test_optional_battery_thermal

battery thermal shutdown test:
- adb shell setprop sys.powerctl shutdown,thermal,battery
- (power up the device)
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report shutdown,thermal,battery" ]
test_optional_battery_thermal() {
  duration_test ">60"
  echo "      power on request" >&2
  adb_sh setprop sys.powerctl shutdown,thermal,battery </dev/null
  sleep 5
  echo -n "WARNING: Please power device back up, waiting ... " >&2
  wait_for_screen -n >&2
  EXPECT_PROPERTY sys.boot.reason shutdown,thermal,battery
  EXPECT_PROPERTY sys.boot.reason.last shutdown,thermal,battery
  check_boilerplate_properties
  report_bootstat_logs shutdown,thermal,battery
}

[ "USAGE: test_unknown

unknown test
- adb reboot unknown
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,unknown
- NB: expect log \"... I bootstat: Unknown boot reason: reboot,unknown\"" ]
test_unknown() {
  blind_reboot_test
}

[ "USAGE: test_kernel_panic

kernel_panic test:
- echo c | adb shell su root tee /proc/sysrq-trigger
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report kernel_panic,sysrq" ]
test_kernel_panic() {
  checkDebugBuild || return
  duration_test ">90"
  panic_msg="kernel_panic,sysrq"
  enterPstore
  if [ ${?} != 0 ]; then
    echo "         or functional bootloader" >&2
    panic_msg="\(kernel_panic,sysrq\|kernel_panic\)"
    pstore_ok=true
  fi
  echo c | adb_su tee /proc/sysrq-trigger >/dev/null
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason ${panic_msg}
  EXPECT_PROPERTY sys.boot.reason.last ${panic_msg}
  check_boilerplate_properties
  report_bootstat_logs kernel_panic,sysrq
  exitPstore
}

[ "USAGE: test_kernel_panic_subreason

kernel_panic_subreason test:
- echo SysRq : Trigger a crash : 'test' | adb shell su root tee /dev/kmsg
- echo c | adb shell su root tee /proc/sysrq-trigger
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report kernel_panic,sysrq,test" ]
test_kernel_panic_subreason() {
  checkDebugBuild || return
  duration_test ">90"
  panic_msg="kernel_panic,sysrq,test"
  enterPstore
  if [ ${?} != 0 ]; then
    echo "         or functional bootloader" >&2
    panic_msg="\(kernel_panic,sysrq,test\|kernel_panic\)"
    pstore_ok=true
  fi
  echo "SysRq : Trigger a crash : 'test'" | adb_su tee /dev/kmsg
  echo c | adb_su tee /proc/sysrq-trigger >/dev/null
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason ${panic_msg}
  EXPECT_PROPERTY sys.boot.reason.last ${panic_msg}
  check_boilerplate_properties
  report_bootstat_logs kernel_panic,sysrq,test \
    "-bootstat: Unknown boot reason: kernel_panic,sysrq,test"
  exitPstore
}

[ "USAGE: test_kernel_panic_hung

kernel_panic_hung test:
- echo Kernel panic - not synching: hung_task: blocked tasks |
  adb shell su root tee /dev/kmsg
- adb reboot warm
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report kernel_panic,hung" ]
test_kernel_panic_hung() {
  checkDebugBuild || return
  duration_test
  panic_msg="kernel_panic,hung"
  enterPstore
  if [ ${?} != 0 ]; then
    echo "         or functional bootloader" >&2
    panic_msg="\(kernel_panic,hung\|reboot,hung\)"
    pstore_ok=true
  fi
  echo "Kernel panic - not syncing: hung_task: blocked tasks" |
    adb_su tee /dev/kmsg
  adb reboot warm
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason ${panic_msg}
  EXPECT_PROPERTY sys.boot.reason.last ${panic_msg}
  check_boilerplate_properties
  report_bootstat_logs kernel_panic,hung
  exitPstore
}

[ "USAGE: test_warm

warm test
- adb reboot warm
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report warm" ]
test_warm() {
  blind_reboot_test
}

[ "USAGE: test_thermal_shutdown

thermal shutdown test:
- adb shell setprop sys.powerctl shutdown,thermal
- (power up the device)
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report shutdown,thermal" ]
test_thermal_shutdown() {
  duration_test ">60"
  echo "      power on request" >&2
  adb_sh setprop sys.powerctl shutdown,thermal </dev/null
  sleep 5
  echo -n "WARNING: Please power device back up, waiting ... " >&2
  wait_for_screen -n >&2
  EXPECT_PROPERTY sys.boot.reason shutdown,thermal
  EXPECT_PROPERTY sys.boot.reason.last shutdown,thermal
  check_boilerplate_properties
  report_bootstat_logs shutdown,thermal
}

[ "USAGE: test_userrequested_shutdown

userrequested shutdown test:
- adb shell setprop sys.powerctl shutdown,userrequested
- (power up the device)
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report shutdown,userrequested" ]
test_userrequested_shutdown() {
  duration_test ">60"
  echo "      power on request" >&2
  adb_sh setprop sys.powerctl shutdown,userrequested </dev/null
  sleep 5
  echo -n "WARNING: Please power device back up, waiting ... " >&2
  wait_for_screen -n >&2
  EXPECT_PROPERTY sys.boot.reason shutdown,userrequested
  EXPECT_PROPERTY sys.boot.reason.last shutdown,userrequested
  check_boilerplate_properties
  report_bootstat_logs shutdown,userrequested
}

[ "USAGE: test_shell_reboot

shell reboot test:
- adb shell reboot
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,shell" ]
test_shell_reboot() {
  duration_test
  adb_sh reboot </dev/null
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason reboot,shell
  EXPECT_PROPERTY sys.boot.reason.last reboot,shell
  check_boilerplate_properties
  report_bootstat_logs reboot,shell
}

[ "USAGE: test_adb_reboot

adb reboot test:
- adb reboot
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,adb" ]
test_adb_reboot() {
  duration_test
  adb reboot
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason reboot,adb
  EXPECT_PROPERTY sys.boot.reason.last reboot,adb
  check_boilerplate_properties
  report_bootstat_logs reboot,adb
}

[ "USAGE: test_rescueparty

rescueparty test
- adb reboot rescueparty
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- adb shell getprop ro.boot.bootreason
- NB: should report reboot,rescueparty" ]
test_optional_rescueparty() {
  blind_reboot_test
  echo "WARNING: legacy devices are allowed to fail following ro.boot.bootreason result" >&2
  EXPECT_PROPERTY ro.boot.bootreason '\(reboot\|reboot,rescueparty\)'
}

[ "USAGE: test_Its_Just_So_Hard_reboot

Its Just So Hard reboot test:
- adb shell reboot 'Its Just So Hard'
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,its_just_so_hard
- NB: expect log \"... I bootstat: Unknown boot reason: reboot,its_just_so_hard\"" ]
test_Its_Just_So_Hard_reboot() {
  if isDebuggable; then       # see below
    duration_test
  else
    duration_test `expr ${DURATION_DEFAULT} + ${DURATION_DEFAULT}`
  fi
  adb_sh 'reboot "Its Just So Hard"' </dev/null
  wait_for_screen
  EXPECT_PROPERTY sys.boot.reason reboot,its_just_so_hard
  EXPECT_PROPERTY sys.boot.reason.last reboot,its_just_so_hard
  check_boilerplate_properties
  report_bootstat_logs reboot,its_just_so_hard
}

[ "USAGE: run_bootloader [value [expected]]

bootloader boot reason injection tests:
- setBootloaderBootReason value
- adb shell reboot
- (wait until screen is up, boot has completed)
- adb shell getprop sys.boot.reason
- NB: should report reboot,value" ]
run_bootloader() {
  bootloader_expected="${1}"
  if [ -z "${bootloader_expected}" ]; then
    bootloader_expected="${TEST#bootloader_}"
  fi
  if ! setBootloaderBootReason ${bootloader_expected}; then
    echo "       Skipping FAILURE." 2>&1
    return
  fi
  duration_test
  if [ X"warm" = X"${bootloader_expected}" ]; then
    last_expected=cold
  else
    last_expected=warm
  fi
  adb reboot ${last_expected}
  wait_for_screen
  # Reset so that other tests do not get unexpected injection
  setBootloaderBootReason
  # Determine the expected values
  sys_expected="${2}"
  if [ -z "${sys_expected}" ]; then
    sys_expected="`validate_reason ${bootloader_expected}`"
    if [ "reboot" = "${sys_expected}" ]; then
      sys_expected="${last_expected}"
    fi
  else
    sys_expected=`validate_reason ${sys_expected}`
  fi
  case ${sys_expected} in
    kernel_panic | kernel_panic,* | watchdog | watchdog,* )
      last_expected=${sys_expected}
      ;;
  esac
  # Check values
  EXPECT_PROPERTY ro.boot.bootreason "${bootloader_expected}"
  EXPECT_PROPERTY sys.boot.reason "${sys_expected}"
  EXPECT_PROPERTY sys.boot.reason.last "${last_expected}"
  check_boilerplate_properties
  report_bootstat_logs "${sys_expected}"
}

[ "USAGE: test_bootloader_<type>

bootloader boot reasons test injection" ]
test_bootloader_normal() {
  run_bootloader
}

test_bootloader_watchdog() {
  run_bootloader
}

test_bootloader_kernel_panic() {
  run_bootloader
}

test_bootloader_oem_powerkey() {
  run_bootloader
}

test_bootloader_wdog_reset() {
  run_bootloader
}

test_bootloader_cold() {
  run_bootloader
}

test_bootloader_warm() {
  run_bootloader
}

test_bootloader_hard() {
  run_bootloader
}

test_bootloader_recovery() {
  run_bootloader
}

[ "USAGE: run_kBootReasonMap [--boot_reason_enum] value expected

bootloader boot reason injection tests:
- if --boot_reason_enum run bootstat executable for result instead.
- inject boot reason into sys.boot.reason
- run bootstat --set_system_boot_reason
- check for expected enum
- " ]
run_kBootReasonMap() {
  if [ X"--boot_reason_enum" = X"${1}" ]; then
    shift
    local sys_expected="${1}"
    shift
    local enum_expected="${1}"
    adb_su bootstat --boot_reason_enum="${sys_expected}" |
      (
        local retval=-1
        while read -r id match; do
          if [ ${retval} = -1 -a ${enum_expected} = ${id} ]; then
            retval=0
          fi
          if [ ${enum_expected} != ${id} ]; then
            echo "ERROR: ${enum_expected} ${sys_expected} got ${id} ${match}" >&2
            retval=1
          fi
        done
        exit ${retval}
      )
    return
  fi
  local sys_expected="${1}"
  shift
  local enum_expected="${1}"
  adb_su setprop sys.boot.reason "${sys_expected}" </dev/null
  adb_su bootstat --record_boot_reason </dev/null
  # Check values
  EXPECT_PROPERTY sys.boot.reason "${sys_expected}"
  local retval=${?}
  local result=`adb_su stat -c %Y /data/misc/bootstat/system_boot_reason </dev/null 2>/dev/null`
  [ "${enum_expected}" = "${result}" ] ||
    (
      [ -n "${result}" ] || result="<nothing>"
      echo "ERROR: ${enum_expected} ${sys_expected} got ${result}" >&2
      false
    ) ||
    retval=${?}
  return ${retval}
}

[ "USAGE: filter_kBootReasonMap </dev/stdin >/dev/stdout

convert any regex expressions into a series of non-regex test strings" ]
filter_kBootReasonMap() {
  while read -r id match; do
    case ${match} in
      'reboot,[empty]')
        echo ${id}          # matches b/c of special case
        echo ${id} reboot,y # matches b/c of regex
        echo 1 reboot,empty # negative test (ID for unknown is 1)
        ;;
      reboot)
        echo 1 reboog       # negative test (ID for unknown is 1)
        ;;
      'reboot,pmic_off_fault,.*')
        echo ${id} reboot,pmic_off_fault,hello,world
        echo ${id} reboot,pmic_off_fault,
        echo 1 reboot,pmic_off_fault
        ;;
    esac
    echo ${id} "${match}"   # matches b/c of exact
  done
}

[ "USAGE: test_kBootReasonMap

kBootReasonMap test
- (wait until screen is up, boot has completed)
- read bootstat for kBootReasonMap entries and test them all" ]
test_kBootReasonMap() {
  checkDebugBuild || return
  duration_test 15
  local tempfile="`mktemp`"
  local arg=--boot_reason_enum
  adb_su bootstat ${arg} </dev/null 2>/dev/null |
    filter_kBootReasonMap >${tempfile}
  if [ ! -s "${tempfile}" ]; then
    wait_for_screen
    arg=
    sed -n <${progpath}bootstat.cpp \
      '/kBootReasonMap = {/,/^};/s/.*{"\([^"]*\)", *\([0-9][0-9]*\)},.*/\2 \1/p' |
      sed 's/\\\\/\\/g' |
      filter_kBootReasonMap >${tempfile}
  fi
  T=`adb_date`
  retval=0
  while read -r enum string; do
    if [ X"${string}" != X"${string#*[[].[]]}" -o X"${string}" != X"${string#*\\.}" ]; then
      if [ 'reboot\.empty' != "${string}" ]; then
        echo "WARNING: regex snuck through filter_kBootReasonMap ${enum} ${string}" >&2
        enum=1
      fi
    fi
    run_kBootReasonMap ${arg} "${string}" "${enum}" </dev/null || retval=${?}
  done <${tempfile}
  rm ${tempfile}
  ( exit ${retval} )
  # See filter_kBootReasonMap() for negative tests and add them here too
  report_bootstat_logs -t${T} \
    '-bootstat: Service started: bootstat --boot_reason_enum=' \
    '-bootstat: Unknown boot reason: reboot,empty' \
    '-bootstat: Unknown boot reason: reboog' \
    '-bootstat: Unknown boot reason: reboot,pmic_off_fault'
}

[ "USAGE: ${progname} [-s SERIAL] [tests]...

Mainline executive to run the above tests" ]

# Rudimentary argument parsing

if [ ${#} -ge 2 -a X"-s" = X"${1}" ]; then
  export ANDROID_SERIAL="${2}"
  shift 2
fi

# Helpful for debugging, allows us to import the functions.
if [ X"--macros" != X"${1}" ]; then

  if [ X"--help" = X"${1}" -o X"-h" = X"${1}" -o X"-?" = X"${1}" ]; then
    echo "USAGE: ${progname} [-s SERIAL] [tests]..."
    echo tests - `sed -n 's/^test_\([^ ()]*\)() {/\1/p' $0 </dev/null`
    exit 0
  fi

  if [ X"--stop" = X"${1}" ]; then
    STOP_ON_FAILURE=true
    shift
  fi

  # Check if all conditions for the script are valid

  if [ -z "${ANDROID_SERIAL}" ]; then
    ndev=`(
        adb devices | grep -v 'List of devices attached'
        fastboot devices
      ) |
      grep -v "^[${SPACE}${TAB}]*\$" |
      wc -l`
    if [ ${ndev} -gt 1 ]; then
      echo "ERROR: no target device specified, ${ndev} connected" >&2
      echo "${RED}[  FAILED  ]${NORMAL}"
      exit 1
    fi
    echo "WARNING: no target device specified" >&2
  fi

  ret=0

  # Test Series
  if [ X"all" = X"${*}" ]; then
    # automagically pick up all test_<function>s.
    eval set nothing `sed -n 's/^test_\([^ ()]*\)() {/\1/p' $0 </dev/null`
    if [ X"nothing" = X"${1}" ]; then
      shift 1
    fi
  fi
  if [ -z "$*" ]; then
    # automagically pick up all test_<function>, except test_optional_<function>.
    eval set nothing `sed -n 's/^test_\([^ ()]*\)() {/\1/p' $0 </dev/null |
                              grep -v '^optional_'`
    if [ -z "${2}" ]; then
      # Hard coded should shell fail to find them (search/permission issues)
      eval set properties ota cold factory_reset hard battery unknown \
               kernel_panic kernel_panic_subreason kernel_panic_hung warm \
               thermal_shutdown userrequested_shutdown shell_reboot adb_reboot \
               Its_Just_So_Hard_reboot bootloader_normal bootloader_watchdog \
               bootloader_kernel_panic bootloader_oem_powerkey \
               bootloader_wdog_reset bootloader_cold bootloader_warm \
               bootloader_hard bootloader_recovery kBootReasonMap
    fi
    if [ X"nothing" = X"${1}" ]; then
      shift 1
    fi
  fi
  echo "INFO: selected test(s): ${@}" >&2
  echo
  # Prepare device
  setBootloaderBootReason 2>/dev/null
  # Start pouring through the tests.
  failures=
  successes=
  for t in "${@}"; do
    wrap_test ${t}
    retval=${?}
    if [ 0 = ${retval} ]; then
      if [ -z "${successes}" ]; then
        successes=${t}
      else
        successes="${successes} ${t}"
      fi
    else
      ret=${retval}
      if [ -z "${failures}" ]; then
        failures=${t}
      else
        failures="${failures} ${t}"
      fi
    fi
    echo
  done

  if [ -n "${successes}" ]; then
    echo "${GREEN}[  PASSED  ]${NORMAL} ${successes}"
  fi
  if [ -n "${failures}" ]; then
    echo "${RED}[  FAILED  ]${NORMAL} ${failures}"
  fi
  exit ${ret}

fi
