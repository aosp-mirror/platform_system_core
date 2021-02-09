#! /bin/bash
#
# Divided into four section:
#
##  USAGE
##  Helper Variables
##  Helper Functions
##  MAINLINE

##
##  USAGE
##

USAGE="USAGE: `basename ${0}` [--help] [--serial <SerialNumber>] [options]

adb remount tests

-c --color                     Dress output with highlighting colors
-h --help                      This help
-D --no-wait-screen            Do not wait for display screen to settle
-t --print-time                Report the test duration
-s --serial                    Specify device (must if multiple are present)"
if [ -n "`which timeout`" ]; then
  USAGE="${USAGE}
-a --wait-adb <duration>       adb wait timeout
-f --wait-fastboot <duration>  fastboot wait timeout"
fi
USAGE="${USAGE}

Conditions:
 - Must be a userdebug build.
 - Must be in adb mode.
 - Also tests overlayfs
  - Kernel must have overlayfs enabled and patched to support override_creds.
  - Must have either erofs, squashfs, ext4-dedupe or full partitions.
  - Minimum expectation system and vender are overlayfs covered partitions.
"

##
##  Helper Variables
##

EMPTY=""
SPACE=" "
# Line up wrap to [  XXXXXXX ] messages.
INDENT="             "
# A _real_ embedded tab character
TAB="`echo | tr '\n' '\t'`"
# A _real_ embedded escape character
ESCAPE="`echo | tr '\n' '\033'`"
# A _real_ embedded carriage return character
CR="`echo | tr '\n' '\r'`"
GREEN="${ESCAPE}[32m"
RED="${ESCAPE}[31m"
YELLOW="${ESCAPE}[33m"
BLUE="${ESCAPE}[34m"
NORMAL="${ESCAPE}[0m"
TMPDIR=${TMPDIR:-/tmp}
print_time=false
start_time=`date +%s`
ACTIVE_SLOT=

ADB_WAIT=4m
FASTBOOT_WAIT=2m
screen_wait=true

##
##  Helper Functions
##

[ "USAGE: inFastboot

Returns: true if device is in fastboot mode" ]
inFastboot() {
  fastboot devices |
    if [ -n "${ANDROID_SERIAL}" ]; then
      grep "^${ANDROID_SERIAL}[${SPACE}${TAB}]" > /dev/null
    else
      wc -l | grep "^[${SPACE}${TAB}]*1\$" >/dev/null
    fi
}

[ "USAGE: inAdb

Returns: true if device is in adb mode" ]
inAdb() {
  adb devices |
    grep -v -e 'List of devices attached' -e '^$' -e "[${SPACE}${TAB}]recovery\$" |
    if [ -n "${ANDROID_SERIAL}" ]; then
      grep "^${ANDROID_SERIAL}[${SPACE}${TAB}]" > /dev/null
    else
      wc -l | grep "^[${SPACE}${TAB}]*1\$" >/dev/null
    fi
}

[ "USAGE: inRecovery

Returns: true if device is in recovery mode" ]
inRecovery() {
  local list="`adb devices |
              grep -v -e 'List of devices attached' -e '^$'`"
  if [ -n "${ANDROID_SERIAL}" ]; then
    echo "${list}" |
      grep "^${ANDROID_SERIAL}[${SPACE}${TAB}][${SPACE}${TAB}]*recovery\$" >/dev/null
    return ${?}
  fi
  if echo "${list}" | wc -l | grep "^[${SPACE}${TAB}]*1\$" >/dev/null; then
    echo "${list}" |
      grep "[${SPACE}${TAB}]recovery\$" >/dev/null
    return ${?}
  fi
  false
}

[ "USAGE: adb_sh <commands> </dev/stdin >/dev/stdout 2>/dev/stderr

Returns: true if the command succeeded" ]
adb_sh() {
  local args=
  for i in "${@}"; do
    [ -z "${args}" ] || args="${args} "
    if [ X"${i}" != X"${i#\'}" ]; then
      args="${args}${i}"
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

[ "USAGE: adb_date >/dev/stdout

Returns: report device epoch time (suitable for logcat -t)" ]
adb_date() {
  adb_sh date +%s.%N </dev/null
}

[ "USAGE: adb_logcat [arguments] >/dev/stdout

Returns: the logcat output" ]
adb_logcat() {
  echo "${RED}[     INFO ]${NORMAL} logcat ${@}" >&2 &&
  adb logcat "${@}" </dev/null |
    tr -d '\r' |
    grep -v 'logd    : logdr: UID=' |
    sed -e '${ /------- beginning of kernel/d }' -e 's/^[0-1][0-9]-[0-3][0-9] //'
}

[ "USAGE: avc_check >/dev/stderr

Returns: worrisome avc violations" ]
avc_check() {
  if ! ${overlayfs_supported:-false}; then
    return
  fi
  local L=`adb_logcat -b all -v brief -d \
                      -e 'context=u:object_r:unlabeled:s0' 2>/dev/null |
             sed -n 's/.*avc: //p' |
             sort -u`
  if [ -z "${L}" ]; then
    return
  fi
  echo "${YELLOW}[  WARNING ]${NORMAL} unlabeled sepolicy violations:" >&2
  echo "${L}" | sed "s/^/${INDENT}/" >&2
}

[ "USAGE: get_property <prop>

Returns the property value" ]
get_property() {
  adb_sh getprop ${1} </dev/null
}

[ "USAGE: isDebuggable

Returns: true if device is (likely) a debug build" ]
isDebuggable() {
  if inAdb && [ 1 != "`get_property ro.debuggable`" ]; then
    false
  fi
}

[ "USAGE: adb_su <commands> </dev/stdin >/dev/stdout 2>/dev/stderr

Returns: true if the command running as root succeeded" ]
adb_su() {
  adb_sh su root "${@}"
}

[ "USAGE: adb_cat <file> >stdout

Returns: content of file to stdout with carriage returns skipped,
         true if the file exists" ]
adb_cat() {
    local OUTPUT="`adb_sh cat ${1} </dev/null 2>&1`"
    local ret=${?}
    echo "${OUTPUT}" | tr -d '\r'
    return ${ret}
}

[ "USAGE: adb_ls <dirfile> >stdout

Returns: filename or directoru content to stdout with carriage returns skipped,
         true if the ls had no errors" ]
adb_ls() {
    local OUTPUT="`adb_sh ls ${1} </dev/null 2>/dev/null`"
    local ret=${?}
    echo "${OUTPUT}" | tr -d '\r'
    return ${ret}
}

[ "USAGE: adb_test <expression>

Returns: exit status of the test expression" ]
adb_test() {
  adb_sh test "${@}" </dev/null
}

[ "USAGE: adb_reboot

Returns: true if the reboot command succeeded" ]
adb_reboot() {
  avc_check
  adb reboot remount-test </dev/null || true
  sleep 2
}

[ "USAGE: format_duration [<seconds>|<seconds>s|<minutes>m|<hours>h|<days>d]

human readable output whole seconds, whole minutes or mm:ss" ]
format_duration() {
  if [ -z "${1}" ]; then
    echo unknown
    return
  fi
  local duration="${1}"
  if [ X"${duration}" != X"${duration%s}" ]; then
    duration=${duration%s}
  elif [ X"${duration}" != X"${duration%m}" ]; then
    duration=`expr ${duration%m} \* 60`
  elif [ X"${duration}" != X"${duration%h}" ]; then
    duration=`expr ${duration%h} \* 3600`
  elif [ X"${duration}" != X"${duration%d}" ]; then
    duration=`expr ${duration%d} \* 86400`
  fi
  local seconds=`expr ${duration} % 60`
  local minutes=`expr \( ${duration} / 60 \) % 60`
  local hours=`expr ${duration} / 3600`
  if [ 0 -eq ${minutes} -a 0 -eq ${hours} ]; then
    if [ 1 -eq ${duration} ]; then
      echo 1 second
      return
    fi
    echo ${duration} seconds
    return
  elif [ 60 -eq ${duration} ]; then
    echo 1 minute
    return
  elif [ 0 -eq ${seconds} -a 0 -eq ${hours} ]; then
    echo ${minutes} minutes
    return
  fi
  if [ 0 -eq ${hours} ]; then
    echo ${minutes}:`expr ${seconds} / 10``expr ${seconds} % 10`
    return
  fi
  echo ${hours}:`expr ${minutes} / 10``expr ${minutes} % 10`:`expr ${seconds} / 10``expr ${seconds} % 10`
}

[ "USAGE: USB_DEVICE=\`usb_devnum [--next]\`

USB_DEVICE contains cache. Update if system changes.

Returns: the devnum for the USB_SERIAL device" ]
usb_devnum() {
  if [ -n "${USB_SERIAL}" ]; then
    local usb_device=`cat ${USB_SERIAL%/serial}/devnum 2>/dev/null | tr -d ' \t\r\n'`
    if [ -n "${usb_device}" ]; then
      USB_DEVICE=dev${usb_device}
    elif [ -n "${USB_DEVICE}" -a "${1}" ]; then
      USB_DEVICE=dev`expr ${USB_DEVICE#dev} + 1`
    fi
    echo "${USB_DEVICE}"
  fi
}

[ "USAGE: adb_wait [timeout]

Returns: waits until the device has returned for adb or optional timeout" ]
adb_wait() {
  local start=`date +%s`
  local duration=
  local ret
  if [ -n "${1}" -a -n "`which timeout`" ]; then
    USB_DEVICE=`usb_devnum --next`
    duration=`format_duration ${1}`
    echo -n ". . . waiting ${duration}" ${ANDROID_SERIAL} ${USB_ADDRESS} ${USB_DEVICE} "${CR}"
    timeout --preserve-status --signal=KILL ${1} adb wait-for-device 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}"
  else
    adb wait-for-device
    ret=${?}
  fi
  USB_DEVICE=`usb_devnum`
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${YELLOW}[  WARNING ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}" >&2
    fi
  fi
  local end=`date +%s`
  local diff_time=`expr ${end} - ${start}`
  local _print_time=${print_time}
  if [ ${diff_time} -lt 15 ]; then
    _print_time=false
  fi
  diff_time=`format_duration ${diff_time}`
  if [ "${diff_time}" = "${duration}" ]; then
    _print_time=false
  fi

  local reason=
  if inAdb; then
    reason=`get_property ro.boot.bootreason`
  fi
  case ${reason} in
    reboot*)
      reason=
      ;;
    ${EMPTY})
      ;;
    *)
      reason=" for boot reason ${reason}"
      ;;
  esac
  if ${_print_time} || [ -n "${reason}" ]; then
    echo "${BLUE}[     INFO ]${NORMAL} adb wait duration ${diff_time}${reason}"
  fi >&2

  return ${ret}
}

[ "USAGE: adb_user > /dev/stdout

Returns: the adb daemon user" ]
adb_user() {
  adb_sh echo '${USER}' </dev/null
}

[ "USAGE: usb_status > stdout 2> stderr

Assumes referenced right after adb_wait or fastboot_wait failued.
If wait failed, check if device is in adb, recovery or fastboot mode
and report status strings like  \"(USB stack borken?)\",
\"(In fastboot mode)\", \"(In recovery mode)\" or \"(in adb mode)\".
Additional diagnostics may be provided to the stderr output.

Returns: USB status string" ]
usb_status() {
  if inFastboot; then
    echo "(In fastboot mode)"
  elif inRecovery; then
    echo "(In recovery mode)"
  elif inAdb; then
    echo "(In adb mode `adb_user`)"
  else
    echo "(USB stack borken for ${USB_ADDRESS})"
    if [ -n "`which usb_devnum`" ]; then
      USB_DEVICE=`usb_devnum`
      if [ -n "`which lsusb`" ]; then
        if [ -n "${USB_DEVICE}" ]; then
          echo "# lsusb -v -s ${USB_DEVICE#dev}"
          local D=`lsusb -v -s ${USB_DEVICE#dev} 2>&1`
          if [ -n "${D}" ]; then
            echo "${D}"
          else
            lsusb -v
          fi
        else
          echo "# lsusb -v (expected device missing)"
          lsusb -v
        fi
      fi
    fi >&2
  fi
}

[ "USAGE: fastboot_wait [timeout]

Returns: waits until the device has returned for fastboot or optional timeout" ]
fastboot_wait() {
  local ret
  # fastboot has no wait-for-device, but it does an automatic
  # wait and requires (even a nonsensical) command to do so.
  if [ -n "${1}" -a -n "`which timeout`" ]; then
    USB_DEVICE=`usb_devnum --next`
    echo -n ". . . waiting `format_duration ${1}`" ${ANDROID_SERIAL} ${USB_ADDRESS} ${USB_DEVICE} "${CR}"
    timeout --preserve-status --signal=KILL ${1} fastboot wait-for-device >/dev/null 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}"
    ( exit ${ret} )
  else
    fastboot wait-for-device >/dev/null 2>/dev/null
  fi ||
    inFastboot
  ret=${?}
  USB_DEVICE=`usb_devnum`
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${YELLOW}[  WARNING ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    fi >&2
  fi
  return ${ret}
}

[ "USAGE: recovery_wait [timeout]

Returns: waits until the device has returned for recovery or optional timeout" ]
recovery_wait() {
  local ret
  if [ -n "${1}" -a -n "`which timeout`" ]; then
    USB_DEVICE=`usb_devnum --next`
    echo -n ". . . waiting `format_duration ${1}`" ${ANDROID_SERIAL} ${USB_ADDRESS} ${USB_DEVICE} "${CR}"
    timeout --preserve-status --signal=KILL ${1} adb wait-for-recovery 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}"
  else
    adb wait-for-recovery
    ret=${?}
  fi
  USB_DEVICE=`usb_devnum`
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${YELLOW}[  WARNING ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    fi >&2
  fi
  return ${ret}
}

[ "any_wait [timeout]

Returns: waits until a device has returned or optional timeout" ]
any_wait() {
  (
    adb_wait ${1} &
    adb_pid=${!}
    fastboot_wait ${1} &
    fastboot_pid=${!}
    recovery_wait ${1} &
    recovery_pid=${!}
    wait -n
    kill "${adb_pid}" "${fastboot_pid}" "${recovery_pid}"
  ) >/dev/null 2>/dev/null
  inFastboot || inAdb || inRecovery
}

wait_for_screen_timeout=900
[ "USAGE: wait_for_screen [-n] [TIMEOUT]

-n - echo newline at exit
TIMEOUT - default `format_duration ${wait_for_screen_timeout}`" ]
wait_for_screen() {
  if ! ${screen_wait}; then
    adb_wait
    return
  fi
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
        adb_wait
      fi
      if [ "1" = "`get_property sys.boot_completed`" ]; then
        sleep 1
        break
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

[ "USAGE: adb_root

NB: This can be flakey on devices due to USB state

Returns: true if device in root state" ]
adb_root() {
  [ root != "`adb_user`" ] || return 0
  adb root >/dev/null </dev/null 2>/dev/null
  sleep 2
  adb_wait ${ADB_WAIT} &&
    [ root = "`adb_user`" ]
}

[ "USAGE: adb_unroot

NB: This can be flakey on devices due to USB state

Returns: true if device in un root state" ]
adb_unroot() {
  [ root = "`adb_user`" ] || return 0
  adb unroot >/dev/null </dev/null 2>/dev/null
  sleep 2
  adb_wait ${ADB_WAIT} &&
    [ root != "`adb_user`" ]
}

[ "USAGE: fastboot_getvar var expected >/dev/stderr

Returns: true if var output matches expected" ]
fastboot_getvar() {
  local O=`fastboot getvar ${1} 2>&1`
  local ret=${?}
  O="${O#< waiting for * >?}"
  O="${O%%?Finished. Total time: *}"
  if [ 0 -ne ${ret} ]; then
    echo ${O} >&2
    false
    return
  fi
  if [ "${O}" != "${O#*FAILED}" ]; then
    O="${1}: <empty>"
  fi
  if [ -n "${2}" -a "${1}: ${2}" != "${O}" ]; then
    echo "${2} != ${O}"
    false
    return
  fi >&2
  echo ${O} >&2
}

[ "USAGE: get_active_slot >/dev/stdout

Returns: with a or b string reporting active slot" ]
get_active_slot() {
  if inAdb || inRecovery; then
    get_property ro.boot.slot_suffix | tr -d _
  elif inFastboot; then
    fastboot_getvar current-slot 2>&1 | sed -n 's/current-slot: //p'
  else
    false
  fi
}

[ "USAGE: restore

Do nothing: should be redefined when necessary.  Called after cleanup.

Returns: reverses configurations" ]
restore() {
  true
}

[ "USAGE: cleanup

Do nothing: should be redefined when necessary

Returns: cleans up any latent resources" ]
cleanup() {
  true
}

[ "USAGE: test_duration >/dev/stderr

Prints the duration of the test

Returns: reports duration" ]
test_duration() {
  if ${print_time}; then
    echo "${BLUE}[     INFO ]${NORMAL} end `date`"
    [ -n "${start_time}" ] || return
    end_time=`date +%s`
    local diff_time=`expr ${end_time} - ${start_time}`
    echo "${BLUE}[     INFO ]${NORMAL} duration `format_duration ${diff_time}`"
  fi >&2
}

[ "USAGE: die [-d|-t <epoch>] [message] >/dev/stderr

If -d, or -t <epoch> argument is supplied, dump logcat.

Returns: exit failure, report status" ]
die() {
  if [ X"-d" = X"${1}" ]; then
    adb_logcat -b all -v nsec -d
    shift
  elif [ X"-t" = X"${1}" ]; then
    if [ -n "${2}" ]; then
      adb_logcat -b all -v nsec -t ${2}
    else
      adb_logcat -b all -v nsec -d
    fi
    shift 2
  fi >&2
  echo "${RED}[  FAILED  ]${NORMAL} ${@}" >&2
  cleanup
  restore
  test_duration
  exit 1
}

[ "USAGE: EXPECT_EQ <lval> <rval> [--warning [message]]

Returns true if (regex) lval matches rval" ]
EXPECT_EQ() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  local error=1
  local prefix="${RED}[    ERROR ]${NORMAL}"
  if [ X"${1}" = X"--warning" ]; then
      prefix="${RED}[  WARNING ]${NORMAL}"
      error=0
      shift 1
  fi
  if ! ( echo X"${rval}" | grep '^X'"${lval}"'$' >/dev/null 2>/dev/null ); then
    if [ `echo ${lval}${rval}${*} | wc -c` -gt 50 -o "${rval}" != "${rval%
*}" ]; then
      echo "${prefix} expected \"${lval}\""
      echo "${prefix} got \"${rval}\"" |
        sed ": again
             N
             s/\(\n\)\([^ ]\)/\1${INDENT}\2/
             t again"
      if [ -n "${*}" ] ; then
        echo "${prefix} ${*}"
      fi
    else
      echo "${prefix} expected \"${lval}\" got \"${rval}\" ${*}"
    fi >&2
    return ${error}
  fi
  if [ -n "${*}" ] ; then
    prefix="${GREEN}[     INFO ]${NORMAL}"
    if [ X"${lval}" != X"${rval}" ]; then  # we were supplied a regex?
      if [ `echo ${lval}${rval}${*} | wc -c` -gt 60 -o "${rval}" != "${rval% *}" ]; then
        echo "${prefix} ok \"${lval}\""
        echo "       = \"${rval}\"" |
          sed ": again
               N
               s/\(\n\)\([^ ]\)/\1${INDENT}\2/
               t again"
        if [ -n "${*}" ] ; then
          echo "${prefix} ${*}"
        fi
      else
        echo "${prefix} ok \"${lval}\" = \"${rval}\" ${*}"
      fi
    else
      echo "${prefix} ok \"${lval}\" ${*}"
    fi >&2
  fi
  return 0
}

[ "USAGE: EXPECT_NE <lval> <rval> [--warning [message]]

Returns true if lval matches rval" ]
EXPECT_NE() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  local error=1
  local prefix="${RED}[    ERROR ]${NORMAL}"
  if [ X"${1}" = X"--warning" ]; then
      prefix="${RED}[  WARNING ]${NORMAL}"
      error=0
      shift 1
  fi
  if [ X"${rval}" = X"${lval}" ]; then
    echo "${prefix} did not expect \"${lval}\" ${*}" >&2
    return ${error}
  fi
  if [ -n "${*}" ] ; then
    echo "${prefix} ok \"${lval}\" not \"${rval}\" ${*}" >&2
  fi
  return 0
}

[ "USAGE: check_eq <lval> <rval> [--warning [message]]

Exits if (regex) lval mismatches rval" ]
check_eq() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  if [ X"${1}" = X"--warning" ]; then
      EXPECT_EQ "${lval}" "${rval}" ${*}
      return
  fi
  if ! EXPECT_EQ "${lval}" "${rval}"; then
    die "${@}"
  fi
}

[ "USAGE: check_ne <lval> <rval> [--warning [message]]

Exits if lval matches rval" ]
check_ne() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  if [ X"${1}" = X"--warning" ]; then
      EXPECT_NE "${lval}" "${rval}" ${*}
      return
  fi
  if ! EXPECT_NE "${lval}" "${rval}"; then
    die "${@}"
  fi
}

[ "USAGE: skip_administrative_mounts [data] < /proc/mounts

Filters out all administrative (eg: sysfs) mounts uninteresting to the test" ]
skip_administrative_mounts() {
  if [ "data" = "${1}" ]; then
    grep -v " /data "
  else
    cat -
  fi |
  grep -v \
    -e "^\(overlay\|tmpfs\|none\|sysfs\|proc\|selinuxfs\|debugfs\|bpf\) " \
    -e "^\(binfmt_misc\|cg2_bpf\|pstore\|tracefs\|adb\|mtp\|ptp\|devpts\) " \
    -e "^\(ramdumpfs\|binder\|/sys/kernel/debug\|securityfs\) " \
    -e " functionfs " \
    -e "^\(/data/media\|/dev/block/loop[0-9]*\) " \
    -e "^rootfs / rootfs rw," \
    -e " /\(cache\|mnt/scratch\|mnt/vendor/persist\|persist\|metadata\) "
}

[ "USAGE: skip_unrelated_mounts < /proc/mounts

or output from df

Filters out all apex and vendor override administrative overlay mounts
uninteresting to the test" ]
skip_unrelated_mounts() {
    grep -v "^overlay.* /\(apex\|bionic\|system\|vendor\)/[^ ]" |
      grep -v "[%] /\(data_mirror\|apex\|bionic\|system\|vendor\)/[^ ][^ ]*$"
}

##
##  MAINLINE
##

HOSTOS=`uname`
GETOPTS="--alternative --unquoted
         --longoptions help,serial:,colour,color,no-colour,no-color
         --longoptions wait-adb:,wait-fastboot:
         --longoptions wait-screen,wait-display
         --longoptions no-wait-screen,no-wait-display
         --longoptions gtest_print_time,print-time
         --"
if [ "Darwin" = "${HOSTOS}" ]; then
  GETOPTS=
  USAGE="`echo \"${USAGE}\" |
            sed 's/--color/       /g
                 1s/--help/-h/
                 s/--help/      /g
                 s/--no-wait-screen/                /g
                 s/--print-time/            /g
                 1s/--serial/-s/
                 s/--serial/        /g
                 s/--wait-adb/          /g
                 s/--wait-fastboot/               /g'`"
fi
OPTIONS=`getopt ${GETOPTS} "?a:cCdDf:hs:t" ${*}` ||
  ( echo "${USAGE}" >&2 ; false ) ||
  die "getopt failure"
set -- ${OPTIONS}

color=false
while [ ${#} -gt 0 ]; do
  case ${1} in
    -h | --help | -\?)
      echo "${USAGE}" >&2
      exit 0
      ;;
    -s | --serial)
      export ANDROID_SERIAL=${2}
      shift
      ;;
    -c | --color | --colour)
      color=true
      ;;
    -C | --no-color | --no-colour)
      color=false
      ;;
    -D | --no-wait-display | --no-wait-screen)
      screen_wait=false
      ;;
    -d | --wait-display | --wait-screen)
      screen_wait=true
      ;;
    -t | --print-time | --gtest_print_time)
      print_time=true
      ;;
    -a | --wait-adb)
      ADB_WAIT=${2}
      shift
      ;;
    -f | --wait-fastboot)
      FASTBOOT_WAIT=${2}
      shift
      ;;
    --)
      shift
      break
      ;;
    -*)
      echo "${USAGE}" >&2
      die "${0}: error unknown option ${1}"
      ;;
    *)
      break
      ;;
  esac
  shift
done
if ! ${color}; then
  GREEN=""
  RED=""
  YELLOW=""
  BLUE=""
  NORMAL=""
fi

# Set an ERR trap handler to report any unhandled error
trap 'die "line ${LINENO}: unhandled error"' ERR

if ${print_time}; then
  echo "${BLUE}[     INFO ]${NORMAL}" start `date` >&2
fi

inFastboot && die "device in fastboot mode"
inRecovery && die "device in recovery mode"
if ! inAdb; then
  echo "${YELLOW}[  WARNING ]${NORMAL} device not in adb mode" >&2
  adb_wait ${ADB_WAIT}
fi
inAdb || die "specified device not in adb mode"
isDebuggable || die "device not a debug build"
enforcing=true
if ! adb_su getenforce </dev/null | grep 'Enforcing' >/dev/null; then
  echo "${YELLOW}[  WARNING ]${NORMAL} device does not have sepolicy in enforcing mode" >&2
  enforcing=false
fi

# Do something.

# Collect characteristics of the device and report.

D=`get_property ro.serialno`
[ -n "${D}" ] || D=`get_property ro.boot.serialno`
[ -z "${D}" -o -n "${ANDROID_SERIAL}" ] || ANDROID_SERIAL=${D}
USB_SERIAL=
if [ -n "${ANDROID_SERIAL}" -a "Darwin" != "${HOSTOS}" ]; then
  USB_SERIAL="`find /sys/devices -name serial | grep usb || true`"
  if [ -n "${USB_SERIAL}" ]; then
    USB_SERIAL=`echo "${USB_SERIAL}" |
                  xargs grep -l ${ANDROID_SERIAL} || true`
  fi
fi
USB_ADDRESS=
if [ -n "${USB_SERIAL}" ]; then
  USB_ADDRESS=${USB_SERIAL%/serial}
  USB_ADDRESS=usb${USB_ADDRESS##*/}
fi
[ -z "${ANDROID_SERIAL}${USB_ADDRESS}" ] ||
  USB_DEVICE=`usb_devnum`
  echo "${BLUE}[     INFO ]${NORMAL}" ${ANDROID_SERIAL} ${USB_ADDRESS} ${USB_DEVICE} >&2
BUILD_DESCRIPTION=`get_property ro.build.description`
[ -z "${BUILD_DESCRIPTION}" ] ||
  echo "${BLUE}[     INFO ]${NORMAL} ${BUILD_DESCRIPTION}" >&2
KERNEL_VERSION="`adb_su cat /proc/version </dev/null 2>/dev/null`"
[ -z "${KERNEL_VERSION}" ] ||
  echo "${BLUE}[     INFO ]${NORMAL} ${KERNEL_VERSION}" >&2
ACTIVE_SLOT=`get_active_slot`
[ -z "${ACTIVE_SLOT}" ] ||
  echo "${BLUE}[     INFO ]${NORMAL} active slot is ${ACTIVE_SLOT}" >&2

# Acquire list of system partitions

PARTITIONS=`adb_su cat /vendor/etc/fstab* </dev/null |
              skip_administrative_mounts |
              sed -n "s@^\([^ ${TAB}/][^ ${TAB}/]*\)[ ${TAB}].*[, ${TAB}]ro[, ${TAB}].*@\1@p" |
              sort -u |
              tr '\n' ' '`
PARTITIONS="${PARTITIONS:-system vendor}"
# KISS (we do not support sub-mounts for system partitions currently)
MOUNTS="`for i in ${PARTITIONS}; do
           echo /${i}
         done |
         tr '\n' ' '`"
echo "${BLUE}[     INFO ]${NORMAL} System Partitions list: ${PARTITIONS}" >&2

# Report existing partition sizes
adb_sh ls -l /dev/block/by-name/ /dev/block/mapper/ </dev/null 2>/dev/null |
  sed -n 's@.* \([^ ]*\) -> /dev/block/\([^ ]*\)$@\1 \2@p' |
  while read name device; do
    [ super = ${name} -o cache = ${name} ] ||
      (
        for i in ${PARTITIONS}; do
          [ ${i} = ${name} -o ${i} = ${name%_[ab]} ] && exit
        done
        exit 1
      ) ||
      continue

    case ${device} in
      sd*)
        device=${device%%[0-9]*}/${device}
        ;;
    esac
    size=`adb_su cat /sys/block/${device}/size 2>/dev/null </dev/null` &&
      size=`expr ${size} / 2` &&
      echo "${BLUE}[     INFO ]${NORMAL} partition ${name} device ${device} size ${size}K" >&2
  done

# If reboot too soon after fresh flash, could trip device update failure logic
if ${screen_wait}; then
  echo "${YELLOW}[  WARNING ]${NORMAL} waiting for screen to come up. Consider --no-wait-screen option" >&2
fi
if ! wait_for_screen && ${screen_wait}; then
  screen_wait=false
  echo "${YELLOW}[  WARNING ]${NORMAL} not healthy, no launcher, skipping wait for screen" >&2
fi

# Can we test remount -R command?
OVERLAYFS_BACKING="cache mnt/scratch"
overlayfs_supported=true
if [ "orange" != "`get_property ro.boot.verifiedbootstate`" -o \
     "2" != "`get_property partition.system.verified`" ]; then
  restore() {
    ${overlayfs_supported} || return 0
    inFastboot &&
      fastboot reboot &&
      adb_wait ${ADB_WAIT} ||
      true
    if inAdb; then
      reboot=false
      for d in ${OVERLAYFS_BACKING}; do
        if adb_test -d /${d}/overlay; then
          adb_su rm -rf /${d}/overlay </dev/null
          reboot=true
        fi
      done
      if ${reboot}; then
        adb_reboot &&
        adb_wait ${ADB_WAIT}
      fi
    fi
  }
else
  restore() {
    ${overlayfs_supported} || return 0
    inFastboot &&
      fastboot reboot &&
      adb_wait ${ADB_WAIT} ||
      true
    inAdb &&
      adb_root &&
      adb enable-verity >/dev/null 2>/dev/null &&
      adb_reboot &&
      adb_wait ${ADB_WAIT}
  }

  echo "${GREEN}[ RUN      ]${NORMAL} Testing adb shell su root remount -R command" >&2

  avc_check
  T=`adb_date`
  adb_su remount -R system </dev/null
  err=${?}
  if [ "${err}" != 0 ]; then
    echo "${YELLOW}[  WARNING ]${NORMAL} adb shell su root remount -R system = ${err}, likely did not reboot!" >&2
    T="-t ${T}"
  else
    # Rebooted, logcat will be meaningless, and last logcat will likely be clear
    T=""
  fi
  sleep 2
  adb_wait ${ADB_WAIT} ||
    die "waiting for device after adb shell su root remount -R system `usb_status`"
  if [ "orange" != "`get_property ro.boot.verifiedbootstate`" -o \
       "2" = "`get_property partition.system.verified`" ]; then
    die ${T} "remount -R command failed
${INDENT}ro.boot.verifiedbootstate=\"`get_property ro.boot.verifiedbootstate`\"
${INDENT}partition.system.verified=\"`get_property partition.system.verified`\""
  fi

  echo "${GREEN}[       OK ]${NORMAL} adb shell su root remount -R command" >&2
fi

echo "${GREEN}[ RUN      ]${NORMAL} Testing kernel support for overlayfs" >&2

adb_wait || die "wait for device failed"
adb_root ||
  die "initial setup"

adb_test -d /sys/module/overlay ||
  adb_sh grep "nodev${TAB}overlay" /proc/filesystems </dev/null >/dev/null 2>/dev/null &&
  echo "${GREEN}[       OK ]${NORMAL} overlay module present" >&2 ||
  (
    echo "${YELLOW}[  WARNING ]${NORMAL} overlay module not present" >&2 &&
      false
  ) ||
  overlayfs_supported=false
if ${overlayfs_supported}; then
  adb_test -f /sys/module/overlay/parameters/override_creds &&
    echo "${GREEN}[       OK ]${NORMAL} overlay module supports override_creds" >&2 ||
    case `adb_sh uname -r </dev/null` in
      4.[456789].* | 4.[1-9][0-9]* | [56789].*)
        echo "${YELLOW}[  WARNING ]${NORMAL} overlay module does not support override_creds" >&2 &&
        overlayfs_supported=false
        ;;
      *)
        echo "${GREEN}[       OK ]${NORMAL} overlay module uses caller's creds" >&2
        ;;
    esac
fi

echo "${GREEN}[ RUN      ]${NORMAL} Checking current overlayfs status" >&2

# We can not universally use adb enable-verity to ensure device is
# in a overlayfs disabled state since it can prevent reboot on
# devices that remount the physical content rather than overlayfs.
# So lets do our best to surgically wipe the overlayfs state without
# having to go through enable-verity transition.
reboot=false
for d in ${OVERLAYFS_BACKING}; do
  if adb_test -d /${d}/overlay; then
    echo "${YELLOW}[  WARNING ]${NORMAL} /${d}/overlay is setup, surgically wiping" >&2
    adb_sh rm -rf /${d}/overlay </dev/null ||
      die "/${d}/overlay wipe"
    reboot=true
  fi
done
if ${reboot}; then
  echo "${YELLOW}[  WARNING ]${NORMAL} rebooting before test" >&2
  adb_reboot &&
    adb_wait ${ADB_WAIT} ||
    die "lost device after reboot after wipe `usb_status`"
  adb_root ||
    die "lost device after elevation to root after wipe `usb_status`"
fi
D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay "` &&
  echo "${H}" &&
  echo "${D}" &&
  echo "${YELLOW}[  WARNING ]${NORMAL} overlays present before setup" >&2 ||
  echo "${GREEN}[       OK ]${NORMAL} no overlay present before setup" >&2
overlayfs_needed=true
D=`adb_sh cat /proc/mounts </dev/null |
   skip_administrative_mounts data`
if echo "${D}" | grep /dev/root >/dev/null; then
  D=`echo / /
     echo "${D}" | grep -v /dev/root`
fi
D=`echo "${D}" | cut -s -d' ' -f1 | sort -u`
no_dedupe=true
for d in ${D}; do
  adb_sh tune2fs -l $d </dev/null 2>&1 |
    grep "Filesystem features:.*shared_blocks" >/dev/null &&
  no_dedupe=false
done
D=`adb_sh df -k ${D} </dev/null |
   sed 's@\([%] /\)\(apex\|bionic\|system\|vendor\)/[^ ][^ ]*$@\1@'`
echo "${D}"
if [ X"${D}" = X"${D##* 100[%] }" ] && ${no_dedupe} ; then
  overlayfs_needed=false
  # if device does not need overlays, then adb enable-verity will brick device
  restore() {
    ${overlayfs_supported} || return 0
    inFastboot &&
      fastboot reboot &&
      adb_wait ${ADB_WAIT}
    inAdb &&
      adb_wait ${ADB_WAIT}
  }
elif ! ${overlayfs_supported}; then
  die "need overlayfs, but do not have it"
fi

echo "${GREEN}[ RUN      ]${NORMAL} disable verity" >&2

T=`adb_date`
H=`adb disable-verity 2>&1`
err=${?}
L=
D="${H%?Now reboot your device for settings to take effect*}"
if [ X"${D}" != X"${D##*[Uu]sing overlayfs}" ]; then
  echo "${GREEN}[       OK ]${NORMAL} using overlayfs" >&2
fi
if [ ${err} != 0 ]; then
  echo "${H}"
  ( [ -n "${L}" ] && echo "${L}" && false ) ||
  die -t "${T}" "disable-verity"
fi
rebooted=false
if [ X"${D}" != X"${H}" ]; then
  echo "${H}"
  if [ X"${D}" != X"${D##*setup failed}" ]; then
    echo "${YELLOW}[  WARNING ]${NORMAL} overlayfs setup whined" >&2
  fi
  D=`adb_sh df -k </dev/null` &&
    H=`echo "${D}" | head -1` &&
    D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay " || true` &&
    [ -z "${D}" ] ||
    ( echo "${H}" && echo "${D}" && false ) ||
    die -t ${T} "overlay takeover unexpected at this phase"
  echo "${GREEN}[     INFO ]${NORMAL} rebooting as requested" >&2
  L=`adb_logcat -b all -v nsec -t ${T} 2>&1`
  adb_reboot &&
    adb_wait ${ADB_WAIT} ||
    die "lost device after reboot requested `usb_status`"
  adb_root ||
    die "lost device after elevation to root `usb_status`"
  rebooted=true
  # re-disable verity to see the setup remarks expected
  T=`adb_date`
  H=`adb disable-verity 2>&1`
  err=${?}
  D="${H%?Now reboot your device for settings to take effect*}"
  if [ X"${D}" != X"${D##*[Uu]sing overlayfs}" ]; then
    echo "${GREEN}[       OK ]${NORMAL} using overlayfs" >&2
  fi
  if [ ${err} != 0 ]; then
    T=
  fi
fi
if ${overlayfs_supported} && ${overlayfs_needed} && [ X"${D}" != X"${D##*setup failed}" ]; then
  echo "${D}"
  ( [ -n "${L}" ] && echo "${L}" && false ) ||
  die -t "${T}" "setup for overlay"
fi
if [ X"${D}" != X"${D##*Successfully disabled verity}" ]; then
  echo "${H}"
  D=`adb_sh df -k </dev/null` &&
    H=`echo "${D}" | head -1` &&
    D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay " || true` &&
    [ -z "${D}" ] ||
    ( echo "${H}" && echo "${D}" && false ) ||
    ( [ -n "${L}" ] && echo "${L}" && false ) ||
    die -t "${T}" "overlay takeover unexpected"
  [ -n "${L}" ] && echo "${L}"
  die -t "${T}" "unexpected report of verity being disabled a second time"
elif ${rebooted}; then
  echo "${GREEN}[       OK ]${NORMAL} verity already disabled" >&2
else
  echo "${YELLOW}[  WARNING ]${NORMAL} verity already disabled" >&2
fi

echo "${GREEN}[ RUN      ]${NORMAL} remount" >&2

# Feed log with selinux denials as baseline before overlays
adb_unroot
adb_sh find ${MOUNTS} </dev/null >/dev/null 2>/dev/null || true
adb_root

D=`adb remount 2>&1`
ret=${?}
echo "${D}"
[ ${ret} != 0 ] ||
  [ X"${D}" = X"${D##*remount failed}" ] ||
  ( [ -n "${L}" ] && echo "${L}" && false ) ||
  die -t "${T}" "adb remount failed"
D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | skip_unrelated_mounts | grep "^overlay "` ||
  ( [ -n "${L}" ] && echo "${L}" && false )
ret=${?}
uses_dynamic_scratch=false
scratch_partition=
virtual_ab=`get_property ro.virtual_ab.enabled`
if ${overlayfs_needed}; then
  if [ ${ret} != 0 ]; then
    die -t ${T} "overlay takeover failed"
  fi
  echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
   echo "${YELLOW}[  WARNING ]${NORMAL} overlay takeover not complete" >&2
  if [ -z "${virtual_ab}" ]; then
    scratch_partition=scratch
  fi
  if echo "${D}" | grep " /mnt/scratch" >/dev/null; then
    echo "${BLUE}[     INFO ]${NORMAL} using ${scratch_partition} dynamic partition for overrides" >&2
  fi
  M=`adb_sh cat /proc/mounts </dev/null |
     sed -n 's@\([^ ]*\) /mnt/scratch \([^ ]*\) .*@\2 on \1@p'`
  [ -n "${M}" ] &&
    echo "${BLUE}[     INFO ]${NORMAL} scratch filesystem ${M}"
  uses_dynamic_scratch=true
  if [ "${M}" != "${M##*/dev/block/by-name/}" ]; then
    uses_dynamic_scratch=false
    scratch_partition="${M##*/dev/block/by-name/}"
  fi
  scratch_size=`adb_sh df -k /mnt/scratch </dev/null 2>/dev/null |
                while read device kblocks used available use mounted on; do
                  if [ "/mnt/scratch" = "\${mounted}" ]; then
                    echo \${kblocks}
                  fi
                done` &&
    [ -n "${scratch_size}" ] ||
    die "scratch size"
  echo "${BLUE}[     INFO ]${NORMAL} scratch size ${scratch_size}KB" >&2
  for d in ${OVERLAYFS_BACKING}; do
    if adb_test -d /${d}/overlay/system/upper; then
      echo "${BLUE}[     INFO ]${NORMAL} /${d}/overlay is setup" >&2
    fi
  done

  echo "${H}" &&
    echo "${D}" &&
    echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
    die  "overlay takeover after remount"
  !(adb_sh grep "^overlay " /proc/mounts </dev/null |
    skip_unrelated_mounts |
    grep " overlay ro,") ||
    die "remount overlayfs missed a spot (ro)"
  !(adb_sh grep -v noatime /proc/mounts </dev/null |
    skip_administrative_mounts data |
    skip_unrelated_mounts |
    grep -v ' ro,') ||
    die "mounts are not noatime"
  D=`adb_sh grep " rw," /proc/mounts </dev/null |
     skip_administrative_mounts data`
  if echo "${D}" | grep /dev/root >/dev/null; then
    D=`echo / /
       echo "${D}" | grep -v /dev/root`
  fi
  D=`echo "${D}" | cut -s -d' ' -f1 | sort -u`
  bad_rw=false
  for d in ${D}; do
    if adb_sh tune2fs -l $d </dev/null 2>&1 |
       grep "Filesystem features:.*shared_blocks" >/dev/null; then
      bad_rw=true
    else
      d=`adb_sh df -k ${D} </dev/null |
       sed 's@\([%] /\)\(apex\|bionic\|system\|vendor\)/[^ ][^ ]*$@\1@'`
      [ X"${d}" = X"${d##* 100[%] }" ] ||
        bad_rw=true
    fi
  done
  [ -z "${D}" ] ||
    D=`adb_sh df -k ${D} </dev/null |
       sed -e 's@\([%] /\)\(apex\|bionic\|system\|vendor\)/[^ ][^ ]*$@\1@' \
           -e 's/^Filesystem      /Filesystem (rw) /'`
  [ -z "${D}" ] || echo "${D}"
  ${bad_rw} && die "remount overlayfs missed a spot (rw)"
else
  if [ ${ret} = 0 ]; then
    die -t ${T} "unexpected overlay takeover"
  fi
fi

# Check something.

echo "${GREEN}[ RUN      ]${NORMAL} push content to ${MOUNTS}" >&2

A="Hello World! $(date)"
for i in ${MOUNTS}; do
  echo "${A}" | adb_sh cat - ">${i}/hello"
  B="`adb_cat ${i}/hello`" ||
    die "${i#/} hello"
  check_eq "${A}" "${B}" ${i} before reboot
done
echo "${A}" | adb_sh cat - ">/system/priv-app/hello"
B="`adb_cat /system/priv-app/hello`" ||
  die "system priv-app hello"
check_eq "${A}" "${B}" /system/priv-app before reboot
SYSTEM_DEVT=`adb_sh stat --format=%D /system/hello </dev/null`
VENDOR_DEVT=`adb_sh stat --format=%D /vendor/hello </dev/null`
SYSTEM_INO=`adb_sh stat --format=%i /system/hello </dev/null`
VENDOR_INO=`adb_sh stat --format=%i /vendor/hello </dev/null`
BASE_SYSTEM_DEVT=`adb_sh stat --format=%D /system/bin/stat </dev/null`
BASE_VENDOR_DEVT=`adb_sh stat --format=%D /vendor/bin/stat </dev/null`
check_eq "${SYSTEM_DEVT%[0-9a-fA-F][0-9a-fA-F]}" "${VENDOR_DEVT%[0-9a-fA-F][0-9a-fA-F]}" vendor and system devt
check_ne "${SYSTEM_INO}" "${VENDOR_INO}" vendor and system inode
if ${overlayfs_needed}; then
  check_ne "${SYSTEM_DEVT}" "${BASE_SYSTEM_DEVT}" system devt
  check_ne "${VENDOR_DEVT}" "${BASE_VENDOR_DEVT}" vendor devt
else
  check_eq "${SYSTEM_DEVT}" "${BASE_SYSTEM_DEVT}" system devt
  check_eq "${VENDOR_DEVT}" "${BASE_VENDOR_DEVT}" vendor devt
fi
check_ne "${BASE_SYSTEM_DEVT}" "${BASE_VENDOR_DEVT}" --warning system/vendor devt
[ -n "${SYSTEM_DEVT%[0-9a-fA-F][0-9a-fA-F]}" ] ||
  echo "${YELLOW}[  WARNING ]${NORMAL} system devt ${SYSTEM_DEVT} major 0" >&2
[ -n "${VENDOR_DEVT%[0-9a-fA-F][0-9a-fA-F]}" ] ||
  echo "${YELLOW}[  WARNING ]${NORMAL} vendor devt ${VENDOR_DEVT} major 0" >&2

# Download libc.so, append some garbage, push back, and check if the file
# is updated.
tempdir="`mktemp -d`"
cleanup() {
  rm -rf ${tempdir}
}
adb pull /system/lib/bootstrap/libc.so ${tempdir} >/dev/null ||
  die "pull libc.so from device"
garbage="D105225BBFCB1EB8AB8EBDB7094646F0"
echo "${garbage}" >> ${tempdir}/libc.so
adb push ${tempdir}/libc.so /system/lib/bootstrap/libc.so >/dev/null ||
  die "push libc.so to device"
adb pull /system/lib/bootstrap/libc.so ${tempdir}/libc.so.fromdevice >/dev/null ||
  die "pull libc.so from device"
diff ${tempdir}/libc.so ${tempdir}/libc.so.fromdevice > /dev/null ||
  die "libc.so differ"

echo "${GREEN}[ RUN      ]${NORMAL} reboot to confirm content persistent" >&2

fixup_from_recovery() {
  inRecovery || return 1
  echo "${YELLOW}[    ERROR ]${NORMAL} Device in recovery" >&2
  adb reboot </dev/null
  adb_wait ${ADB_WAIT}
}

adb_reboot &&
  adb_wait ${ADB_WAIT} ||
  fixup_from_recovery ||
  die "reboot after override content added failed `usb_status`"

if ${overlayfs_needed}; then
  D=`adb_su df -k </dev/null` &&
    H=`echo "${D}" | head -1` &&
    D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay "` ||
    ( echo "${L}" && false ) ||
    die -d "overlay takeover failed after reboot"

  adb_su sed -n '1,/overlay \/system/p' /proc/mounts </dev/null |
    skip_administrative_mounts |
    grep -v ' \(erofs\|squashfs\|ext4\|f2fs\|vfat\) ' &&
    echo "${YELLOW}[  WARNING ]${NORMAL} overlay takeover after first stage init" >&2 ||
    echo "${GREEN}[       OK ]${NORMAL} overlay takeover in first stage init" >&2
fi

if ${enforcing}; then
  adb_unroot ||
    die "device not in unroot'd state"
  B="`adb_cat /vendor/hello 2>&1`"
  check_eq "cat: /vendor/hello: Permission denied" "${B}" vendor after reboot w/o root
  echo "${GREEN}[       OK ]${NORMAL} /vendor content correct MAC after reboot" >&2
  # Feed unprivileged log with selinux denials as a result of overlays
  wait_for_screen
  adb_sh find ${MOUNTS} </dev/null >/dev/null 2>/dev/null || true
fi
# If overlayfs has a nested security problem, this will fail.
B="`adb_ls /system/`" ||
  die "adb ls /system"
[ X"${B}" != X"${B#*priv-app}" ] ||
  die "adb ls /system/priv-app"
B="`adb_cat /system/priv-app/hello`"
check_eq "${A}" "${B}" /system/priv-app after reboot
# Only root can read vendor if sepolicy permissions are as expected.
adb_root ||
  die "adb root"
for i in ${MOUNTS}; do
  B="`adb_cat ${i}/hello`"
  check_eq "${A}" "${B}" ${i#/} after reboot
  echo "${GREEN}[       OK ]${NORMAL} ${i} content remains after reboot" >&2
done

check_eq "${SYSTEM_DEVT}" "`adb_sh stat --format=%D /system/hello </dev/null`" system devt after reboot
check_eq "${VENDOR_DEVT}" "`adb_sh stat --format=%D /vendor/hello </dev/null`" vendor devt after reboot
check_eq "${SYSTEM_INO}" "`adb_sh stat --format=%i /system/hello </dev/null`" system inode after reboot
check_eq "${VENDOR_INO}" "`adb_sh stat --format=%i /vendor/hello </dev/null`" vendor inode after reboot
check_eq "${BASE_SYSTEM_DEVT}" "`adb_sh stat --format=%D /system/bin/stat </dev/null`" --warning base system devt after reboot
check_eq "${BASE_VENDOR_DEVT}" "`adb_sh stat --format=%D /vendor/bin/stat </dev/null`" --warning base vendor devt after reboot
check_eq "${BASE_SYSTEM_DEVT}" "`adb_sh stat --format=%D /system/xbin/su </dev/null`" --warning devt for su after reboot

# Feed log with selinux denials as a result of overlays
adb_sh find ${MOUNTS} </dev/null >/dev/null 2>/dev/null || true

# Check if the updated libc.so is persistent after reboot.
adb_root &&
  adb pull /system/lib/bootstrap/libc.so ${tempdir}/libc.so.fromdevice >/dev/null ||
  die "pull libc.so from device"
diff ${tempdir}/libc.so ${tempdir}/libc.so.fromdevice > /dev/null || die "libc.so differ"
rm -rf ${tempdir}
cleanup() {
  true
}
echo "${GREEN}[       OK ]${NORMAL} /system/lib/bootstrap/libc.so content remains after reboot" >&2

echo "${GREEN}[ RUN      ]${NORMAL} flash vendor, confirm its content disappears" >&2

H=`adb_sh echo '${HOSTNAME}' </dev/null 2>/dev/null`
is_bootloader_fastboot=false
# cuttlefish?
[ X"${H}" != X"${H#vsoc}" ] || is_bootloader_fastboot=true
is_userspace_fastboot=false

if ! ${is_bootloader_fastboot}; then
  echo "${YELLOW}[  WARNING ]${NORMAL} does not support fastboot, skipping"
elif [ -z "${ANDROID_PRODUCT_OUT}" ]; then
  echo "${YELLOW}[  WARNING ]${NORMAL} build tree not setup, skipping"
elif [ ! -s "${ANDROID_PRODUCT_OUT}/vendor.img" ]; then
  echo "${YELLOW}[  WARNING ]${NORMAL} vendor image missing, skipping"
elif [ "${ANDROID_PRODUCT_OUT}" = "${ANDROID_PRODUCT_OUT%*/${H}}" ]; then
  echo "${YELLOW}[  WARNING ]${NORMAL} wrong vendor image, skipping"
elif [ -z "${ANDROID_HOST_OUT}" ]; then
  echo "${YELLOW}[  WARNING ]${NORMAL} please run lunch, skipping"
elif ! (
          adb_cat /vendor/build.prop |
          cmp -s ${ANDROID_PRODUCT_OUT}/vendor/build.prop
       ) >/dev/null 2>/dev/null; then
  echo "${YELLOW}[  WARNING ]${NORMAL} vendor image signature mismatch, skipping"
else
  wait_for_screen
  avc_check
  adb reboot fastboot </dev/null ||
    die "fastbootd not supported (wrong adb in path?)"
  any_wait ${ADB_WAIT} &&
    inFastboot ||
    die "reboot into fastboot to flash vendor `usb_status` (bad bootloader?)"
  fastboot flash vendor ||
    ( fastboot reboot && false) ||
    die "fastboot flash vendor"
  fastboot_getvar is-userspace yes &&
    is_userspace_fastboot=true
  if [ -n "${scratch_paritition}" ]; then
    fastboot_getvar partition-type:${scratch_partition} raw ||
      ( fastboot reboot && false) ||
      die "fastboot can not see ${scratch_partition} parameters"
    if ${uses_dynamic_scratch}; then
      # check ${scratch_partition} via fastboot
      fastboot_getvar has-slot:${scratch_partition} no &&
        fastboot_getvar is-logical:${scratch_partition} yes ||
        ( fastboot reboot && false) ||
        die "fastboot can not see ${scratch_partition} parameters"
    else
      fastboot_getvar is-logical:${scratch_partition} no ||
        ( fastboot reboot && false) ||
        die "fastboot can not see ${scratch_partition} parameters"
    fi
    if ! ${uses_dynamic_scratch}; then
      fastboot reboot-bootloader ||
        die "Reboot into fastboot"
    fi
    if ${uses_dynamic_scratch}; then
      echo "${BLUE}[     INFO ]${NORMAL} expect fastboot erase ${scratch_partition} to fail" >&2
      fastboot erase ${scratch_partition} &&
        ( fastboot reboot || true) &&
        die "fastboot can erase ${scratch_partition}"
    fi
    echo "${BLUE}[     INFO ]${NORMAL} expect fastboot format ${scratch_partition} to fail" >&2
    fastboot format ${scratch_partition} &&
      ( fastboot reboot || true) &&
      die "fastboot can format ${scratch_partition}"
  fi
  fastboot reboot ||
    die "can not reboot out of fastboot"
  echo "${YELLOW}[  WARNING ]${NORMAL} adb after fastboot"
  adb_wait ${ADB_WAIT} ||
    fixup_from_recovery ||
    die "did not reboot after formatting ${scratch_partition} `usb_status`"
  if ${overlayfs_needed}; then
    adb_root &&
      D=`adb_sh df -k </dev/null` &&
      H=`echo "${D}" | head -1` &&
      D=`echo "${D}" | skip_unrelated_mounts | grep "^overlay "` &&
      echo "${H}" &&
      echo "${D}" &&
      echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
      die  "overlay /system takeover after flash vendor"
    echo "${D}" | grep "^overlay .* /vendor\$" >/dev/null &&
      if ${is_userspace_fastboot}; then
        die  "overlay supposed to be minus /vendor takeover after flash vendor"
      else
        echo "${YELLOW}[  WARNING ]${NORMAL} user fastboot missing required to invalidate, ignoring a failure" >&2
        echo "${YELLOW}[  WARNING ]${NORMAL} overlay supposed to be minus /vendor takeover after flash vendor" >&2
      fi
  fi
  B="`adb_cat /system/hello`"
  check_eq "${A}" "${B}" system after flash vendor
  B="`adb_ls /system/`" ||
    die "adb ls /system"
  [ X"${B}" != X"${B#*priv-app}" ] ||
    die "adb ls /system/priv-app"
  B="`adb_cat /system/priv-app/hello`"
  check_eq "${A}" "${B}" system/priv-app after flash vendor
  adb_root ||
    die "adb root"
  B="`adb_cat /vendor/hello`"
  if ${is_userspace_fastboot} || ! ${overlayfs_needed}; then
    check_eq "cat: /vendor/hello: No such file or directory" "${B}" \
             vendor content after flash vendor
  else
    echo "${YELLOW}[  WARNING ]${NORMAL} user fastboot missing required to invalidate, ignoring a failure" >&2
    check_eq "cat: /vendor/hello: No such file or directory" "${B}" \
             --warning vendor content after flash vendor
  fi

  check_eq "${SYSTEM_DEVT}" "`adb_sh stat --format=%D /system/hello </dev/null`" system devt after reboot
  check_eq "${SYSTEM_INO}" "`adb_sh stat --format=%i /system/hello </dev/null`" system inode after reboot
  check_eq "${BASE_SYSTEM_DEVT}" "`adb_sh stat --format=%D /system/bin/stat </dev/null`" --warning base system devt after reboot
  check_eq "${BASE_SYSTEM_DEVT}" "`adb_sh stat --format=%D /system/xbin/su </dev/null`" --warning devt for su after reboot

fi

wait_for_screen
echo "${GREEN}[ RUN      ]${NORMAL} remove test content (cleanup)" >&2

T=`adb_date`
H=`adb remount 2>&1`
err=${?}
L=
D="${H%?Now reboot your device for settings to take effect*}"
if [ X"${H}" != X"${D}" ]; then
  echo "${YELLOW}[  WARNING ]${NORMAL} adb remount requires a reboot after partial flash (legacy avb)"
  L=`adb_logcat -b all -v nsec -t ${T} 2>&1`
  adb_reboot &&
    adb_wait ${ADB_WAIT} &&
    adb_root ||
    die "failed to reboot"
  T=`adb_date`
  H=`adb remount 2>&1`
  err=${?}
fi
echo "${H}"
[ ${err} = 0 ] &&
  ( adb_sh rm /vendor/hello </dev/null 2>/dev/null || true ) &&
  adb_sh rm /system/hello /system/priv-app/hello </dev/null ||
  ( [ -n "${L}" ] && echo "${L}" && false ) ||
  die -t ${T} "cleanup hello"
B="`adb_cat /system/hello`"
check_eq "cat: /system/hello: No such file or directory" "${B}" after rm
B="`adb_cat /system/priv-app/hello`"
check_eq "cat: /system/priv-app/hello: No such file or directory" "${B}" after rm
B="`adb_cat /vendor/hello`"
check_eq "cat: /vendor/hello: No such file or directory" "${B}" after rm
for i in ${MOUNTS}; do
  adb_sh rm ${i}/hello </dev/null 2>/dev/null || true
done

if ${is_bootloader_fastboot} && [ -n "${scratch_partition}" ]; then

  echo "${GREEN}[ RUN      ]${NORMAL} test fastboot flash to ${scratch_partition} recovery" >&2

  avc_check
  adb reboot fastboot </dev/null ||
    die "Reboot into fastbootd"
  img=${TMPDIR}/adb-remount-test-${$}.img
  cleanup() {
    rm ${img}
  }
  dd if=/dev/zero of=${img} bs=4096 count=16 2>/dev/null &&
    fastboot_wait ${FASTBOOT_WAIT} ||
    die "reboot into fastboot to flash scratch `usb_status`"
  fastboot flash --force ${scratch_partition} ${img}
  err=${?}
  cleanup
  cleanup() {
    true
  }
  fastboot reboot ||
    die "can not reboot out of fastboot"
  [ 0 -eq ${err} ] ||
    die "fastboot flash ${scratch_partition}"
  adb_wait ${ADB_WAIT} &&
    adb_root ||
    die "did not reboot after flashing empty ${scratch_partition} `usb_status`"
  T=`adb_date`
  D=`adb disable-verity 2>&1`
  err=${?}
  if [ X"${D}" != "${D%?Now reboot your device for settings to take effect*}" ]
  then
    echo "${YELLOW}[  WARNING ]${NORMAL} adb disable-verity requires a reboot after partial flash"
    adb_reboot &&
      adb_wait ${ADB_WAIT} &&
      adb_root ||
      die "failed to reboot"
    T=`adb_date`
    D="${D}
`adb disable-verity 2>&1`"
    err=${?}
  fi

  echo "${D}"
  [ ${err} = 0 ] &&
    [ X"${D}" = X"${D##*setup failed}" ] &&
    [ X"${D}" != X"${D##*[Uu]sing overlayfs}" ] &&
    echo "${GREEN}[       OK ]${NORMAL} ${scratch_partition} recreated" >&2 ||
    die -t ${T} "setup for overlayfs"
  D=`adb remount 2>&1`
  err=${?}
  echo "${D}"
  [ ${err} != 0 ] ||
    [ X"${D}" = X"${D##*remount failed}" ] ||
    ( echo "${D}" && false ) ||
    die -t ${T} "remount failed"
fi

echo "${GREEN}[ RUN      ]${NORMAL} test raw remount commands" >&2

fixup_from_fastboot() {
  inFastboot || return 1
  if [ -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${YELLOW}[    ERROR ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    else
      echo "${YELLOW}[    ERROR ]${NORMAL} Active slot to be set to ${ACTIVE_SLOT}"
    fi >&2
    fastboot --set-active=${ACTIVE_SLOT}
  fi
  fastboot reboot
  adb_wait ${ADB_WAIT}
}

# Prerequisite is a prepped device from above.
adb_reboot &&
  adb_wait ${ADB_WAIT} ||
  fixup_from_fastboot ||
  die "lost device after reboot to ro state `usb_status`"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/vendor is not read-only"
adb_su mount -o rw,remount /vendor </dev/null ||
  die "remount command"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null ||
  die "/vendor is not read-write"
echo "${GREEN}[       OK ]${NORMAL} mount -o rw,remount command works" >&2

# Prerequisite is a prepped device from above.
adb_reboot &&
  adb_wait ${ADB_WAIT} ||
  fixup_from_fastboot ||
  die "lost device after reboot to ro state `usb_status`"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/vendor is not read-only"
adb_su remount vendor </dev/null ||
  die "remount command"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null ||
  die "/vendor is not read-write"
adb_sh grep " /system .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/vendor is not read-only"
echo "${GREEN}[       OK ]${NORMAL} remount command works from setup" >&2

# Prerequisite is an overlayfs deconstructed device but with verity disabled.
# This also saves a lot of 'noise' from the command doing a mkfs on backing
# storage and all the related tuning and adjustment.
for d in ${OVERLAYFS_BACKING}; do
  if adb_test -d /${d}/overlay; then
    adb_su rm -rf /${d}/overlay </dev/null ||
      die "/${d}/overlay wipe"
  fi
done
adb_reboot &&
  adb_wait ${ADB_WAIT} ||
  fixup_from_fastboot ||
  die "lost device after reboot after wipe `usb_status`"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/vendor is not read-only"
adb_su remount vendor </dev/null ||
  die "remount command"
adb_su df -k </dev/null | skip_unrelated_mounts
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null ||
  die "/vendor is not read-write"
adb_sh grep " \(/system\|/\) .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/system is not read-only"
echo "${GREEN}[       OK ]${NORMAL} remount command works from scratch" >&2

if ! restore; then
  restore() {
    true
  }
  die "failed to restore verity after remount from scratch test"
fi

err=0

if ${overlayfs_supported}; then
  echo "${GREEN}[ RUN      ]${NORMAL} test 'adb remount -R'" >&2
  avc_check
  adb_root ||
    die "adb root in preparation for adb remount -R"
  T=`adb_date`
  adb remount -R
  err=${?}
  if [ "${err}" != 0 ]; then
    die -t ${T} "adb remount -R = ${err}"
  fi
  sleep 2
  adb_wait ${ADB_WAIT} ||
    die "waiting for device after adb remount -R `usb_status`"
  if [ "orange" != "`get_property ro.boot.verifiedbootstate`" -o \
       "2" = "`get_property partition.system.verified`" ] &&
     [ -n "`get_property ro.boot.verifiedbootstate`" -o \
       -n "`get_property partition.system.verified`" ]; then
    die "remount -R command failed to disable verity
${INDENT}ro.boot.verifiedbootstate=\"`get_property ro.boot.verifiedbootstate`\"
${INDENT}partition.system.verified=\"`get_property partition.system.verified`\""
  fi

  echo "${GREEN}[       OK ]${NORMAL} 'adb remount -R' command" >&2

  restore
  err=${?}
fi

restore() {
  true
}

[ ${err} = 0 ] ||
  die "failed to restore verity"

echo "${GREEN}[  PASSED  ]${NORMAL} adb remount" >&2

test_duration
