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
OVERLAYFS_BACKING="cache mnt/scratch"

ADB_WAIT=4m
FASTBOOT_WAIT=2m
screen_wait=true

##
##  Helper Functions
##

[ "USAGE: LOG [RUN|OK|PASSED|WARNING|ERROR|FAILED|INFO] [message]..." ]
LOG() {
  case "${1}" in
    R*)
      shift
      echo "${GREEN}[ RUN      ]${NORMAL}" "${@}"
      ;;
    OK)
      shift
      echo "${GREEN}[       OK ]${NORMAL}" "${@}"
      ;;
    P*)
      shift
      echo "${GREEN}[  PASSED  ]${NORMAL}" "${@}"
      ;;
    W*)
      shift
      echo "${YELLOW}[  WARNING ]${NORMAL}" "${@}"
      ;;
    E*)
      shift
      echo "${RED}[    ERROR ]${NORMAL}" "${@}"
      ;;
    F*)
      shift
      echo "${RED}[  FAILED  ]${NORMAL}" "${@}"
      ;;
    I*)
      shift
      echo "${BLUE}[     INFO ]${NORMAL}" "${@}"
      ;;
    *)
      echo "${BLUE}[     INFO ]${NORMAL}" "${@}"
      ;;
  esac >&2
}

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
  LOG INFO "logcat ${*}"
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
  LOG WARNING "unlabeled sepolicy violations:"
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
    duration=$(( ${duration%m} * 60 ))
  elif [ X"${duration}" != X"${duration%h}" ]; then
    duration=$(( ${duration%h} * 3600 ))
  elif [ X"${duration}" != X"${duration%d}" ]; then
    duration=$(( ${duration%d} * 86400 ))
  fi
  local seconds=$(( ${duration} % 60 ))
  local minutes=$(( ( ${duration} / 60 ) % 60 ))
  local hours=$(( ${duration} / 3600 ))
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
    echo ${minutes}:$(( ${seconds} / 10 ))$(( ${seconds} % 10 ))
    return
  fi
  echo ${hours}:$(( ${minutes} / 10 ))$(( ${minutes} % 10 )):$(( ${seconds} / 10 ))$(( ${seconds} % 10))
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
      USB_DEVICE=dev$(( ${USB_DEVICE#dev} + 1 ))
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
    echo -n ". . . waiting ${duration}" ${ANDROID_SERIAL} ${USB_ADDRESS} ${USB_DEVICE} "${CR}" >&2
    timeout --preserve-status --signal=KILL ${1} adb wait-for-device 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}" >&2
  else
    adb wait-for-device
    ret=${?}
  fi
  USB_DEVICE=`usb_devnum`
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      LOG WARNING "Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    fi
  fi
  local end=`date +%s`
  local diff_time=$(( ${end} - ${start} ))
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
    LOG INFO "adb wait duration ${diff_time}${reason}"
  fi

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
      LOG WARNING "Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    fi
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
      LOG WARNING "Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    fi
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
    counter=$(( ${counter} + 1 ))
    if [ ${counter} -gt ${timeout} ]; then
      ${exit_function}
      LOG ERROR "wait_for_screen() timed out ($(format_duration ${timeout}))"
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
    LOG INFO "end $(date)"
    [ -n "${start_time}" ] || return
    end_time=`date +%s`
    local diff_time=$(( ${end_time} - ${start_time} ))
    LOG INFO "duration $(format_duration ${diff_time})"
  fi
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
  LOG FAILED "${@}"
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

[ "USAGE: join_with <delimiter> <strings>

Joins strings with delimiter" ]
join_with() {
  if [ "${#}" -lt 2 ]; then
    echo
    return
  fi
  local delimiter="${1}"
  local result="${2}"
  shift 2
  for element in "${@}"; do
    result+="${delimiter}${element}"
  done
  echo "${result}"
}

[ "USAGE: skip_administrative_mounts [data] < /proc/mounts

Filters out all administrative (eg: sysfs) mounts uninteresting to the test" ]
skip_administrative_mounts() {
  local exclude_filesystems=(
    "overlay" "tmpfs" "none" "sysfs" "proc" "selinuxfs" "debugfs" "bpf"
    "binfmt_misc" "cg2_bpf" "pstore" "tracefs" "adb" "mtp" "ptp" "devpts"
    "ramdumpfs" "binder" "securityfs" "functionfs" "rootfs"
  )
  local exclude_devices=(
    "\/sys\/kernel\/debug" "\/data\/media" "\/dev\/block\/loop[0-9]*"
    "${exclude_filesystems[@]}"
  )
  local exclude_mount_points=(
    "\/cache" "\/mnt\/scratch" "\/mnt\/vendor\/persist" "\/persist"
    "\/metadata"
  )
  if [ "data" = "${1}" ]; then
    exclude_mount_points+=("\/data")
  fi
  awk '$1 !~ /^('"$(join_with "|" "${exclude_devices[@]}")"')$/ &&
      $2 !~ /^('"$(join_with "|" "${exclude_mount_points[@]}")"')$/ &&
      $3 !~ /^('"$(join_with "|" "${exclude_filesystems[@]}")"')$/'
}

[ "USAGE: skip_unrelated_mounts < /proc/mounts

or output from df

Filters out all apex and vendor override administrative overlay mounts
uninteresting to the test" ]
skip_unrelated_mounts() {
    grep -v "^overlay.* /\(apex\|bionic\|system\|vendor\)/[^ ]" |
      grep -v "[%] /\(data_mirror\|apex\|bionic\|system\|vendor\)/[^ ][^ ]*$"
}

[ "USAGE: surgically_wipe_overlayfs

Surgically wipe any mounted overlayfs scratch files.

Returns: true if wiped anything" ]
surgically_wipe_overlayfs() {
  local wiped_anything=false
  for d in ${OVERLAYFS_BACKING}; do
    if adb_su test -d "/${d}/overlay" </dev/null; then
      LOG INFO "/${d}/overlay is setup, surgically wiping"
      adb_su rm -rf "/${d}/overlay" </dev/null
      wiped_anything=true
    fi
  done
  ${wiped_anything}
}

[ "USAGE: is_overlayfs_mounted

Returns: true if overlayfs is mounted" ]
is_overlayfs_mounted() {
  local df_output=$(adb_su df -k </dev/null)
  local df_header_line=$(echo "${df_output}" | head -1)
  local overlay_mounts=$(echo "${df_output}" | tail +2 |
                         skip_unrelated_mounts |
                         awk '$1 == "overlay" || $6 == "/mnt/scratch"')
  if ! echo "${overlay_mounts}" | grep -q '^overlay '; then
    return 1
  fi >/dev/null 2>/dev/null
  ( echo "${df_header_line}"
    echo "${overlay_mounts}"
  ) >&2
  return 0
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

if ${print_time}; then
  LOG INFO "start $(date)"
fi

inFastboot && die "device in fastboot mode"
inRecovery && die "device in recovery mode"
if ! inAdb; then
  LOG WARNING "device not in adb mode"
  adb_wait ${ADB_WAIT}
fi
inAdb || die "specified device not in adb mode"
isDebuggable || die "device not a debug build"
enforcing=true
if ! adb_su getenforce </dev/null | grep 'Enforcing' >/dev/null; then
  LOG WARNING "device does not have sepolicy in enforcing mode"
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
  LOG INFO "${ANDROID_SERIAL} ${USB_ADDRESS} ${USB_DEVICE}"
BUILD_DESCRIPTION=`get_property ro.build.description`
[ -z "${BUILD_DESCRIPTION}" ] ||
  LOG INFO "${BUILD_DESCRIPTION}"
KERNEL_VERSION="`adb_su cat /proc/version </dev/null 2>/dev/null`"
[ -z "${KERNEL_VERSION}" ] ||
  LOG INFO "${KERNEL_VERSION}"
ACTIVE_SLOT=`get_active_slot`
[ -z "${ACTIVE_SLOT}" ] ||
  LOG INFO "active slot is ${ACTIVE_SLOT}"

# Acquire list of system partitions

# KISS (assume system partition mount point is "/<partition name>")
PARTITIONS=`adb_su cat /vendor/etc/fstab* </dev/null |
              grep -v "^[#${SPACE}${TAB}]" |
              skip_administrative_mounts |
              awk '$1 ~ /^[^\/]+$/ && "/"$1 == $2 && $4 ~ /(^|,)ro(,|$)/ { print $1 }' |
              sort -u |
              tr '\n' ' '`
PARTITIONS="${PARTITIONS:-system vendor}"
# KISS (we do not support sub-mounts for system partitions currently)
MOUNTS="`for i in ${PARTITIONS}; do
           echo /${i}
         done |
         tr '\n' ' '`"
LOG INFO "System Partitions list: ${PARTITIONS}"

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
      size=$(( ${size} / 2 )) &&
      LOG INFO "partition ${name} device ${device} size ${size}K"
  done

# If reboot too soon after fresh flash, could trip device update failure logic
if ${screen_wait}; then
  LOG WARNING "waiting for screen to come up. Consider --no-wait-screen option"
fi
if ! wait_for_screen && ${screen_wait}; then
  screen_wait=false
  LOG WARNING "not healthy, no launcher, skipping wait for screen"
fi

# Can we test remount -R command?
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
      if surgically_wipe_overlayfs; then
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

  LOG RUN "Testing adb shell su root remount -R command"

  avc_check
  T=`adb_date`
  adb_su remount -R system </dev/null
  err=${?}
  if [ "${err}" != 0 ]; then
    LOG WARNING "adb shell su root remount -R system = ${err}, likely did not reboot!"
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

  LOG OK "adb shell su root remount -R command"
fi

LOG RUN "Testing kernel support for overlayfs"

adb_wait || die "wait for device failed"
adb_root ||
  die "initial setup"

adb_test -d /sys/module/overlay ||
  adb_sh grep "nodev${TAB}overlay" /proc/filesystems </dev/null >/dev/null 2>/dev/null &&
  LOG OK "overlay module present" ||
  (
    LOG WARNING "overlay module not present" &&
      false
  ) ||
  overlayfs_supported=false
if ${overlayfs_supported}; then
  adb_test -f /sys/module/overlay/parameters/override_creds &&
    LOG OK "overlay module supports override_creds" ||
    case `adb_sh uname -r </dev/null` in
      4.[456789].* | 4.[1-9][0-9]* | [56789].*)
        LOG WARNING "overlay module does not support override_creds" &&
        overlayfs_supported=false
        ;;
      *)
        LOG OK "overlay module uses caller's creds"
        ;;
    esac
fi

LOG RUN "Checking current overlayfs status"

# We can not universally use adb enable-verity to ensure device is
# in a overlayfs disabled state since it can prevent reboot on
# devices that remount the physical content rather than overlayfs.
# So lets do our best to surgically wipe the overlayfs state without
# having to go through enable-verity transition.
if surgically_wipe_overlayfs; then
  LOG WARNING "rebooting before test"
  adb_reboot &&
    adb_wait ${ADB_WAIT} ||
    die "lost device after reboot after wipe `usb_status`"
  adb_root ||
    die "lost device after elevation to root after wipe `usb_status`"
fi
is_overlayfs_mounted &&
  die "overlay takeover unexpected at this phase"
LOG OK "no overlay present before setup"

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
echo "${D}" >&2
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

LOG RUN "disable-verity -R"

L=
T=$(adb_date)
H=$(adb_su disable-verity -R 2>&1)
err="${?}"
echo "${H}" >&2

if [ "${err}" != 0 ]; then
  die -t "${T}" "disable-verity -R"
fi

# Fuzzy search for a line that contains "overlay" and "fail". Informational only.
if echo "${H}" | grep -i "overlay" | grep -iq "fail"; then
  LOG WARNING "overlayfs setup whined"
fi

adb_wait "${ADB_WAIT}" &&
  adb_root ||
  die "lost device after adb shell su root disable-verity -R $(usb_status)"

if ${overlayfs_needed}; then
  if ! is_overlayfs_mounted; then
    die "no overlay being setup after disable-verity -R"
  fi
fi

LOG RUN "remount"

# Feed log with selinux denials as baseline before overlays
adb_unroot
adb_sh find ${MOUNTS} </dev/null >/dev/null 2>/dev/null || true
adb_root

D=`adb remount 2>&1`
ret=${?}
echo "${D}" >&2
[ ${ret} != 0 ] ||
  [ X"${D}" = X"${D##*remount failed}" ] ||
  ( [ -n "${L}" ] && echo "${L}" && false ) >&2 ||
  die -t "${T}" "adb remount failed"
D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | skip_unrelated_mounts | grep "^overlay "` ||
  ( [ -n "${L}" ] && echo "${L}" && false ) >&2
ret=${?}
uses_dynamic_scratch=false
scratch_partition=
virtual_ab=`get_property ro.virtual_ab.enabled`
if ${overlayfs_needed}; then
  if [ ${ret} != 0 ]; then
    die -t ${T} "overlay takeover failed"
  fi
  echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
   LOG WARNING "overlay takeover not complete"
  if [ -z "${virtual_ab}" ]; then
    scratch_partition=scratch
  fi
  if echo "${D}" | grep " /mnt/scratch" >/dev/null; then
    LOG INFO "using ${scratch_partition} dynamic partition for overrides"
  fi
  M=`adb_sh cat /proc/mounts </dev/null |
     sed -n 's@\([^ ]*\) /mnt/scratch \([^ ]*\) .*@\2 on \1@p'`
  [ -n "${M}" ] &&
    LOG INFO "scratch filesystem ${M}"
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
  LOG INFO "scratch size ${scratch_size}KB"
  for d in ${OVERLAYFS_BACKING}; do
    if adb_test -d /${d}/overlay/system/upper; then
      LOG INFO "/${d}/overlay is setup"
    fi
  done

  ( echo "${H}" &&
    echo "${D}"
  ) >&2 &&
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
  [ -z "${D}" ] || echo "${D}" >&2
  ${bad_rw} && die "remount overlayfs missed a spot (rw)"
else
  if [ ${ret} = 0 ]; then
    die -t ${T} "unexpected overlay takeover"
  fi
fi

# Check something.

LOG RUN "push content to ${MOUNTS}"

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
SYSTEM_INO=`adb_sh stat --format=%i /system/hello </dev/null`
VENDOR_INO=`adb_sh stat --format=%i /vendor/hello </dev/null`
check_ne "${SYSTEM_INO}" "${VENDOR_INO}" vendor and system inode

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

LOG RUN "reboot to confirm content persistent"

fixup_from_recovery() {
  inRecovery || return 1
  LOG ERROR "Device in recovery"
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
    ( echo "${L}" && false ) >&2 ||
    die -d "overlay takeover failed after reboot"

  adb_su sed -n '1,/overlay \/system/p' /proc/mounts </dev/null |
    skip_administrative_mounts |
    grep -v ' \(erofs\|squashfs\|ext4\|f2fs\|vfat\) ' &&
    LOG WARNING "overlay takeover after first stage init" ||
    LOG OK "overlay takeover in first stage init"
fi

if ${enforcing}; then
  adb_unroot ||
    die "device not in unroot'd state"
  B="`adb_cat /vendor/hello 2>&1`"
  check_eq "cat: /vendor/hello: Permission denied" "${B}" vendor after reboot w/o root
  LOG OK "/vendor content correct MAC after reboot"
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
  LOG OK "${i} content remains after reboot"
done

check_eq "${SYSTEM_INO}" "`adb_sh stat --format=%i /system/hello </dev/null`" system inode after reboot
check_eq "${VENDOR_INO}" "`adb_sh stat --format=%i /vendor/hello </dev/null`" vendor inode after reboot

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
LOG OK "/system/lib/bootstrap/libc.so content remains after reboot"

LOG RUN "flash vendor, confirm its content disappears"

H=`adb_sh echo '${HOSTNAME}' </dev/null 2>/dev/null`
is_bootloader_fastboot=false
# cuttlefish?
[ X"${H}" != X"${H#vsoc}" ] || is_bootloader_fastboot=true
is_userspace_fastboot=false

if ! ${is_bootloader_fastboot}; then
  LOG WARNING "does not support fastboot, skipping"
elif [ -z "${ANDROID_PRODUCT_OUT}" ]; then
  LOG WARNING "build tree not setup, skipping"
elif [ ! -s "${ANDROID_PRODUCT_OUT}/vendor.img" ]; then
  LOG WARNING "vendor image missing, skipping"
elif [ "${ANDROID_PRODUCT_OUT}" = "${ANDROID_PRODUCT_OUT%*/${H}}" ]; then
  LOG WARNING "wrong vendor image, skipping"
elif [ -z "${ANDROID_HOST_OUT}" ]; then
  LOG WARNING "please run lunch, skipping"
elif ! (
          adb_cat /vendor/build.prop |
          cmp -s ${ANDROID_PRODUCT_OUT}/vendor/build.prop
       ) >/dev/null 2>/dev/null; then
  LOG WARNING "vendor image signature mismatch, skipping"
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
  if [ -n "${scratch_partition}" ]; then
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
      LOG INFO "expect fastboot erase ${scratch_partition} to fail"
      fastboot erase ${scratch_partition} &&
        ( fastboot reboot || true) &&
        die "fastboot can erase ${scratch_partition}"
    fi
    LOG INFO "expect fastboot format ${scratch_partition} to fail"
    fastboot format ${scratch_partition} &&
      ( fastboot reboot || true) &&
      die "fastboot can format ${scratch_partition}"
  fi
  fastboot reboot ||
    die "can not reboot out of fastboot"
  LOG WARNING "adb after fastboot"
  adb_wait ${ADB_WAIT} ||
    fixup_from_recovery ||
    die "did not reboot after formatting ${scratch_partition} `usb_status`"
  if ${overlayfs_needed}; then
    adb_root &&
      D=`adb_sh df -k </dev/null` &&
      H=`echo "${D}" | head -1` &&
      D=`echo "${D}" | skip_unrelated_mounts | grep "^overlay "` &&
      ( echo "${H}" &&
        echo "${D}"
      ) >&2 &&
      echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
      die  "overlay /system takeover after flash vendor"
    echo "${D}" | grep "^overlay .* /vendor\$" >/dev/null &&
      if ${is_userspace_fastboot}; then
        die  "overlay supposed to be minus /vendor takeover after flash vendor"
      else
        LOG WARNING "user fastboot missing required to invalidate, ignoring a failure"
        LOG WARNING "overlay supposed to be minus /vendor takeover after flash vendor"
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
    LOG WARNING "user fastboot missing required to invalidate, ignoring a failure"
    check_eq "cat: /vendor/hello: No such file or directory" "${B}" \
             --warning vendor content after flash vendor
  fi

  check_eq "${SYSTEM_INO}" "`adb_sh stat --format=%i /system/hello </dev/null`" system inode after reboot

fi

wait_for_screen
LOG RUN "remove test content (cleanup)"

T=`adb_date`
H=`adb remount 2>&1`
err=${?}
L=
D="${H%?Now reboot your device for settings to take effect*}"
if [ X"${H}" != X"${D}" ]; then
  LOG WARNING "adb remount requires a reboot after partial flash (legacy avb)"
  L=`adb_logcat -b all -v nsec -t ${T} 2>&1`
  adb_reboot &&
    adb_wait ${ADB_WAIT} &&
    adb_root ||
    die "failed to reboot"
  T=`adb_date`
  H=`adb remount 2>&1`
  err=${?}
fi
echo "${H}" >&2
[ ${err} = 0 ] &&
  ( adb_sh rm /vendor/hello </dev/null 2>/dev/null || true ) &&
  adb_sh rm /system/hello /system/priv-app/hello </dev/null ||
  ( [ -n "${L}" ] && echo "${L}" && false ) >&2 ||
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

  LOG RUN "test fastboot flash to ${scratch_partition} recovery"

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
    LOG WARNING "adb disable-verity requires a reboot after partial flash"
    adb_reboot &&
      adb_wait ${ADB_WAIT} &&
      adb_root ||
      die "failed to reboot"
    T=`adb_date`
    D="${D}
`adb disable-verity 2>&1`"
    err=${?}
  fi

  echo "${D}" >&2
  [ ${err} = 0 ] &&
    [ X"${D}" = X"${D##*setup failed}" ] &&
    [ X"${D}" != X"${D##*[Uu]sing overlayfs}" ] &&
    LOG OK "${scratch_partition} recreated" ||
    die -t ${T} "setup for overlayfs"
  D=`adb remount 2>&1`
  err=${?}
  echo "${D}" >&2
  [ ${err} != 0 ] ||
    [ X"${D}" = X"${D##*remount failed}" ] ||
    ( echo "${D}" && false ) >&2 ||
    die -t ${T} "remount failed"
fi

LOG RUN "test raw remount commands"

fixup_from_fastboot() {
  inFastboot || return 1
  if [ -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      LOG WARNING "Active slot changed from ${ACTIVE_SLOT} to ${active_slot}"
    else
      LOG WARNING "Active slot to be set to ${ACTIVE_SLOT}"
    fi
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
LOG OK "mount -o rw,remount command works"

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
LOG OK "remount command works from setup"

# Prerequisite is an overlayfs deconstructed device but with verity disabled.
# This also saves a lot of 'noise' from the command doing a mkfs on backing
# storage and all the related tuning and adjustment.
surgically_wipe_overlayfs || true
adb_reboot &&
  adb_wait ${ADB_WAIT} ||
  fixup_from_fastboot ||
  die "lost device after reboot after wipe `usb_status`"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/vendor is not read-only"
adb_su remount vendor </dev/null ||
  die "remount command"
adb_su df -k </dev/null | skip_unrelated_mounts >&2
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null ||
  die "/vendor is not read-write"
adb_sh grep " \(/system\|/\) .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/system is not read-only"
LOG OK "remount command works from scratch"

if ! restore; then
  restore() {
    true
  }
  die "failed to restore verity after remount from scratch test"
fi

err=0

if ${overlayfs_supported}; then
  LOG RUN "test 'adb remount -R'"
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

  LOG OK "'adb remount -R' command"

  restore
  err=${?}
fi

restore() {
  true
}

[ ${err} = 0 ] ||
  die "failed to restore verity"

LOG PASSED "adb remount test"

test_duration
