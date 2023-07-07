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
RED=
GREEN=
YELLOW=
BLUE=
NORMAL=
color=false
# Assume support color if stdout is terminal.
[ -t 1 ] && color=true
print_time=true
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
  if ${print_time}; then
    echo -n "$(date '+%m-%d %T') "
  fi >&2
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
  if ! ${overlayfs_needed:-false}; then
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
  adb_wait "${ADB_WAIT}"
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

Do nothing: should be redefined when necessary.

Returns: reverses configurations" ]
restore() {
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
  exit 1
}

[ "USAGE: check_eq <lval> <rval> [--warning [message]]

Exits if (regex) lval mismatches rval.

Returns: true if lval matches rval" ]
check_eq() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  if [[ "${rval}" =~ ^${lval}$ ]]; then
    return 0
  fi

  local error=true
  local logt=ERROR
  if [ X"${1}" = X"--warning" ]; then
    shift 1
    error=false
    logt=WARNING
  fi
  if [ $(( ${#lval} + ${#rval} )) -gt 40 ]; then
    LOG "${logt}" "expected \"${lval}\"
${INDENT}got      \"${rval}\""
  else
    LOG "${logt}" "expected \"${lval}\" got \"${rval}\""
  fi
  ${error} && die "${*}"
  [ -n "${*}" ] && LOG "${logt}" "${*}"
  return 1
}

[ "USAGE: check_ne <lval> <rval> [--warning [message]]

Exits if (regex) lval matches rval.

Returns: true if lval mismatches rval" ]
check_ne() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  if ! [[ "${rval}" =~ ^${lval}$ ]]; then
    return 0
  fi

  local error=true
  local logt=ERROR
  if [ X"${1}" = X"--warning" ]; then
      shift 1
      error=false
      logt=WARNING
  fi
  LOG "${logt}" "unexpected \"${rval}\""
  ${error} && die "${*}"
  [ -n "${*}" ] && LOG "${logt}" "${*}"
  return 1
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

[ "USAGE: skip_administrative_mounts < /proc/mounts

Filters out all administrative (eg: sysfs) mounts uninteresting to the test" ]
skip_administrative_mounts() {
  local exclude_filesystems=(
    "overlay" "tmpfs" "none" "sysfs" "proc" "selinuxfs" "debugfs" "bpf"
    "binfmt_misc" "cg2_bpf" "pstore" "tracefs" "adb" "mtp" "ptp" "devpts"
    "ramdumpfs" "binder" "securityfs" "functionfs" "rootfs" "fuse"
  )
  local exclude_devices=(
    "\/sys\/kernel\/debug" "\/data\/media" "\/dev\/block\/loop[0-9]*"
    "\/dev\/block\/vold\/[^ ]+"
    "${exclude_filesystems[@]}"
  )
  local exclude_mount_points=(
    "\/cache" "\/mnt\/scratch" "\/mnt\/vendor\/persist" "\/persist"
    "\/metadata" "\/apex\/[^ ]+"
  )
  awk '$1 !~ /^('"$(join_with "|" "${exclude_devices[@]}")"')$/ &&
      $2 !~ /^('"$(join_with "|" "${exclude_mount_points[@]}")"')$/ &&
      $3 !~ /^('"$(join_with "|" "${exclude_filesystems[@]}")"')$/'
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

[ "USAGE: is_overlayfs_mounted [mountpoint]

Diagnostic output of overlayfs df lines to stderr.

Returns: true if overlayfs is mounted [on mountpoint]" ]
is_overlayfs_mounted() {
  local df_output=$(adb_su df -k </dev/null)
  local df_header_line=$(echo "${df_output}" | head -1)
  # KISS (we do not support sub-mounts for system partitions currently)
  local overlay_mounts=$(echo "${df_output}" | tail +2 |
                         grep -vE "[%] /(apex|system|vendor)/[^ ]+$" |
                         awk '$1 == "overlay" || $6 == "/mnt/scratch"')
  if ! echo "${overlay_mounts}" | grep -q '^overlay '; then
    return 1
  fi >/dev/null 2>/dev/null
  ( echo "${df_header_line}"
    echo "${overlay_mounts}"
  ) >&2
  if [ "${#}" -gt 0 ] && ! ( echo "${overlay_mounts}" | grep -qE " ${1}\$" ); then
    return 1
  fi >/dev/null 2>/dev/null
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
         --longoptions gtest_print_time,print-time,no-print-time
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
OPTIONS=`getopt ${GETOPTS} "?a:cCdDf:hs:tT" ${*}` ||
  ( echo "${USAGE}" >&2 ; false ) ||
  die "getopt failure"
set -- ${OPTIONS}

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
    -T | --no-print-time)
      print_time=false
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

if ${color}; then
  RED="${ESCAPE}[31m"
  GREEN="${ESCAPE}[32m"
  YELLOW="${ESCAPE}[33m"
  BLUE="${ESCAPE}[34m"
  NORMAL="${ESCAPE}[0m"
fi

TMPDIR=

exit_handler() {
  [ -n "${TMPDIR}" ] && rm -rf "${TMPDIR}"
  local err=0
  if ! restore; then
    LOG ERROR "restore failed"
    err=1
  fi >&2
  test_duration || true
  if [ "${err}" != 0 ]; then
    exit "${err}"
  fi
}
trap 'exit_handler' EXIT

TMPDIR=$(mktemp -d)

if ${print_time}; then
  LOG INFO "start $(date)"
fi

if [ -z "${ANDROID_SERIAL}" ]; then
  inAdb || die "no device or more than one device in adb mode"
  D=$(adb devices | awk '$2 == "device" { print $1; exit }')
  [ -n "${D}" ] || die "cannot get device serial"
  ANDROID_SERIAL="${D}"
fi
export ANDROID_SERIAL

inFastboot && die "device in fastboot mode"
inRecovery && die "device in recovery mode"
if ! inAdb; then
  LOG WARNING "device not in adb mode"
  adb_wait ${ADB_WAIT}
fi
inAdb || die "specified device not in adb mode"
[ "1" = "$(get_property ro.debuggable)" ] || die "device not a debug build"
[ "orange" = "$(get_property ro.boot.verifiedbootstate)" ] || die "device not bootloader unlocked"

################################################################################
# Collect characteristics of the device and report.
can_restore_verity=true
if [ "2" != "$(get_property partition.system.verified)" ]; then
  LOG WARNING "device might not support verity"
  can_restore_verity=false
fi
enforcing=true
if ! adb_su getenforce </dev/null | grep 'Enforcing' >/dev/null; then
  LOG WARNING "device does not have sepolicy in enforcing mode"
  enforcing=false
fi

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
USB_DEVICE=$(usb_devnum)
[ -z "${ANDROID_SERIAL}${USB_ADDRESS}${USB_DEVICE}" ] ||
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
FSTAB_SUFFIXES=(
  "$(get_property ro.boot.fstab_suffix)"
  "$(get_property ro.boot.hardware)"
  "$(get_property ro.boot.hardware.platform)"
)
FSTAB_PATTERN='\.('"$(join_with "|" "${FSTAB_SUFFIXES[@]}")"')$'
FSTAB_FILE=$(adb_su ls -1 '/vendor/etc/fstab*' </dev/null |
             grep -E "${FSTAB_PATTERN}" |
             head -1)

# KISS (assume system partition mount point is "/<partition name>")
if [ -n "${FSTAB_FILE}" ]; then
  PARTITIONS=$(adb_su grep -v "^[#${SPACE}${TAB}]" "${FSTAB_FILE}" |
               skip_administrative_mounts |
               awk '$1 ~ /^[^\/]+$/ && "/"$1 == $2 && $4 ~ /(^|,)ro(,|$)/ { print $1 }' |
               sort -u |
               tr '\n' ' ')
else
  PARTITIONS="system vendor"
fi

# KISS (we do not support sub-mounts for system partitions currently)
# Ensure /system and /vendor mountpoints are in mounts list
MOUNTS=$(for i in system vendor ${PARTITIONS}; do
           echo "/${i}"
         done | sort -u | tr '\n' ' ')
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

restore() {
  LOG INFO "restoring device"
  inFastboot &&
    fastboot reboot &&
    adb_wait "${ADB_WAIT}" ||
    true
  if ! inAdb; then
    LOG ERROR "expect adb device"
    return 1
  fi
  adb_root || true
  local reboot=false
  if surgically_wipe_overlayfs; then
    reboot=true
  fi
  if ${can_restore_verity}; then
    if ! adb enable-verity; then
      LOG ERROR "adb enable-verity"
      return 1
    fi
    LOG INFO "restored verity"
    reboot=true
  fi >&2
  if ${reboot}; then
    adb_reboot
  fi
}

# If reboot too soon after fresh flash, could trip device update failure logic
if ${screen_wait}; then
  LOG INFO "waiting for screen to come up. Consider --no-wait-screen option"
fi
if ! wait_for_screen && ${screen_wait}; then
  screen_wait=false
  LOG WARNING "not healthy, no launcher, skipping wait for screen"
fi

################################################################################
LOG RUN "Checking current overlayfs status"

adb_wait || die "wait for device failed"
adb_root || die "adb root failed"

# We can not universally use adb enable-verity to ensure device is
# in a overlayfs disabled state since it can prevent reboot on
# devices that remount the physical content rather than overlayfs.
# So lets do our best to surgically wipe the overlayfs state without
# having to go through enable-verity transition.
if surgically_wipe_overlayfs; then
  LOG WARNING "rebooting before test"
  adb_reboot ||
    die "lost device after reboot after overlay wipe $(usb_status)"
  adb_root ||
    die "lost device after elevation to root after wipe `usb_status`"
fi
is_overlayfs_mounted &&
  die "overlay takeover unexpected at this phase"

overlayfs_needed=true
data_device=$(adb_sh awk '$2 == "/data" { print $1; exit }' /proc/mounts)
D=$(adb_sh grep " ro," /proc/mounts </dev/null |
    grep -v "^${data_device}" |
    skip_administrative_mounts |
    awk '{ print $1 }' |
    sed 's|/dev/root|/|' |
    sort -u)
no_dedupe=true
for d in ${D}; do
  adb_sh tune2fs -l $d </dev/null 2>&1 |
    grep "Filesystem features:.*shared_blocks" >/dev/null &&
  no_dedupe=false
done
D=$(adb_sh df -k ${D} </dev/null)
echo "${D}" >&2
if [ X"${D}" = X"${D##* 100[%] }" ] && ${no_dedupe} ; then
  overlayfs_needed=false
  # if device does not need overlays, then adb enable-verity will brick device
  can_restore_verity=false
fi
LOG OK "no overlay present before setup"

################################################################################
# Precondition is overlayfs *not* setup.
LOG RUN "Testing adb disable-verity -R"

T=$(adb_date)
adb_su disable-verity -R >&2 ||
  die -t "${T}" "disable-verity -R failed"
sleep 2
adb_wait "${ADB_WAIT}" ||
  die "lost device after adb disable-verity -R $(usb_status)"

if [ "2" = "$(get_property partition.system.verified)" ]; then
  LOG ERROR "partition.system.verified=$(get_property partition.system.verified)"
  die "verity not disabled after adb disable-verity -R"
fi
if ${overlayfs_needed}; then
  is_overlayfs_mounted ||
    die -d "no overlay takeover after adb disable-verity -R"
  LOG OK "overlay takeover after adb disable-verity -R"
fi
LOG OK "adb disable-verity -R"

################################################################################
LOG RUN "Checking kernel has overlayfs required patches"

adb_root || die "adb root"
if adb_test -d /sys/module/overlay ||
    adb_sh grep -q "nodev${TAB}overlay" /proc/filesystems; then
  LOG OK "overlay module present"
else
  LOG INFO "overlay module not present"
fi
if is_overlayfs_mounted 2>/dev/null; then
  if adb_test -f /sys/module/overlay/parameters/override_creds; then
    LOG OK "overlay module supports override_creds"
  else
    case "$(adb_sh uname -r </dev/null)" in
      4.[456789].* | 4.[1-9][0-9]* | [56789].*)
        die "overlay module does not support override_creds"
        ;;
      *)
        LOG OK "overlay module uses caller's creds"
        ;;
    esac
  fi
fi

################################################################################
# Precondition is a verity-disabled device with overlayfs already setup.
LOG RUN "Testing raw remount commands"

adb_sh grep -qE " (/system|/) [^ ]* rw," /proc/mounts </dev/null &&
  die "/system is not RO"
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null &&
  die "/vendor is not RO"

T=$(adb_date)
adb_su mount -o remount,rw /vendor ||
  die -t "${T}" "mount -o remount,rw /vendor"
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null ||
  die "/vendor is not RW after mount -o remount,rw"
LOG OK "mount -o remount,rw"

T=$(adb_date)
adb_su mount -o remount,ro /vendor ||
  die -t "${T}" "mount -o remount,ro /vendor"
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null &&
  die "/vendor is not RO after mount -o remount,ro"
LOG OK "mount -o remount,ro"

T=$(adb_date)
adb_su remount vendor >&2 ||
  die -t "${T}" "adb remount vendor"
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null ||
  die -t "${T}" "/vendor is not RW after adb remount vendor"
adb_sh grep -qE " (/system|/) [^ ]* rw," /proc/mounts </dev/null &&
  die -t "${T}" "/system is not RO after adb remount vendor"
LOG OK "adb remount vendor"

LOG INFO "Restoring device RO state and destroying overlayfs"
T=$(adb_date)
adb_su mount -o remount,ro /vendor ||
  die -t "${T}" "mount -o remount,ro /vendor"
if surgically_wipe_overlayfs; then
  adb_reboot ||
    die "lost device after reboot after overlay wipe $(usb_status)"
fi
is_overlayfs_mounted &&
  die "overlay takeover unexpected at this phase"

################################################################################
# Precondition is a verity-disabled device with overlayfs *not* setup.
LOG RUN "Testing adb remount performs overlayfs setup from scratch"

adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null &&
  die "/vendor is not RO"
T=$(adb_date)
adb_su remount vendor >&2 ||
  die -t "${T}" "adb remount vendor from scratch"
if ${overlayfs_needed}; then
  is_overlayfs_mounted /vendor ||
    die -t "${T}" "expected overlay takeover /vendor"
  is_overlayfs_mounted /system 2>/dev/null &&
    die -t "${T}" "unexpected overlay takeover /system"
fi
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null ||
  die -t "${T}" "/vendor is not RW after adb remount vendor"
adb_sh grep -qE " (/system|/) [^ ]* rw," /proc/mounts </dev/null &&
  die -t "${T}" "/system is not RO after adb remount vendor"
LOG OK "adb remount from scratch"

################################################################################
# Precondition is overlayfs partially setup by previous test.
LOG RUN "Testing adb remount -R"

T=$(adb_date)
adb_su remount -R </dev/null >&2 ||
  die -t "${T}" "adb remount -R failed"
sleep 2
adb_wait "${ADB_WAIT}" ||
  die "lost device after adb remount -R $(usb_status)"

if [ "2" = "$(get_property partition.system.verified)" ]; then
  LOG ERROR "partition.system.verified=$(get_property partition.system.verified)"
  die "verity not disabled after adb remount -R"
fi
if ${overlayfs_needed}; then
  is_overlayfs_mounted /system ||
    die -d "expected overlay takeover /system"
  is_overlayfs_mounted /vendor 2>/dev/null ||
    die -d "expected overlay takeover /vendor"
  LOG OK "overlay takeover after adb remount -R"
fi
LOG OK "adb remount -R"

# For devices using overlayfs, remount -R should reboot after overlayfs setup.
# For legacy device, manual reboot to ensure device clean state.
if ! ${overlayfs_needed}; then
  LOG WARNING "Reboot to RO (device doesn't use overlayfs)"
  adb_reboot ||
    die "lost device after reboot to RO $(usb_status)"
fi

################################################################################
# Precondition is a verity-disabled device with overlayfs already setup.
LOG RUN "Testing adb remount RW"

# Feed log with selinux denials as baseline before overlays
adb_unroot
adb_sh find ${MOUNTS} </dev/null >/dev/null 2>/dev/null || true
adb_root

adb_sh grep -qE " (/system|/) [^ ]* rw," /proc/mounts </dev/null &&
  die "/system is not RO"
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null &&
  die "/vendor is not RO"

T=$(adb_date)
adb remount >&2 ||
  die -t "${T}" "adb remount"
adb_sh grep -qE " (/system|/) [^ ]* rw," /proc/mounts </dev/null ||
  die -t "${T}" "/system is not RW"
adb_sh grep -q " /vendor [^ ]* rw," /proc/mounts </dev/null ||
  die -t "${T}" "/vendor is not RW"

scratch_on_super=false
if ${overlayfs_needed}; then
  is_overlayfs_mounted /system ||
    die -t "${T}" "expected overlay to takeover /system after remount"

  # Collect information about the scratch device if we have one
  M=$(adb_sh cat /proc/mounts </dev/null |
      awk '$2 == "/mnt/scratch" { print $1, $3; exit }')
  if [ -n "${M}" ]; then
    scratch_device=$(echo "${M}" | awk '{ print $1 }')
    scratch_filesystem=$(echo "${M}" | awk '{ print $2 }')
    scratch_size=$(adb_sh df -k "${scratch_device}" </dev/null |
                  tail +2 | head -1 | awk '{ print $2 }')
    [ -z "${scratch_size}" ] && die "cannot get size of scratch device (${scratch_device})"

    # Detect scratch partition backed by super?
    for b in "/dev/block/by-name/super"{,_${ACTIVE_SLOT}}; do
      if adb_test -e "${b}"; then
        device=$(adb_su realpath "${b}")
        D=$(adb_su stat -c '0x%t 0x%T' "${device}")
        major=$(echo "${D}" | awk '{ print $1 }')
        minor=$(echo "${D}" | awk '{ print $2 }')
        super_devt=$(( major )):$(( minor ))
        if adb_su dmctl table scratch | tail +2 | grep -q -w "${super_devt}"; then
          scratch_on_super=true
        fi
        break
      fi
    done

    if ${scratch_on_super}; then
      LOG INFO "using dynamic scratch partition on super"
    else
      LOG INFO "using dynamic scratch partition on /data (VAB device)"
    fi
    LOG INFO "scratch device ${scratch_device} filesystem ${scratch_filesystem} size ${scratch_size}KiB"
  else
    LOG INFO "cannot find any scratch device mounted on /mnt/scratch, using scratch on /cache"
  fi

  for d in ${OVERLAYFS_BACKING}; do
    if adb_test -d /${d}/overlay/system/upper; then
      LOG INFO "/${d}/overlay is setup"
    fi
  done

  data_device=$(adb_sh awk '$2 == "/data" { print $1; exit }' /proc/mounts)
  # KISS (we do not support sub-mounts for system partitions currently)
  adb_sh grep "^overlay " /proc/mounts </dev/null |
    grep -vE "^overlay.* /(apex|system|vendor)/[^ ]" |
    grep " overlay ro," &&
    die "expected overlay to be RW after remount"
  adb_sh grep -v noatime /proc/mounts </dev/null |
    grep -v "^${data_device}" |
    skip_administrative_mounts |
    grep -v ' ro,' &&
    die "mounts are not noatime"

  D=$(adb_sh grep " rw," /proc/mounts </dev/null |
      grep -v "^${data_device}" |
      skip_administrative_mounts |
      awk '{ print $1 }' |
      sed 's|/dev/root|/|' |
      sort -u)
  if [ -n "${D}" ]; then
    adb_sh df -k ${D} </dev/null |
      sed -e 's/^Filesystem      /Filesystem (rw) /'
  fi >&2
  for d in ${D}; do
    if adb_sh tune2fs -l "${d}" </dev/null 2>&1 | grep -q "Filesystem features:.*shared_blocks" ||
        adb_sh df -k "${d}" | grep -q " 100% "; then
      die "remount overlayfs missed a spot (rw)"
    fi
  done
else
  is_overlayfs_mounted && die -t "${T}" "unexpected overlay takeover"
fi

LOG OK "adb remount RW"

################################################################################
LOG RUN "push content to ${MOUNTS}"

adb_root || die "adb root"
A="Hello World! $(date)"
for i in ${MOUNTS} /system/priv-app; do
  echo "${A}" | adb_sh cat - ">${i}/hello"
  B="`adb_cat ${i}/hello`" ||
    die "${i#/} hello"
  check_eq "${A}" "${B}" ${i} before reboot
done
SYSTEM_INO=`adb_sh stat --format=%i /system/hello </dev/null`
VENDOR_INO=`adb_sh stat --format=%i /vendor/hello </dev/null`
check_ne "${SYSTEM_INO}" "${VENDOR_INO}" vendor and system inode

# Edit build.prop and check if properties are updated.
system_build_prop_original="${TMPDIR}/system_build.prop.original"
system_build_prop_modified="${TMPDIR}/system_build.prop.modified"
system_build_prop_fromdevice="${TMPDIR}/system_build.prop.fromdevice"
adb pull /system/build.prop "${system_build_prop_original}" >/dev/null ||
  die "adb pull /system/build.prop"
# Prepend with extra newline in case the original file doesn't end with a newline.
cat "${system_build_prop_original}" - <<EOF >"${system_build_prop_modified}"

# Properties added by adb remount test
test.adb.remount.system.build.prop=true
EOF
adb push "${system_build_prop_modified}" /system/build.prop >/dev/null ||
  die "adb push /system/build.prop"
adb pull /system/build.prop "${system_build_prop_fromdevice}" >/dev/null ||
  die "adb pull /system/build.prop"
diff "${system_build_prop_modified}" "${system_build_prop_fromdevice}" >/dev/null ||
  die "/system/build.prop differs from pushed content"

################################################################################
LOG RUN "reboot to confirm content persistent"

fixup_from_recovery() {
  inRecovery || return 1
  LOG ERROR "Device in recovery"
  adb reboot </dev/null
  adb_wait ${ADB_WAIT}
}

adb_reboot ||
  fixup_from_recovery ||
  die "reboot after override content added failed `usb_status`"

if ${overlayfs_needed}; then
  is_overlayfs_mounted ||
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
adb_sh ls /system >/dev/null || die "ls /system"
adb_test -d /system/priv-app || die "[ -d /system/priv-app ]"
B="`adb_cat /system/priv-app/hello`"
check_eq "${A}" "${B}" /system/priv-app after reboot

# Only root can read vendor if sepolicy permissions are as expected.
adb_root || die "adb root"
for i in ${MOUNTS}; do
  B="`adb_cat ${i}/hello`"
  check_eq "${A}" "${B}" ${i#/} after reboot
  LOG OK "${i} content remains after reboot"
done

check_eq "${SYSTEM_INO}" "`adb_sh stat --format=%i /system/hello </dev/null`" system inode after reboot
check_eq "${VENDOR_INO}" "`adb_sh stat --format=%i /vendor/hello </dev/null`" vendor inode after reboot

# Feed log with selinux denials as a result of overlays
adb_sh find ${MOUNTS} </dev/null >/dev/null 2>/dev/null || true

# Check if the updated build.prop is persistent after reboot.
check_eq "true" "$(get_property 'test.adb.remount.system.build.prop')" "load modified build.prop"
adb pull /system/build.prop "${system_build_prop_fromdevice}" >/dev/null ||
  die "adb pull /system/build.prop"
diff "${system_build_prop_modified}" "${system_build_prop_fromdevice}" >/dev/null ||
  die "/system/build.prop differs from pushed content"
LOG OK "/system/build.prop content remains after reboot"

################################################################################
LOG RUN "flash vendor, and confirm vendor override disappears"

is_bootloader_fastboot=true
# virtual device?
case "$(get_property ro.product.vendor.device)" in
  vsoc_* | emulator_* | emulator64_*)
    is_bootloader_fastboot=false
    ;;
esac
is_userspace_fastboot=false

if ! ${is_bootloader_fastboot}; then
  LOG WARNING "does not support fastboot flash, skipping"
else
  wait_for_screen
  adb_root || die "adb root"

  VENDOR_DEVICE_CANDIDATES=(
    "/dev/block/mapper/vendor"{_${ACTIVE_SLOT},}
    "/dev/block/by-name/vendor"{_${ACTIVE_SLOT},}
  )
  for b in "${VENDOR_DEVICE_CANDIDATES[@]}"; do
    if adb_test -e "${b}"; then
      adb pull "${b}" "${TMPDIR}/vendor.img" || die "adb pull ${b}"
      LOG INFO "pulled ${b} from device as vendor.img"
      break
    fi
  done
  [ -f "${TMPDIR}/vendor.img" ] ||
    die "cannot find block device of vendor partition"

  avc_check
  adb reboot fastboot </dev/null ||
    die "fastbootd not supported (wrong adb in path?)"
  any_wait ${ADB_WAIT} &&
    inFastboot ||
    die "reboot into fastboot to flash vendor `usb_status` (bad bootloader?)"
  fastboot flash vendor "${TMPDIR}/vendor.img" ||
    ( fastboot reboot && false) ||
    die "fastboot flash vendor"
  LOG OK "flashed vendor"

  fastboot_getvar is-userspace yes &&
    is_userspace_fastboot=true

  if ${scratch_on_super}; then
    fastboot_getvar partition-type:scratch raw ||
      die "fastboot cannot see parameter partition-type:scratch"
    fastboot_getvar has-slot:scratch no ||
      die "fastboot cannot see parameter has-slot:scratch"
    fastboot_getvar is-logical:scratch yes ||
      die "fastboot cannot see parameter is-logical:scratch"
    LOG INFO "expect fastboot erase scratch to fail"
    fastboot erase scratch && die "fastboot can erase scratch"
    LOG INFO "expect fastboot format scratch to fail"
    fastboot format scratch && die "fastboot can format scratch"
  fi

  fastboot reboot || die "cannot reboot out of fastboot"
  LOG INFO "reboot from fastboot"
  adb_wait ${ADB_WAIT} ||
    fixup_from_recovery ||
    die "cannot reboot after flash vendor $(usb_status)"
  if ${overlayfs_needed}; then
    is_overlayfs_mounted /system ||
      die  "overlay /system takeover after flash vendor"
    if is_overlayfs_mounted /vendor 2>/dev/null; then
      if ${is_userspace_fastboot}; then
        die  "overlay supposed to be minus /vendor takeover after flash vendor"
      else
        LOG WARNING "fastbootd missing required to invalidate, ignoring a failure"
        LOG WARNING "overlay supposed to be minus /vendor takeover after flash vendor"
      fi
    fi
  fi
  check_eq "${A}" "$(adb_cat /system/hello)" "/system content after flash vendor"
  check_eq "${SYSTEM_INO}" "$(adb_sh stat --format=%i /system/hello </dev/null)" "system inode after flash vendor"
  adb_sh ls /system >/dev/null || die "ls /system"
  adb_test -d /system/priv-app || die "[ -d /system/priv-app ]"
  check_eq "${A}" "$(adb_cat /system/priv-app/hello)" "/system/priv-app content after flash vendor"
  adb_root || die "adb root"
  if adb_test -e /vendor/hello; then
    if ${is_userspace_fastboot} || ! ${overlayfs_needed}; then
      die "vendor content after flash vendor"
    else
      LOG WARNING "fastbootd missing required to invalidate, ignoring a failure"
      LOG WARNING "vendor content after flash vendor"
    fi
  fi
  LOG OK "vendor override destroyed after flash verdor"
fi >&2

wait_for_screen

################################################################################
LOG RUN "Clean up test content"

adb_root || die "adb root"
T=$(adb_date)
D=$(adb remount 2>&1) ||
  die -t "${T}" "adb remount"
echo "${D}" >&2
if [[ "${D}" =~ [Rr]eboot ]]; then
  LOG OK "adb remount calls for a reboot after partial flash"
  # but we don't really want to, since rebooting just recreates the already tore
  # down vendor overlay.
fi

for i in ${MOUNTS} /system/priv-app; do
  adb_sh rm "${i}/hello" 2>/dev/null || true
  adb_test -e "${i}/hello" &&
    die -t "${T}" "/${i}/hello lingers after rm"
done

################################################################################
if ${is_bootloader_fastboot} && ${scratch_on_super}; then

  LOG RUN "test fastboot flash to scratch recovery"

  avc_check
  adb reboot fastboot </dev/null ||
    die "Reboot into fastbootd"
  img="${TMPDIR}/adb-remount-test-${$}.img"
  dd if=/dev/zero of=${img} bs=4096 count=16 2>/dev/null &&
    fastboot_wait ${FASTBOOT_WAIT} ||
    die "reboot into fastboot to flash scratch `usb_status`"
  fastboot flash --force scratch ${img}
  err=${?}
  fastboot reboot ||
    die "can not reboot out of fastboot"
  [ 0 -eq ${err} ] ||
    die "fastboot flash scratch"
  adb_wait ${ADB_WAIT} &&
    adb_root ||
    die "did not reboot after flashing empty scratch $(usb_status)"
  T=`adb_date`
  D=`adb disable-verity 2>&1`
  err=${?}
  if [ X"${D}" != "${D%?Now reboot your device for settings to take effect*}" ]
  then
    LOG WARNING "adb disable-verity requires a reboot after partial flash"
    adb_reboot &&
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
    LOG OK "recreated scratch" ||
    die -t ${T} "setup for overlayfs"
  adb remount >&2 ||
    die -t ${T} "remount failed"
fi


LOG PASSED "adb remount test"
