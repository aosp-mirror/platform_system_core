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

--help        This help
--serial      Specify device (must if multiple are present)
--color       Dress output with highlighting colors
--print-time  Report the test duration

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

SPACE=" "
# A _real_ embedded tab character
TAB="`echo | tr '\n' '\t'`"
# A _real_ embedded escape character
ESCAPE="`echo | tr '\n' '\033'`"
# A _real_ embedded carriage return character
CR="`echo | tr '\n' '\r'`"
GREEN="${ESCAPE}[38;5;40m"
RED="${ESCAPE}[38;5;196m"
ORANGE="${ESCAPE}[38;5;255:165:0m"
BLUE="${ESCAPE}[35m"
NORMAL="${ESCAPE}[0m"
TMPDIR=${TMPDIR:-/tmp}
print_time=false
start_time=`date +%s`
ACTIVE_SLOT=

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
      wc -l | grep '^1$' >/dev/null
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
      wc -l | grep '^1$' >/dev/null
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
  if echo "${list}" | wc -l | grep '^1$' >/dev/null; then
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
    grep -v 'logd    : logdr: UID=' |
    sed -e '${/------- beginning of kernel/d}' -e 's/^[0-1][0-9]-[0-3][0-9] //'
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
         true of the file exists" ]
adb_cat() {
    local OUTPUT="`adb_sh cat ${1} </dev/null 2>&1`"
    local ret=${?}
    echo "${OUTPUT}" | tr -d '\r'
    return ${ret}
}

[ "USAGE: adb_reboot

Returns: true if the reboot command succeeded" ]
adb_reboot() {
  adb reboot remount-test || true
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

[ "USAGE: adb_wait [timeout]

Returns: waits until the device has returned for adb or optional timeout" ]
adb_wait() {
  local ret
  if [ -n "${1}" ]; then
    echo -n ". . . waiting `format_duration ${1}`" ${ANDROID_SERIAL} ${USB_ADDRESS} "${CR}"
    timeout --preserve-status --signal=KILL ${1} adb wait-for-device 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}"
  else
    adb wait-for-device
    ret=${?}
  fi
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${ORANGE}[  WARNING ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}" >&2
    fi
  fi
  return ${ret}
}

[ "USAGE: usb_status > stdout

If adb_wait failed, check if device is in adb, recovery or fastboot mode
and report status string.

Returns: \"(USB stack borken?)\", \"(In fastboot mode)\" or \"(in adb mode)\"" ]
usb_status() {
  if inFastboot; then
    echo "(In fastboot mode)"
  elif inRecovery; then
    echo "(In recovery mode)"
  elif inAdb; then
    echo "(In adb mode)"
  else
    echo "(USB stack borken?)"
  fi
}

[ "USAGE: fastboot_wait [timeout]

Returns: waits until the device has returned for fastboot or optional timeout" ]
fastboot_wait() {
  local ret
  # fastboot has no wait-for-device, but it does an automatic
  # wait and requires (even a nonsensical) command to do so.
  if [ -n "${1}" ]; then
    echo -n ". . . waiting `format_duration ${1}`" ${ANDROID_SERIAL} ${USB_ADDRESS} "${CR}"
    timeout --preserve-status --signal=KILL ${1} fastboot wait-for-device >/dev/null 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}"
    ( exit ${ret} )
  else
    fastboot wait-for-device >/dev/null 2>/dev/null
  fi ||
    inFastboot
  ret=${?}
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${ORANGE}[  WARNING ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}" >&2
    fi
  fi
  return ${ret}
}

[ "USAGE: recovery_wait [timeout]

Returns: waits until the device has returned for recovery or optional timeout" ]
recovery_wait() {
  local ret
  if [ -n "${1}" ]; then
    echo -n ". . . waiting `format_duration ${1}`" ${ANDROID_SERIAL} ${USB_ADDRESS} "${CR}"
    timeout --preserve-status --signal=KILL ${1} adb wait-for-recovery 2>/dev/null
    ret=${?}
    echo -n "                                                                             ${CR}"
  else
    adb wait-for-recovery
    ret=${?}
  fi
  if [ 0 = ${ret} -a -n "${ACTIVE_SLOT}" ]; then
    local active_slot=`get_active_slot`
    if [ X"${ACTIVE_SLOT}" != X"${active_slot}" ]; then
      echo "${ORANGE}[  WARNING ]${NORMAL} Active slot changed from ${ACTIVE_SLOT} to ${active_slot}" >&2
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

[ "USAGE: adb_root

NB: This can be flakey on devices due to USB state

Returns: true if device in root state" ]
adb_root() {
  [ root != "`adb_sh echo '${USER}' </dev/null`" ] || return 0
  adb root >/dev/null </dev/null 2>/dev/null
  sleep 2
  adb_wait 2m &&
    [ root = "`adb_sh echo '${USER}' </dev/null`" ]
}

[ "USAGE: adb_unroot

NB: This can be flakey on devices due to USB state

Returns: true if device in un root state" ]
adb_unroot() {
  [ root = "`adb_sh echo '${USER}' </dev/null`" ] || return 0
  adb unroot >/dev/null </dev/null 2>/dev/null
  sleep 2
  adb_wait 2m &&
    [ root != "`adb_sh echo '${USER}' </dev/null`" ]
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
    echo "${2} != ${O}" >&2
    false
    return
  fi
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
    adb_logcat -b all -v nsec -d >&2
    shift
  elif [ X"-t" = X"${1}" ]; then
    if [ -n "${2}" ]; then
      adb_logcat -b all -v nsec -t ${2} >&2
    else
      adb_logcat -b all -v nsec -d >&2
    fi
    shift 2
  fi
  echo "${RED}[  FAILED  ]${NORMAL} ${@}" >&2
  cleanup
  restore
  test_duration
  exit 1
}

[ "USAGE: EXPECT_EQ <lval> <rval> [message]

Returns true if (regex) lval matches rval" ]
EXPECT_EQ() {
  local lval="${1}"
  local rval="${2}"
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
      if [ `echo ${lval}${rval}${*} | wc -c` -gt 60 -o "${rval}" != "${rval% *}" ]; then
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

[ "USAGE: check_eq <lval> <rval> [message]

Exits if (regex) lval mismatches rval" ]
check_eq() {
  local lval="${1}"
  local rval="${2}"
  shift 2
  EXPECT_EQ "${lval}" "${rval}" ||
    die "${@}"
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
    -e "^\(overlay\|tmpfs\|none\|sysfs\|proc\|selinuxfs\|debugfs\) " \
    -e "^\(bpf\|cg2_bpf\|pstore\|tracefs\|adb\|mtp\|ptp\|devpts\) " \
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
      grep -v "[%] /\(apex\|bionic\|system\|vendor\)/[^ ][^ ]*$"
}

##
##  MAINLINE
##

OPTIONS=`getopt --alternative --unquoted \
                --longoptions help,serial:,colour,color,no-colour,no-color \
                --longoptions gtest_print_time,print-time \
                -- "?hs:" ${*}` ||
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
    --color | --colour)
      color=true
      ;;
    --no-color | --no-colour)
      color=false
      ;;
    --print-time | --gtest_print_time)
      print_time=true
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
  ORANGE=""
  BLUE=""
  NORMAL=""
fi

if ${print_time}; then
  echo "${BLUE}[     INFO ]${NORMAL}" start `date` >&2
fi

inFastboot && die "device in fastboot mode"
inRecovery && die "device in recovery mode"
if ! inAdb; then
  echo "${ORANGE}[  WARNING ]${NORMAL} device not in adb mode" >&2
  adb_wait 2m
fi
inAdb || die "specified device not in adb mode"
isDebuggable || die "device not a debug build"
enforcing=true
if ! adb_su getenforce </dev/null | grep 'Enforcing' >/dev/null; then
  echo "${ORANGE}[  WARNING ]${NORMAL} device does not have sepolicy in enforcing mode" >&2
  enforcing=false
fi

# Do something.

D=`get_property ro.serialno`
[ -n "${D}" ] || D=`get_property ro.boot.serialno`
[ -z "${D}" ] || ANDROID_SERIAL=${D}
USB_SERIAL=
[ -z "${ANDROID_SERIAL}" ] || USB_SERIAL=`find /sys/devices -name serial |
                                          grep usb |
                                          xargs grep -l ${ANDROID_SERIAL}`
USB_ADDRESS=
if [ -n "${USB_SERIAL}" ]; then
  USB_ADDRESS=${USB_SERIAL%/serial}
  USB_ADDRESS=usb${USB_ADDRESS##*/}
fi
[ -z "${ANDROID_SERIAL}${USB_ADDRESS}" ] ||
  echo "${BLUE}[     INFO ]${NORMAL}" ${ANDROID_SERIAL} ${USB_ADDRESS} >&2
BUILD_DESCRIPTION=`get_property ro.build.description`
[ -z "${BUILD_DESCRIPTION}" ] ||
  echo "${BLUE}[     INFO ]${NORMAL} ${BUILD_DESCRIPTION}" >&2
ACTIVE_SLOT=`get_active_slot`
[ -z "${ACTIVE_SLOT}" ] ||
  echo "${BLUE}[     INFO ]${NORMAL} active slot is ${ACTIVE_SLOT}" >&2

# Report existing partition sizes
adb_sh ls -l /dev/block/by-name/ </dev/null 2>/dev/null |
  sed -n 's@.* \([^ ]*\) -> /dev/block/\([^ ]*\)$@\1 \2@p' |
  while read name device; do
    case ${name} in
      system_[ab] | system | vendor_[ab] | vendor | super | cache)
        case ${device} in
          sd*)
            device=${device%%[0-9]*}/${device}
            ;;
        esac
        size=`adb_su cat /sys/block/${device}/size 2>/dev/null </dev/null` &&
          size=`expr ${size} / 2` &&
          echo "${BLUE}[     INFO ]${NORMAL} partition ${name} device ${device} size ${size}K" >&2
        ;;
    esac
  done

# Can we test remount -R command?
overlayfs_supported=true
if [ "orange" = "`get_property ro.boot.verifiedbootstate`" -a \
     "2" = "`get_property partition.system.verified`" ]; then
  restore() {
    ${overlayfs_supported} || return 0
    inFastboot &&
      fastboot reboot &&
      adb_wait 2m
    inAdb &&
      adb_root &&
      adb enable-verity >/dev/null 2>/dev/null &&
      adb_reboot &&
      adb_wait 2m
  }

  echo "${GREEN}[ RUN      ]${NORMAL} Testing adb shell su root remount -R command" >&2

  adb_su remount -R system </dev/null || true
  sleep 2
  adb_wait 2m ||
    die "waiting for device after remount -R `usb_status`"
  if [ "orange" != "`get_property ro.boot.verifiedbootstate`" -o \
       "2" = "`get_property partition.system.verified`" ]; then
    die "remount -R command failed"
  fi

  echo "${GREEN}[       OK ]${NORMAL} adb shell su root remount -R command" >&2
fi

echo "${GREEN}[ RUN      ]${NORMAL} Testing kernel support for overlayfs" >&2

adb_wait || die "wait for device failed"
adb_sh ls -d /sys/module/overlay </dev/null >/dev/null 2>/dev/null ||
  adb_sh grep "nodev${TAB}overlay" /proc/filesystems </dev/null >/dev/null 2>/dev/null &&
  echo "${GREEN}[       OK ]${NORMAL} overlay module present" >&2 ||
  (
    echo "${ORANGE}[  WARNING ]${NORMAL} overlay module not present" >&2 &&
      false
  ) ||
  overlayfs_supported=false
if ${overlayfs_supported}; then
  adb_su ls /sys/module/overlay/parameters/override_creds </dev/null >/dev/null 2>/dev/null &&
    echo "${GREEN}[       OK ]${NORMAL} overlay module supports override_creds" >&2 ||
    case `adb_sh uname -r </dev/null` in
      4.[456789].* | 4.[1-9][0-9]* | [56789].*)
        echo "${ORANGE}[  WARNING ]${NORMAL} overlay module does not support override_creds" >&2 &&
        overlayfs_supported=false
        ;;
      *)
        echo "${GREEN}[       OK ]${NORMAL} overlay module uses caller's creds" >&2
        ;;
    esac
fi

adb_root ||
  die "initial setup"

echo "${GREEN}[ RUN      ]${NORMAL} Checking current overlayfs status" >&2

# We can not universally use adb enable-verity to ensure device is
# in a overlayfs disabled state since it can prevent reboot on
# devices that remount the physical content rather than overlayfs.
# So lets do our best to surgically wipe the overlayfs state without
# having to go through enable-verity transition.
reboot=false
OVERLAYFS_BACKING="cache mnt/scratch"
for d in ${OVERLAYFS_BACKING}; do
  if adb_sh ls -d /${d}/overlay </dev/null >/dev/null 2>/dev/null; then
    echo "${ORANGE}[  WARNING ]${NORMAL} /${d}/overlay is setup, surgically wiping" >&2
    adb_sh rm -rf /${d}/overlay </dev/null ||
      die "/${d}/overlay wipe"
    reboot=true
  fi
done
if ${reboot}; then
  echo "${ORANGE}[  WARNING ]${NORMAL} rebooting before test" >&2
  adb_reboot &&
    adb_wait 2m ||
    die "lost device after reboot after wipe `usb_status`"
  adb_root ||
    die "lost device after elevation to root after wipe `usb_status`"
fi
D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay "` &&
  echo "${H}" &&
  echo "${D}" &&
  echo "${ORANGE}[  WARNING ]${NORMAL} overlays present before setup" >&2 ||
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
    echo "${ORANGE}[  WARNING ]${NORMAL} overlayfs setup whined" >&2
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
    adb_wait 2m ||
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
  echo "${ORANGE}[  WARNING ]${NORMAL} verity already disabled" >&2
fi

echo "${GREEN}[ RUN      ]${NORMAL} remount" >&2

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
if ${overlayfs_needed}; then
  if [ ${ret} != 0 ]; then
    die -t ${T} "overlay takeover failed"
  fi
  echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
   echo "${ORANGE}[  WARNING ]${NORMAL} overlay takeover not complete" >&2
  scratch_partition=scratch
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
    if adb_sh ls -d /${d}/overlay/system/upper </dev/null >/dev/null 2>/dev/null; then
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

echo "${GREEN}[ RUN      ]${NORMAL} push content to /system and /vendor" >&2

A="Hello World! $(date)"
echo "${A}" | adb_sh cat - ">/system/hello"
echo "${A}" | adb_sh cat - ">/vendor/hello"
B="`adb_cat /system/hello`" ||
  die "sytem hello"
check_eq "${A}" "${B}" /system before reboot
B="`adb_cat /vendor/hello`" ||
  die "vendor hello"
check_eq "${A}" "${B}" /vendor before reboot

# Download libc.so, append some gargage, push back, and check if the file
# is updated.
tempdir="`mktemp -d`"
cleanup() {
  rm -rf ${tempdir}
}
adb pull /system/lib/bootstrap/libc.so ${tempdir} >/dev/null ||
  die "pull libc.so from device"
garbage="`hexdump -n 16 -e '4/4 "%08X" 1 "\n"' /dev/random`"
echo ${garbage} >> ${tempdir}/libc.so
adb push ${tempdir}/libc.so /system/lib/bootstrap/libc.so >/dev/null ||
  die "push libc.so to device"
adb pull /system/lib/bootstrap/libc.so ${tempdir}/libc.so.fromdevice >/dev/null ||
  die "pull libc.so from device"
diff ${tempdir}/libc.so ${tempdir}/libc.so.fromdevice > /dev/null ||
  die "libc.so differ"

echo "${GREEN}[ RUN      ]${NORMAL} reboot to confirm content persistent" >&2

adb_reboot &&
  adb_wait 2m ||
  die "reboot after override content added failed"

if ${overlayfs_needed}; then
  D=`adb_su df -k </dev/null` &&
    H=`echo "${D}" | head -1` &&
    D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay "` ||
    ( echo "${L}" && false ) ||
    die -d "overlay takeover failed after reboot"

  adb_su sed -n '1,/overlay \/system/p' /proc/mounts </dev/null |
    skip_administrative_mounts |
    grep -v ' \(erofs\|squashfs\|ext4\|f2fs\|vfat\) ' &&
    echo "${ORANGE}[  WARNING ]${NORMAL} overlay takeover after first stage init" >&2 ||
    echo "${GREEN}[       OK ]${NORMAL} overlay takeover in first stage init" >&2
fi

if ${enforcing}; then
  adb_unroot ||
    die "device not in unroot'd state"
  B="`adb_cat /vendor/hello 2>&1`"
  check_eq "cat: /vendor/hello: Permission denied" "${B}" vendor after reboot w/o root
  echo "${GREEN}[       OK ]${NORMAL} /vendor content correct MAC after reboot" >&2
fi
B="`adb_cat /system/hello`"
check_eq "${A}" "${B}" /system after reboot
echo "${GREEN}[       OK ]${NORMAL} /system content remains after reboot" >&2
# Only root can read vendor if sepolicy permissions are as expected.
adb_root ||
  die "adb root"
B="`adb_cat /vendor/hello`"
check_eq "${A}" "${B}" vendor after reboot
echo "${GREEN}[       OK ]${NORMAL} /vendor content remains after reboot" >&2

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
is_userspace_fastboot=false
if [ -z "${ANDROID_PRODUCT_OUT}" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} build tree not setup, skipping"
elif [ ! -s "${ANDROID_PRODUCT_OUT}/vendor.img" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} vendor image missing, skipping"
elif [ "${ANDROID_PRODUCT_OUT}" = "${ANDROID_PRODUCT_OUT%*/${H}}" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} wrong vendor image, skipping"
elif [ -z "${ANDROID_HOST_OUT}" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} please run lunch, skipping"
else
  adb reboot-fastboot ||
    die "fastbootd not supported (wrong adb in path?)"
  any_wait 2m &&
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
  echo "${ORANGE}[  WARNING ]${NORMAL} adb after fastboot"
  adb_wait 2m ||
    die "did not reboot after flash `usb_status`"
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
        echo "${ORANGE}[  WARNING ]${NORMAL} user fastboot missing required to invalidate, ignoring a failure" >&2
        echo "${ORANGE}[  WARNING ]${NORMAL} overlay supposed to be minus /vendor takeover after flash vendor" >&2
      fi
  fi
  B="`adb_cat /system/hello`"
  check_eq "${A}" "${B}" system after flash vendor
  adb_root ||
    die "adb root"
  B="`adb_cat /vendor/hello`"
  if ${is_userspace_fastboot} || ! ${overlayfs_needed}; then
    check_eq "cat: /vendor/hello: No such file or directory" "${B}" \
             vendor content after flash vendor
  else
    (
      echo "${ORANGE}[  WARNING ]${NORMAL} user fastboot missing required to invalidate, ignoring a failure" >&2
      restore() {
        true
      }
      check_eq "cat: /vendor/hello: No such file or directory" "${B}" \
               vendor content after flash vendor
    )
  fi
fi

echo "${GREEN}[ RUN      ]${NORMAL} remove test content (cleanup)" >&2

T=`adb_date`
H=`adb remount 2>&1`
err=${?}
L=
D="${H%?Now reboot your device for settings to take effect*}"
if [ X"${H}" != X"${D}" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} adb remount requires a reboot after partial flash (legacy avb)"
  L=`adb_logcat -b all -v nsec -t ${T} 2>&1`
  adb_reboot &&
    adb_wait 2m &&
    adb_root ||
    die "failed to reboot"
  T=`adb_date`
  H=`adb remount 2>&1`
  err=${?}
fi
echo "${H}"
[ ${err} = 0 ] &&
  ( adb_sh rm /vendor/hello </dev/null 2>/dev/null || true ) &&
  adb_sh rm /system/hello </dev/null ||
  ( [ -n "${L}" ] && echo "${L}" && false ) ||
  die -t ${T} "cleanup hello"
B="`adb_cat /system/hello`"
check_eq "cat: /system/hello: No such file or directory" "${B}" after rm
B="`adb_cat /vendor/hello`"
check_eq "cat: /vendor/hello: No such file or directory" "${B}" after rm

if [ -n "${scratch_partition}" ]; then

  echo "${GREEN}[ RUN      ]${NORMAL} test fastboot flash to ${scratch_partition} recovery" >&2

  adb reboot-fastboot ||
    die "Reboot into fastbootd"
  img=${TMPDIR}/adb-remount-test-${$}.img
  cleanup() {
    rm ${img}
  }
  dd if=/dev/zero of=${img} bs=4096 count=16 2>/dev/null &&
    fastboot_wait 2m ||
    die "reboot into fastboot `usb_status`"
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
  adb_wait 2m &&
    adb_root ||
    die "did not reboot after flash"
  T=`adb_date`
  D=`adb disable-verity 2>&1`
  err=${?}
  if [ X"${D}" != "${D%?Now reboot your device for settings to take effect*}" ]
  then
    echo "${ORANGE}[  WARNING ]${NORMAL} adb disable-verity requires a reboot after partial flash"
    adb_reboot &&
      adb_wait 2m &&
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

# Prerequisite is a prepped device from above.
adb_reboot &&
  adb_wait 2m ||
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
  adb_wait 2m ||
  die "lost device after reboot to ro state (USB stack broken?)"
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
  adb_su rm -rf /${d}/overlay </dev/null ||
    die "/${d}/overlay wipe"
done
adb_reboot &&
  adb_wait 2m ||
  die "lost device after reboot after wipe (USB stack broken?)"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/vendor is not read-only"
adb_su remount vendor </dev/null ||
  die "remount command"
adb_sh grep " /vendor .* rw," /proc/mounts >/dev/null </dev/null ||
  die "/vendor is not read-write"
adb_sh grep " /system .* rw," /proc/mounts >/dev/null </dev/null &&
  die "/system is not read-only"
echo "${GREEN}[       OK ]${NORMAL} remount command works from scratch" >&2

restore
err=${?}

if [ ${err} = 0 ] && ${overlayfs_supported}; then
  echo "${GREEN}[ RUN      ]${NORMAL} test 'adb remount -R'" >&2
  adb_root &&
    adb remount -R &&
    adb_wait 2m ||
    die "adb remount -R"
  if [ "orange" != "`get_property ro.boot.verifiedbootstate`" -o \
       "2" = "`get_property partition.system.verified`" ]; then
    die "remount -R command failed to disable verity"
  fi

  echo "${GREEN}[       OK ]${NORMAL} 'adb remount -R' command" >&2

  restore
  err=${?}
fi

restore() {
  true
}

[ ${err} = 0 ] ||
  die "failed to restore verity" >&2

echo "${GREEN}[  PASSED  ]${NORMAL} adb remount" >&2

test_duration
