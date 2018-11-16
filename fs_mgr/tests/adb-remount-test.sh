#! /bin/bash

USAGE="USAGE: `basename ${0}` [-s <SerialNumber>]

adb remount tests (overlayfs focus)

Conditions:
 - Must be a userdebug build.
 - Must be in adb mode.
 - Kernel must have overlayfs enabled and patched to support override_creds.
 - Must have either squashfs, ext4-dedupe or right-sized partitions.
 - Minimum expectation system and vender are overlayfs covered partitions.
"

if [ X"${1}" = X"--help" -o X"${1}" = X"-h" -o X"${1}" = X"-?" ]; then
  echo "${USAGE}" >&2
  exit 0
fi

# Helper Variables

SPACE=" "
# A _real_ embedded tab character
TAB="`echo | tr '\n' '\t'`"
# A _real_ embedded escape character
ESCAPE="`echo | tr '\n' '\033'`"
GREEN="${ESCAPE}[38;5;40m"
RED="${ESCAPE}[38;5;196m"
ORANGE="${ESCAPE}[38;5;255:165:0m"
NORMAL="${ESCAPE}[0m"

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

[ "USAGE: adb_sh <commands>

Returns: true if the command succeeded" ]
adb_sh() {
  adb shell "${@}"
}

[ "USAGE: adb_date >/dev/stdout

Returns: report device epoch time (suitable for logcat -t)" ]
adb_date() {
  adb_sh date +%s.%N </dev/null
}

[ "USAGE: adb_logcat [arguments] >/dev/stdout

Returns: the logcat output" ]
adb_logcat() {
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
  if inAdb && [ 1 -ne `get_property ro.debuggable` ]; then
    false
  fi
}

[ "USAGE: adb_su <commands>

Returns: true if the command running as root succeeded" ]
adb_su() {
  adb_sh su root "${@}"
}

[ "USAGE: adb_cat <file> >stdout

Returns: content of file to stdout with carriage returns skipped,
         true of the file exists" ]
adb_cat() {
    OUTPUT="`adb_sh cat ${1} </dev/null 2>&1`"
    retval=${?}
    echo "${OUTPUT}" | tr -d '\r'
    return ${retval}
}

[ "USAGE: adb_reboot

Returns: true if the reboot command succeeded" ]
adb_reboot() {
  adb reboot remount-test
}

[ "USAGE: adb_wait [timeout]

Returns: waits until the device has returned or the optional timeout" ]
adb_wait() {
  if [ -n "${1}" ]; then
    timeout --preserve-status --signal=KILL ${1} adb wait-for-device
  else
    adb wait-for-device
  fi
}

[ "USAGE: adb_root

Returns: true if device in root state" ]
adb_root() {
  adb root >/dev/null </dev/null 2>/dev/null &&
  sleep 1 &&
  adb_wait &&
  sleep 1
}

[ "USAGE: die [-t <epoch>] [message] >/dev/stderr

If -t <epoch> argument is supplied, dump logcat.

Returns: exit failure, report status" ]
die() {
  if [ X"-t" = X"${1}" -a -n "${2}" ]; then
    adb_logcat -b all -v nsec -t ${2} >&2
    shift 2
  fi
  echo "${RED}[  FAILED  ]${NORMAL} ${@}" >&2
  exit 1
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
  left="${1}"
  right="${2}"
  shift 2
  EXPECT_EQ "${left}" "${right}" ||
    die "${@}"
}

[ "USAGE: skip_administrative_mounts < /proc/mounts

Filters out all administrative (eg: sysfs) mounts uninteresting to the test" ]
skip_administrative_mounts() {
  grep -v \
    -e "^\(overlay\|tmpfs\|none\|sysfs\|proc\|selinuxfs\|debugfs\) " \
    -e "^\(bpf\|cg2_bpf\|pstore\|tracefs\|adb\|mtp\|ptp\|devpts\) " \
    -e "^\(/data/media\|/dev/block/loop[0-9]*\) " \
    -e " /\(cache\|mnt/scratch\|mnt/vendor/persist\|metadata\|data\) "
}

if [ X"-s" = X"${1}" -a -n "${2}" ]; then
  export ANDROID_SERIAL="${2}"
  shift 2
fi

inFastboot && die "device in fastboot mode"
if ! inAdb; then
  echo "${ORANGE}[  WARNING ]${NORMAL} device not in adb mode ... waiting 2 minutes"
  adb_wait 2m
fi
inAdb || die "device not in adb mode"
isDebuggable || die "device not a debug build"

# Do something
adb_wait || die "wait for device failed"
adb_sh ls -d /sys/module/overlay </dev/null >/dev/null &&
  echo "${GREEN}[       OK ]${NORMAL} overlay module present" >&2 ||
  die "overlay module not present"
adb_su ls /sys/module/overlay/parameters/override_creds </dev/null >/dev/null &&
  echo "${GREEN}[       OK ]${NORMAL} overlay module supports override_creds" >&2 ||
  die "overlay module can not be used on ANDROID"
adb_root &&
  adb_wait ||
  die "initial setup"
reboot=false
OVERLAYFS_BACKING="cache mnt/scratch"
for d in ${OVERLAYFS_BACKING}; do
  if adb_sh ls -d /${d}/overlay </dev/null >/dev/null 2>/dev/null; then
    echo "${ORANGE}[  WARNING ]${NORMAL} /${d}/overlay is setup, wiping" >&2
    adb_sh rm -rf /${d}/overlay </dev/null ||
      die "/${d}/overlay wipe"
    reboot=true
  fi
done
if ${reboot}; then
  echo "${ORANGE}[  WARNING ]${NORMAL} rebooting before test" >&2
  adb_reboot &&
    adb_wait 2m &&
    adb_root &&
    adb_wait ||
    die "reboot after wipe"
fi
D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep "^overlay "` &&
  echo "${H}" &&
  echo "${D}" &&
  echo "${ORANGE}[  WARNING ]${NORMAL} overlays present before setup" >&2 ||
  echo "${GREEN}[       OK ]${NORMAL} no overlay present before setup" >&2
adb_sh df -k `adb_sh cat /proc/mounts |
                skip_administrative_mounts |
                cut -s -d' ' -f1`

T=`adb_date`
D=`adb disable-verity 2>&1`
err=${?}
echo "${D}"
if [ ${err} != 0 -o X"${D}" != X"${D##*setup failed}" ]; then
  die -t ${T} "setup for overlay"
fi
if [ X"${D}" != X"${D##*using overlayfs}" ]; then
  echo "${GREEN}[       OK ]${NORMAL} using overlayfs" >&2
fi
adb_reboot &&
  adb_wait &&
  D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep "^overlay "` &&
  echo "${H}" &&
  echo "${D}" ||
  die "overlay takeover failed"
echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
  echo "${ORANGE}[  WARNING ]${NORMAL} overlay takeover before remount not complete" >&2

T=`adb_date`
adb_root &&
  adb_wait &&
  adb remount &&
  D=`adb_sh df -k </dev/null` ||
  die -t ${T} "can not collect filesystem data"
if echo "${D}" | grep " /mnt/scratch" >/dev/null; then
  echo "${ORANGE}[     INFO ]${NORMAL} using scratch dynamic partition for overrides" >&2
  H=`adb_sh cat /proc/mounts | sed -n 's@\([^ ]*\) /mnt/scratch \([^ ]*\) .*@\2 on \1@p'`
  [ -n "${H}" ] &&
    echo "${ORANGE}[     INFO ]${NORMAL} scratch filesystem ${H}"
fi
for d in ${OVERLAYFS_BACKING}; do
  if adb_sh ls -d /${d}/overlay/system/upper </dev/null >/dev/null 2>/dev/null; then
    echo "${ORANGE}[     INFO ]${NORMAL} /${d}/overlay is setup" >&2
  fi
done

H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep "^overlay "` &&
  echo "${H}" &&
  echo "${D}" &&
  echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
  die  "overlay takeover after remount"
!(adb_sh grep "^overlay " /proc/mounts </dev/null | grep " overlay ro,") &&
  !(adb_sh grep " rw," /proc/mounts </dev/null | skip_administrative_mounts) ||
  die "remount overlayfs missed a spot (ro)"

adb_su "sed -n '1,/overlay \\/system/p' /proc/mounts" </dev/null |
  skip_administrative_mounts |
  grep -v ' \(squashfs\|ext4\|f2fs\) ' &&
  echo "${ORANGE}[  WARNING ]${NORMAL} overlay takeover after first stage init" >&2 ||
  echo "${GREEN}[       OK ]${NORMAL} overlay takeover in first stage init" >&2

# Check something
A="Hello World! $(date)"
echo "${A}" | adb_sh "cat - > /system/hello"
echo "${A}" | adb_sh "cat - > /vendor/hello"
B="`adb_cat /system/hello`" ||
  die "sytem hello"
check_eq "${A}" "${B}" system before reboot
B="`adb_cat /vendor/hello`" ||
  die "vendor hello"
check_eq "${A}" "${B}" vendor before reboot
adb_reboot &&
  adb_wait &&
  B="`adb_cat /system/hello`" ||
  die "re-read system hello after reboot"
check_eq "${A}" "${B}" system after reboot
# Only root can read vendor if sepolicy permissions are as expected
B="`adb_cat /vendor/hello`" &&
  die "re-read vendor hello after reboot w/o root"
check_eq "cat: /vendor/hello: Permission denied" "${B}" vendor after reboot w/o root
adb_root &&
  adb_wait &&
  B="`adb_cat /vendor/hello`" ||
  die "re-read vendor hello after reboot"
check_eq "${A}" "${B}" vendor after reboot

adb reboot-fastboot &&
  fastboot flash vendor &&
  fastboot reboot ||
  die "fastbootd flash vendor"
adb_wait 2m ||
  die "did not reboot after flash"
adb_root &&
  adb_wait &&
  D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep "^overlay "` &&
  echo "${H}" &&
  echo "${D}" &&
  echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
  die  "overlay system takeover after flash vendor"
echo "${D}" | grep "^overlay .* /vendor\$" >/dev/null &&
  die  "overlay minus vendor takeover after flash vendor"
B="`adb_cat /system/hello`" ||
  die "re-read system hello after flash vendor"
check_eq "${A}" "${B}" system after flash vendor
adb_root &&
  adb_wait ||
  die "adb root"
B="`adb_cat /vendor/hello`" &&
  die "re-read vendor hello after flash vendor"
check_eq "cat: /vendor/hello: No such file or directory" "${B}" vendor after flash vendor

T=`adb_date`
adb remount &&
  ( adb_sh rm /vendor/hello </dev/null 2>/dev/null || true ) &&
  adb_sh rm /system/hello </dev/null ||
  die -t ${T} "cleanup hello"
B="`adb_cat /system/hello`" &&
  die "re-read system hello after rm"
check_eq "cat: /system/hello: No such file or directory" "${B}" after flash rm
B="`adb_cat /vendor/hello`" &&
  die "re-read vendor hello after rm"
check_eq "cat: /vendor/hello: No such file or directory" "${B}" after flash rm

echo "${GREEN}[  PASSED  ]${NORMAL} adb remount" >&2
