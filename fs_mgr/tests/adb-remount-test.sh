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
BLUE="${ESCAPE}[35m"
NORMAL="${ESCAPE}[0m"

# Helper functions

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
    grep -v -e 'List of devices attached' -e '^$' |
    if [ -n "${ANDROID_SERIAL}" ]; then
      grep "^${ANDROID_SERIAL}[${SPACE}${TAB}]" > /dev/null
    else
      wc -l | grep '^1$' >/dev/null
    fi
}

[ "USAGE: adb_sh <commands> </dev/stdin >/dev/stdout 2>/dev/stderr

Returns: true if the command succeeded" ]
adb_sh() {
  args=
  for i in ${@}; do
    if [ X"${i}" != X"${i#\'}" ]; then
      args="${args} ${i}"
    elif [ X"${i}" != X"${i#* }" ]; then
      args="${args} '${i}'"
    else
      args="${args} ${i}"
    fi
  done
  adb shell ${args}
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
    OUTPUT="`adb_sh cat ${1} </dev/null 2>&1`"
    retval=${?}
    echo "${OUTPUT}" | tr -d '\r'
    return ${retval}
}

[ "USAGE: adb_reboot

Returns: true if the reboot command succeeded" ]
adb_reboot() {
  adb reboot remount-test &&
  sleep 2
}

[ "USAGE: adb_wait [timeout]

Returns: waits until the device has returned for adb or optional timeout" ]
adb_wait() {
  if [ -n "${1}" ]; then
    timeout --preserve-status --signal=KILL ${1} adb wait-for-device
  else
    adb wait-for-device
  fi
}

[ "USAGE: fastboot_wait [timeout]

Returns: waits until the device has returned for fastboot or optional timeout" ]
fastboot_wait() {
  # fastboot has no wait-for-device, but it does an automatic
  # wait and requires (even a nonsensical) command to do so.
  if [ -n "${1}" ]; then
    timeout --preserve-status --signal=KILL ${1} fastboot wait-for-device
  else
    fastboot wait-for-device >/dev/null
  fi >/dev/null 2>/dev/null ||
    inFastboot
}

[ "USAGE: adb_root

NB: This can be flakey on devices due to USB state

Returns: true if device in root state" ]
adb_root() {
  [ `adb_sh echo '${USER}'` != root ] || return 0
  adb root >/dev/null </dev/null 2>/dev/null
  sleep 2
  adb_wait 2m &&
    [ `adb_sh echo '${USER}'` = root ]
}

[ "USAGE: adb_unroot

NB: This can be flakey on devices due to USB state

Returns: true if device in un root state" ]
adb_unroot() {
  [ `adb_sh echo '${USER}'` = root ] || return 0
  adb unroot >/dev/null </dev/null 2>/dev/null
  sleep 2
  adb_wait 2m &&
    [ `adb_sh echo '${USER}'` != root ]
}

[ "USAGE: fastboot_getvar var expected

Returns: true if var output matches expected" ]
fastboot_getvar() {
  O=`fastboot getvar ${1} 2>&1`
  err=${?}
  O="${O#< waiting for * >?}"
  O="${O%%?Finished. Total time: *}"
  if [ 0 -ne ${err} ]; then
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

[ "USAGE: cleanup

Do nothing: should be redefined when necessary

Returns: cleans up any latent resources, reverses configurations" ]
cleanup () {
  :
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
    -e " /\(cache\|mnt/scratch\|mnt/vendor/persist\|metadata\) "
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
inAdb || die "specified device not in adb mode"
isDebuggable || die "device not a debug build"
enforcing=true
if ! adb_su getenforce </dev/null | grep 'Enforcing' >/dev/null; then
  echo "${ORANGE}[  WARNING ]${NORMAL} device does not have sepolicy in enforcing mode"
  enforcing=false
fi

# Do something

echo "${GREEN}[ RUN      ]${NORMAL} Testing kernel support for overlayfs" >&2

overlayfs_supported=true;
adb_wait || die "wait for device failed"
adb_sh ls -d /sys/module/overlay </dev/null >/dev/null &&
  echo "${GREEN}[       OK ]${NORMAL} overlay module present" >&2 ||
  (
    echo "${ORANGE}[  WARNING ]${NORMAL} overlay module not present" >&2 &&
      false
  ) ||
  overlayfs_supported=false
if ${overlayfs_supported}; then
  case `adb_sh uname -r </dev/null` in
    4.[6789].* | 4.[1-9][0-9]* | [56789].*)
      adb_su ls /sys/module/overlay/parameters/override_creds </dev/null >/dev/null &&
        echo "${GREEN}[       OK ]${NORMAL} overlay module supports override_creds" >&2 ||
        (
          echo "${ORANGE}[  WARNING ]${NORMAL} overlay module does not support override_creds" >&2 &&
          false
        ) ||
        overlayfs_supported=false;
      ;;
    *)
      echo "${GREEN}[       OK ]${NORMAL} overlay module uses callers creds" >&2
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
    die "lost device after reboot after wipe"
  adb_root ||
    die "lost device after elevation to root after wipe"
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
D=`adb_sh df -k ${D} </dev/null`
echo "${D}"
if [ X"${D}" = X"${D##* 100[%] }" ]; then
  overlayfs_needed=false
elif ! ${overlayfs_supported}; then
  die "need overlayfs, but do not have it"
fi

echo "${GREEN}[ RUN      ]${NORMAL} disable verity" >&2

T=`adb_date`
H=`adb disable-verity 2>&1`
err=${?}
L=
D="${H%?Now reboot your device for settings to take effect}"
if [ X"${D}" != X"${D##*using overlayfs}" ]; then
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
    die "lost device after reboot requested"
  adb_root ||
    die "lost device after elevation to root"
  rebooted=true
  # re-disable verity to see the setup remarks expected
  T=`adb_date`
  H=`adb disable-verity 2>&1`
  err=${?}
  D="${H%?Now reboot your device for settings to take effect}"
  if [ X"${D}" != X"${D##*using overlayfs}" ]; then
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

adb remount ||
  ( [ -n "${L}" ] && echo "${L}" && false ) ||
  die -t "${T}" "adb remount failed"
D=`adb_sh df -k </dev/null` &&
  H=`echo "${D}" | head -1` &&
  D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay "` ||
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
    grep -v "^overlay /\(vendor\|system\)/..* overlay ro," |
    grep " overlay ro,") &&
    !(adb_sh grep " rw," /proc/mounts </dev/null |
      skip_administrative_mounts data) ||
    die "remount overlayfs missed a spot (ro)"
else
  if [ ${ret} = 0 ]; then
    die -t ${T} "unexpected overlay takeover"
  fi
fi

# Check something

echo "${GREEN}[ RUN      ]${NORMAL} push content to /system and /vendor" >&2

A="Hello World! $(date)"
echo "${A}" | adb_sh "cat - > /system/hello"
echo "${A}" | adb_sh "cat - > /vendor/hello"
B="`adb_cat /system/hello`" ||
  die "sytem hello"
check_eq "${A}" "${B}" /system before reboot
B="`adb_cat /vendor/hello`" ||
  die "vendor hello"
check_eq "${A}" "${B}" /vendor before reboot

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

  adb_su "sed -n '1,/overlay \\/system/p' /proc/mounts" </dev/null |
    skip_administrative_mounts |
    grep -v ' \(squashfs\|ext4\|f2fs\) ' &&
    echo "${ORANGE}[  WARNING ]${NORMAL} overlay takeover after first stage init" >&2 ||
    echo "${GREEN}[       OK ]${NORMAL} overlay takeover in first stage init" >&2
fi

B="`adb_cat /system/hello`" ||
  die "re-read /system/hello after reboot"
check_eq "${A}" "${B}" /system after reboot
echo "${GREEN}[       OK ]${NORMAL} /system content remains after reboot" >&2
# Only root can read vendor if sepolicy permissions are as expected
if ${enforcing}; then
  adb_unroot
  B="`adb_cat /vendor/hello`" &&
    die "re-read /vendor/hello after reboot w/o root"
  check_eq "cat: /vendor/hello: Permission denied" "${B}" vendor after reboot w/o root
  echo "${GREEN}[       OK ]${NORMAL} /vendor content correct MAC after reboot" >&2
fi
adb_root &&
  B="`adb_cat /vendor/hello`" ||
  die "re-read /vendor/hello after reboot"
check_eq "${A}" "${B}" vendor after reboot
echo "${GREEN}[       OK ]${NORMAL} /vendor content remains after reboot" >&2

echo "${GREEN}[ RUN      ]${NORMAL} flash vendor, confirm its content disappears" >&2

H=`adb_sh echo '${HOSTNAME}' </dev/null 2>/dev/null`
if [ -z "${ANDROID_PRODUCT_OUT}" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} build tree not setup, skipping"
elif [ ! -s "${ANDROID_PRODUCT_OUT}/vendor.img" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} vendor image missing, skipping"
elif [ "${ANDROID_PRODUCT_OUT}" = "${ANDROID_PRODUCT_OUT%*/${H}}" ]; then
  echo "${ORANGE}[  WARNING ]${NORMAL} wrong vendor image, skipping"
else
  adb reboot-fastboot &&
    fastboot_wait 2m &&
    fastboot flash vendor ||
    ( fastboot reboot && false) ||
    die "fastboot flash vendor"
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
  echo "${ORANGE}[  WARNING ]${NORMAL} adb after fastboot ... waiting 2 minutes"
  adb_wait 2m ||
    die "did not reboot after flash"
  if ${overlayfs_needed}; then
    adb_root &&
      D=`adb_sh df -k </dev/null` &&
      H=`echo "${D}" | head -1` &&
      D=`echo "${D}" | grep -v " /vendor/..*$" | grep "^overlay "` &&
      echo "${H}" &&
      echo "${D}" &&
      echo "${D}" | grep "^overlay .* /system\$" >/dev/null ||
      die  "overlay /system takeover after flash vendor"
    echo "${D}" | grep "^overlay .* /vendor\$" >/dev/null &&
      die  "overlay supposed to be minus /vendor takeover after flash vendor"
  fi
  B="`adb_cat /system/hello`" ||
    die "re-read /system/hello after flash vendor"
  check_eq "${A}" "${B}" system after flash vendor
  adb_root ||
    die "adb root"
  B="`adb_cat /vendor/hello`" &&
    die "re-read /vendor/hello after flash vendor"
  check_eq "cat: /vendor/hello: No such file or directory" "${B}" vendor after flash vendor
fi

echo "${GREEN}[ RUN      ]${NORMAL} remove test content (cleanup)" >&2

T=`adb_date`
adb remount &&
  ( adb_sh rm /vendor/hello </dev/null 2>/dev/null || true ) &&
  adb_sh rm /system/hello </dev/null ||
  die -t ${T} "cleanup hello"
B="`adb_cat /system/hello`" &&
  die "re-read /system/hello after rm"
check_eq "cat: /system/hello: No such file or directory" "${B}" after flash rm
B="`adb_cat /vendor/hello`" &&
  die "re-read /vendor/hello after rm"
check_eq "cat: /vendor/hello: No such file or directory" "${B}" after flash rm

if [ -n "${scratch_partition}" ]; then

  echo "${GREEN}[ RUN      ]${NORMAL} test fastboot flash to ${scratch_partition}" >&2

  adb reboot-fastboot ||
    die "Reboot into fastbootd"
  dd if=/dev/zero of=/tmp/adb-remount-test.img bs=4096 count=16 2>/dev/null &&
    fastboot_wait 2m ||
    ( rm /tmp/adb-remount-test.img && false) ||
    die "reboot into fastboot"
  fastboot flash --force ${scratch_partition} /tmp/adb-remount-test.img
  err=${?}
  rm /tmp/adb-remount-test.img
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
  echo "${D}"
  [ ${err} = 0 ] &&
    [ X"${D}" = X"${D##*setup failed}" ] &&
    [ X"${D}" != X"${D##*using overlayfs}" ] &&
    echo "${GREEN}[       OK ]${NORMAL} ${scratch_partition} recreated" >&2 ||
    die -t ${T} "setup for overlayfs"
fi

echo "${GREEN}[  PASSED  ]${NORMAL} adb remount" >&2
