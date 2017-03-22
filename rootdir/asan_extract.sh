#!/system/bin/sh

#
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This script will extract ASAN libraries from /system/asan.tar.gz to /data and then reboot.

# TODO:
#   * Timestamp or something to know when to run this again. Right now take the existence of
#     /data/lib as we're already done.
#   * Need to distinguish pre- from post-decryption for FDE.

SRC=/system/asan.tar.bz2
MD5_FILE=/data/asan.md5sum

if ! test -f $SRC ; then
  log -p i -t asan_install "Did not find $SRC!"
  exit 1
fi

log -p i -t asan_install "Found $SRC, checking whether we need to apply it."

ASAN_TAR_MD5=$(md5sum $SRC)
if test -f $MD5_FILE ; then
  INSTALLED_MD5=$(cat $MD5_FILE)
  if [ "x$ASAN_TAR_MD5" = "x$INSTALLED_MD5" ] ; then
    log -p i -t asan_install "Checksums match, nothing to be done here."
    exit 0
  fi
fi

# Just clean up, helps with restorecon.
rm -rf /data/lib /data/lib64 /data/vendor/lib*

log -p i -t asan_install "Untarring $SRC..."

# Unzip from /system/asan.tar.gz into data. Need to pipe as gunzip is not on device.
bzip2 -c -d $SRC | tar -x -f - --no-same-owner -C / || exit 1

# Cannot log here, log would run with system_data_file.

restorecon -R -F /data/lib* /data/vendor/lib*

log -p i -t asan_install "Fixed selinux labels..."

echo "$ASAN_TAR_MD5" > $MD5_FILE

# We want to reboot now. It seems it is not possible to run "reboot" here, the device will
# just be stuck.

log -p i -t asan_install "Signaling init to reboot..."

setprop asan.restore_reboot 1
