#!/bin/bash

# This is a debug script to quicky test end-to-end flow
# of snapshot updates without going through update-engine.
#
# Usage:
#
#  To update both dynamic and static partitions:
#
# ./system/core/fs_mgr/libsnapshot/apply_update.sh [--update-static-partitions] [--wipe]
#
# --update-static-partitions: This will update bootloader and static A/B
# partitions
# --wipe: Allows data wipe as part of update flow
#
#  To update dynamic partitions only (this should be used when static
#  partitions are present in both the slots):
#
#  ./system/core/fs_mgr/libsnapshot/apply_update.sh
#
#

rm -f $OUT/*.patch

# Compare images and create snapshot patches. Currently, this
# just compares two identical images in $OUT. In general, any source
# and target images could be passed to create snapshot patches. However,
# care must be taken to ensure source images are already present on the device.
#
# create_snapshot is a host side binary. Build it with `m create_snapshot`
create_snapshot --source=$OUT/system.img --target=$OUT/system.img &
create_snapshot --source=$OUT/product.img --target=$OUT/product.img &
create_snapshot --source=$OUT/vendor.img --target=$OUT/vendor.img &
create_snapshot --source=$OUT/system_ext.img --target=$OUT/system_ext.img &
create_snapshot --source=$OUT/vendor_dlkm.img --target=$OUT/vendor_dlkm.img &
create_snapshot --source=$OUT/system_dlkm.img --target=$OUT/system_dlkm.img &

echo "Waiting for snapshot patch creation"
wait $(jobs -p)
echo "Snapshot patch creation completed"

mv *.patch $OUT/

adb root
adb wait-for-device
adb shell mkdir -p /data/update/
adb push $OUT/*.patch /data/update/

if [[ "$2" == "--wipe" ]]; then
  adb shell snapshotctl apply-update /data/update/ -w
else
  adb shell snapshotctl apply-update /data/update/
fi

# Check if the --update-static-partitions option is provided.
# For quick developer workflow, there is no need to repeatedly
# apply static partitions.
if [[ "$1" == "--update-static-partitions" ]]; then
  adb reboot bootloader
  sleep 5
  if [[ "$2" == "--wipe" ]]; then
      fastboot -w
  fi
  fastboot flash bootloader $OUT/bootloader.img
  sleep 1
  fastboot reboot bootloader
  sleep 1
  fastboot flash radio $OUT/radio.img
  sleep 1
  fastboot reboot bootloader
  sleep 1
  fastboot flashall --exclude-dynamic-partitions --disable-super-optimization
else
  adb reboot
fi

echo "Update completed"
