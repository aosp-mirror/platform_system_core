Android OverlayFS Integration with adb Remount
==============================================

Introduction
------------

Users working with userdebug or eng builds expect to be able to remount the
system partition as read-write and then add or modify any number of files
without reflashing the system image, which is efficient for a development cycle.

Limited memory systems use read-only types of file systems or logical resizable
Android partitions (LRAPs). These file systems land system partition images
right-sized, and have been deduped at the block level to compress the content.
This means that a remount either isn’t possible, or isn't useful because of
space limitations or support logistics.

OverlayFS resolves these debug scenarios with the _adb disable-verity_ and
_adb remount_ commands, which set up backing storage for a writable file
system as an upper reference, and mount the lower reference on top.

Performing a remount
--------------------

Use the following sequence to perform the remount.

    $ adb root
    $ adb disable-verity
    $ adb reboot
    $ adb wait-for-device
    $ adb root
    $ adb remount

Then enter one of the following sequences:

    $ adb shell stop
    $ adb sync
    $ adb shell start
    $ adb reboot

*or*

    $ adb push <source> <destination>
    $ adb reboot

Note that you can replace these two lines:

    $ adb disable-verity
    $ adb reboot

with this line:

    $ adb remount -R

**Note:** _adb reboot -R_ won’t reboot if the device is already in the adb remount state.

None of this changes if OverlayFS needs to be engaged.
The decisions whether to use traditional direct file-system remount,
or one wrapped by OverlayFS is automatically determined based on
a probe of the file-system types and space remaining.

### Backing Storage

When *OverlayFS* logic is feasible, it uses either the
**/cache/overlay/** directory for non-A/B devices, or the
**/mnt/scratch/overlay** directory for A/B devices that have
access to *LRAP*.
It is also possible for an A/B device to use the system_<other> partition
for backing storage. eg: if booting off system_a+vendor_a, use system_b.
The backing store is used as soon as possible in the boot
process and can occur at first stage init, or when the
*mount_all* commands are run in init RC scripts.

By attaching OverlayFS early, SEpolicy or init can be pushed and used after the exec phases of each stage.

Caveats
-------

- Backing storage requires more space than immutable storage, as backing is
  done file by file. Be mindful of wasted space. For example, defining
  **BOARD_IMAGE_PARTITION_RESERVED_SIZE** has a negative impact on the
  right-sizing of images and requires more free dynamic partition space.
- The kernel requires **CONFIG_OVERLAY_FS=y**. If the kernel version is higher
  than 4.4, it requires source to be in line with android-common kernels. 
  The patch series is available on the upstream mailing list and the latest as
  of Sep 5 2019 is https://www.spinics.net/lists/linux-mtd/msg08331.html
  This patch adds an override_creds _mount_ option to OverlayFS that
  permits legacy behavior for systems that do not have overlapping
  sepolicy rules, principals of least privilege, which is how Android behaves.
  For 4.19 and higher a rework of the xattr handling to deal with recursion
  is required. https://patchwork.kernel.org/patch/11117145/ is a start of that
  adjustment.
- _adb enable-verity_ frees up OverlayFS and reverts the device to the state
  prior to content updates. The update engine performs a full OTA.
- _adb remount_ overrides are incompatible with OTA resources, so the update
  engine may not run if fs_mgr_overlayfs_is_setup() returns true.
- If a dynamic partition runs out of space, making a logical partition larger
  may fail because of the scratch partition. If this happens, clear the scratch
  storage by running either either _fastboot flashall_ or _adb enable-verity_.
  Then reinstate the overrides and continue.
- For implementation simplicity on retrofit dynamic partition devices,
  take the whole alternate super (eg: if "*a*" slot, then the whole of
  "*system_b*").
  Since landing a filesystem on the alternate super physical device
  without differentiating if it is setup to support logical or physical,
  the alternate slot metadata and previous content will be lost.
- There are other subtle caveats requiring complex logic to solve.
  Have evaluated them as too complex or not worth the trouble, please
  File a bug if a use case needs to be covered.
  - The backing storage is treated fragile, if anything else has
    issue with the space taken, the backing storage will be cleared
    out and we reserve the right to not inform, if the layering
    does not prevent any messaging.
  - Space remaining threshold is hard coded.  If 1% or more space
    still remains, OverlayFS will not be used, yet that amount of
    space remaining is problematic.
  - Flashing a partition via bootloader fastboot, as opposed to user
    space fastbootd, is not detected, thus a partition may have
    override content remaining.  adb enable-verity to wipe.
  - Space is limited, there is near unlimited space on userdata,
    we have made an architectural decision to not utilize
    /data/overlay/ at this time.  Acquiring space to use for
    backing remains an ongoing battle.
  - First stage init, or ramdisk, can not be overriden.
  - Backing storage will be discarded or ignored on errors, leading
    to confusion.  When debugging using **adb remount** it is
    currently advised to confirm update is present after a reboot
    to develop confidence.
- File bugs or submit fixes for review.
