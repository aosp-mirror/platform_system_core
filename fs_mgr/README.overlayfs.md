Android Overlayfs integration with adb remount
==============================================

Introduction
------------

Users working with userdebug or eng builds expect to be able to
remount the system partition as read-write and then add or modify
any number of files without reflashing the system image, which is
understandably efficient for a development cycle.
Limited memory systems that chose to use readonly filesystems like
*squashfs*, or *Logical Resizable Android Partitions* which land
system partition images right-sized, and with filesystem that have
been deduped on the block level to compress the content; means that
either a remount is not possible directly, or when done offers
little or no utility because of remaining space limitations or
support logistics.

*Overlayfs* comes to the rescue for these debug scenarios, and logic
will _automatically_ setup backing storage for a writable filesystem
as an upper reference, and mount overtop the lower.  These actions
will be performed in the **adb disable-verity** and **adb remount**
requests.

Operations
----------

### Cookbook

The typical action to utilize the remount facility is:

    $ adb root
    $ adb disable-verity
    $ adb reboot
    $ adb wait-for-device
    $ adb root
    $ adb remount

Followed by one of the following:

    $ adb stop
    $ adb sync
    $ adb start
    $ adb reboot

*or*

    $ adb push <source> <destination>
    $ adb reboot

Note that the sequence above:

    $ adb disable-verity
    $ adb reboot

*or*

    $ adb remount

can be replaced in both places with:

    $ adb remount -R

which will not reboot if everything is already prepared and ready
to go.

None of this changes if *overlayfs* needs to be engaged.
The decisions whether to use traditional direct filesystem remount,
or one wrapped by *overlayfs* is automatically determined based on
a probe of the filesystem types and space remaining.

### Backing Storage

When *overlayfs* logic is feasible, it will use either the
**/cache/overlay/** directory for non-A/B devices, or the
**/mnt/scratch/overlay** directory for A/B devices that have
access to *Logical Resizable Android Partitions*.
The backing store is used as soon as possible in the boot
process and can occur at first stage init, or at the
mount_all init rc commands.

This early as possible attachment of *overlayfs* means that
*sepolicy* or *init* itself can also be pushed and used after
the exec phases that accompany each stage.

Caveats
-------

- Space used in the backing storage is on a file by file basis
  and will require more space than if updated in place.  As such
  it is important to be mindful of any wasted space, for instance
  **BOARD_<partition>IMAGE_PARTITION_RESERVED_SIZE** being defined
  will have a negative impact on the overall right-sizing of images
  and thus free dynamic partition space.
- Kernel must have CONFIG_OVERLAY_FS=y and will need to be patched
  with "*overlayfs: override_creds=off option bypass creator_cred*"
  if kernel is 4.4 or higher.
  The patch is available on the upstream mailing list and the latest as of
  Feb 8 2019 is https://lore.kernel.org/patchwork/patch/1009299/.
  This patch adds an override_creds _mount_ option to overlayfs that
  permits legacy behavior for systems that do not have overlapping
  sepolicy rules, principals of least privilege, which is how Android behaves.
- *adb enable-verity* will free up overlayfs and as a bonus the
  device will be reverted pristine to before any content was updated.
  Update engine does not take advantage of this, will perform a full OTA.
- Update engine may not run if *fs_mgr_overlayfs_is_setup*() reports
  true as adb remount overrides are incompatible with an OTA resources.
- For implementation simplicity on retrofit dynamic partition devices,
  take the whole alternate super (eg: if "*a*" slot, then the whole of
  "*system_b*").
  Since landing a filesystem on the alternate super physical device
  without differentiating if it is setup to support logical or physical,
  the alternate slot metadata and previous content will be lost.
- If dynamic partitions runs out of space, resizing a logical
  partition larger may fail because of the scratch partition.
  If this happens, either fastboot flashall or adb enable-verity can
  be used to clear scratch storage to permit the flash.
  Then reinstate the overrides and continue.
- File bugs or submit fixes for review.
