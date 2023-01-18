libfiemap
=============

`libfiemap` is a library for creating block-devices that are backed by
storage in read-write partitions. It exists primary for gsid. Generally, the
library works by using `libfiemap_writer` to allocate large files within
filesystem, and then tracks their extents.

There are three main uses for `libfiemap`:
 - Creating images that will act as block devices. For example, gsid needs to
   create a `system_gsi` image to store Dynamic System Updates.
 - Mapping the image as a block device while /data is mounted. This is fairly
   tricky and is described in more detail below.
 - Mapping the image as a block device during first-stage init. This is simple
   because it uses the same logic from dynamic partitions.

Image creation is done through `SplitFiemap`. Depending on the file system,
a large image may have to be split into multiple files. On Ext4 the limit is
16GiB and on FAT32 it's 4GiB. Images are saved into `/data/gsi/<name>/`
where `<name>` is chosen by the process requesting the image.

At the same time, a file called `/metadata/gsi/<name>/lp_metadata` is created.
This is a super partition header that allows first-stage init to create dynamic
partitions from the image files. It also tracks the canonical size of the image,
since the file size may be larger due to alignment.

Mapping
-------

It is easy to make block devices out of blocks on `/data` when it is not
mounted, so first-stage init has no issues mapping dynamic partitions from
images. After `/data` is mounted however, there are two problems:
 - `/data` is encrypted.
 - `/dev/block/by-name/data` may be marked as in-use.

We break the problem down into three scenarios.

### Metadata Encrypted Devices

When metadata encryption is used, `/data` is not mounted from
`/dev/block/by-name/data`. Instead, it is mounted from an intermediate
`dm-default-key` device. This means the underlying device is not marked in use,
and we can create new dm-linear devices on top of it.

On these devices, a block device for an image will consist of a single
device-mapper device with a `dm-linear` table entry for each extent in the
backing file.

### Unencrypted and FBE-only Devices

When a device is unencrypted, or is encrypted with FBE but not metadata
encryption, we instead use a loop device with `LOOP_SET_DIRECT_IO` enabled.
Since `/data/gsi` has encryption disabled, this means the raw blocks will be
unencrypted as well.

### Split Images

If an image was too large to store a single file on the underlying filesystem,
on an FBE/unencrypted device we will have multiple loop devices. In this case,
we create a device-mapper device as well. For each loop device it will have one
`dm-linear` table entry spanning the length of the device.

State Tracking
--------------

It's important that we know whether or not an image is currently in-use by a
block device. It could be catastrophic to write to a dm-linear device if the
underlying blocks are no longer owned by the original file. Thus, when mapping
an image, we create a property called `gsid.mapped_image.<name>` and set it to
the path of the block device.

Additionally, we create a `/metadata/gsi/<subdir>/<name>.status` file. Each
line in this file denotes a dependency on either a device-mapper node or a loop
device. When deleting a block device, this file is used to release all
resources.
