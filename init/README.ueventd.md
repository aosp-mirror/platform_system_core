# Ueventd
-------
Ueventd manages `/dev`, sets permissions for `/sys`, and handles firmware uevents. It has default
behavior described below, along with a scripting language that allows customizing this behavior,
built on the same parser as init.

Ueventd has one generic customization parameter, the size of rcvbuf_size for the ueventd socket. It
is customized by the `uevent_socket_rcvbuf_size` parameter, which takes the format of

    uevent_socket_rcvbuf_size <size>
For example

    uevent_socket_rcvbuf_size 16M
Sets the uevent socket rcvbuf_size to 16 megabytes.

## Importing configuration files
--------------------------------
Ueventd reads /system/etc/ueventd.rc, all other files are imported via the `import` command, which
takes the format of

    import <path>
This command parses an ueventd config file, extending the current configuration.  If _path_ is a
directory, each file in the directory is parsed as a config file. It is not recursive, nested
directories will not be parsed.  Imported files are parsed after the current file has been parsed.

## /dev
----
Ueventd listens to the kernel uevent sockets and creates/deletes nodes in `/dev` based on the
incoming add/remove uevents. It defaults to using `0600` mode and `root` user/group. It always
creates the nodes with the SELabel from the current loaded SEPolicy. It has three default behaviors
for the node path:

  1. Block devices are created as `/dev/block/<basename uevent DEVPATH>`. There are symlinks created
     to this node at `/dev/block/<type>/<parent device>/<basename uevent DEVPATH>`,
     `/dev/block/<type>/<parent device>/by-name/<uevent PARTNAME>`, and `/dev/block/by-name/<uevent
     PARTNAME>` if the device is a boot device.
  2. USB devices are created as `/dev/<uevent DEVNAME>` if `DEVNAME` was specified for the uevent,
     otherwise as `/dev/bus/usb/<bus_id>/<device_id>` where `bus_id` is `uevent MINOR / 128 + 1` and
     `device_id` is `uevent MINOR % 128 + 1`.
  3. All other devices are created as `/dev/<basename uevent DEVPATH>`

The permissions can be modified using a ueventd.rc script and a line that beings with `/dev`. These
lines take the format of

    devname mode uid gid [options]
For example

    /dev/null 0666 root root
When `/dev/null` is created, its mode will be set to `0666`, its user to `root` and its group to
`root`.

The path can be modified using a ueventd.rc script and a `subsystem` section. There are three to set
for a subsystem: the subsystem name, which device name to use, and which directory to place the
device in. The section takes the below format of

    subsystem <subsystem_name>
      devname uevent_devname|uevent_devpath
      [dirname <directory>]

`subsystem_name` is used to match uevent `SUBSYSTEM` value

`devname` takes one of three options
  1. `uevent_devname` specifies that the name of the node will be the uevent `DEVNAME`
  2. `uevent_devpath` specifies that the name of the node will be basename uevent `DEVPATH`
  3. `sys_name` specifies that the name of the node will be the contents of `/sys/DEVPATH/name`

`dirname` is an optional parameter that specifies a directory within `/dev` where the node will be
created.

For example

    subsystem sound
      devname uevent_devpath
      dirname /dev/snd
Indicates that all uevents with `SUBSYSTEM=sound` will create nodes as `/dev/snd/<basename uevent
DEVPATH>`.

## /sys
----
Ueventd by default takes no action for `/sys`, however it can be instructed to set permissions for
certain files in `/sys` when matching uevents are generated. This is done using a ueventd.rc script
and a line that begins with `/sys`. These lines take the format of

    nodename attr mode uid gid [options]
For example

    /sys/devices/system/cpu/cpu* cpufreq/scaling_max_freq 0664 system system
When a uevent that matches the pattern `/sys/devices/system/cpu/cpu*` is sent, the matching sysfs
attribute, `cpufreq/scaling_max_freq`, will have its mode set to `0664`, its user to to `system` and
its group set to `system`.

## Path matching
----------------
The path for a `/dev` or `/sys` entry can contain a `*` anywhere in the path.
1. If the only `*` appears at the end of the string or if the _options_ parameter is set to
`no_fnm_pathname`, ueventd matches the entry by `fnmatch(entry_path, incoming_path, 0)`
2. Otherwise, ueventd matches the entry by `fnmatch(entry_path, incoming_path, FNM_PATHNAME)`

See the [man page for fnmatch](https://www.man7.org/linux/man-pages/man3/fnmatch.3.html) for more
details.

## Firmware loading
----------------
Ueventd by default serves firmware requests by searching through a list of firmware directories
for a file matching the uevent `FIRMWARE`. It then forks a process to serve this firmware to the
kernel.

`/apex/*/etc/firmware` is also searched after a list of firmware directories.

The list of firmware directories is customized by a `firmware_directories` line in a ueventd.rc
file. This line takes the format of

    firmware_directories <firmware_directory> [ <firmware_directory> ]*
For example

    firmware_directories /etc/firmware/ /odm/firmware/ /vendor/firmware/ /firmware/image/
Adds those 4 directories, in that order to the list of firmware directories that will be tried by
ueventd. Note that this option always accumulates to the list; it is not possible to remove previous
entries.

Ueventd will wait until after `post-fs` in init, to keep retrying before believing the firmwares are
not present.

The exact firmware file to be served can be customized by running an external program by a
`external_firmware_handler` line in a ueventd.rc file. This line takes the format of

    external_firmware_handler <devpath> <user [group]> <path to external program>

The handler will be run as the given user, or if a group is provided, as the given user and group.

For example

    external_firmware_handler /devices/leds/red/firmware/coeffs.bin system /vendor/bin/led_coeffs.bin
Will launch `/vendor/bin/led_coeffs.bin` as the system user instead of serving the default firmware
for `/devices/leds/red/firmware/coeffs.bin`.

The `devpath` argument may include asterisks (`*`) to match multiple paths. For example, the string
`/dev/*/red` will match `/dev/leds/red` as well as `/dev/lights/red`. The pattern matching follows
the rules of the fnmatch() function.

Ueventd will provide the uevent `DEVPATH` and `FIRMWARE` to this external program on the environment
via environment variables with the same names. Ueventd will use the string written to stdout as the
new name of the firmware to load. It will still look for the new firmware in the list of firmware
directories stated above. It will also reject file names with `..` in them, to prevent leaving these
directories. If stdout cannot be read, or the program returns with any exit code other than
`EXIT_SUCCESS`, or the program crashes, the default firmware from the uevent will be loaded.

Ueventd will additionally log all messages sent to stderr from the external program to the serial
console after the external program has exited.

If the kernel command-line argument `firmware_class.path` is set, this path
will be used first by the kernel to search for the firmware files. If found,
ueventd will not be called at all. See the
[kernel documentation](https://www.kernel.org/doc/html/v5.10/driver-api/firmware/fw_search_path.html)
for more details on this feature.

## Coldboot
--------
Ueventd must create devices in `/dev` for all devices that have already sent their uevents before
ueventd has started. To do so, when ueventd is started it does what it calls a 'coldboot' on `/sys`,
in which it writes 'add' to every 'uevent' file that it finds in `/sys/class`, `/sys/block`, and
`/sys/devices`. This causes the kernel to regenerate the uevents for these paths, and thus for
ueventd to create the nodes.

For boot time purposes, this is done in parallel across a set of child processes. `ueventd.cpp` in
this directory contains documentation on how the parallelization is done.

There is an option to parallelize the restorecon function during cold boot as well. It is
recommended that devices use genfscon for labeling sysfs nodes. However, some devices may benefit
from enabling the parallelization option:

    parallel_restorecon enabled

Do parallel restorecon to speed up boot process, subdirectories under `/sys`
can be sliced by ueventd.rc, and run on multiple process.
    parallel_restorecon_dir <directory>

For example
    parallel_restorecon_dir /sys
    parallel_restorecon_dir /sys/devices
    parallel_restorecon_dir /sys/devices/platform
    parallel_restorecon_dir /sys/devices/platform/soc
