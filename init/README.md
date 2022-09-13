Android Init Language
---------------------

The Android Init Language consists of five broad classes of statements:
Actions, Commands, Services, Options, and Imports.

All of these are line-oriented, consisting of tokens separated by
whitespace.  The c-style backslash escapes may be used to insert
whitespace into a token.  Double quotes may also be used to prevent
whitespace from breaking text into multiple tokens.  The backslash,
when it is the last character on a line, may be used for line-folding.

Lines which start with a `#` (leading whitespace allowed) are comments.

System properties can be expanded using the syntax
`${property.name}`. This also works in contexts where concatenation is
required, such as `import /init.recovery.${ro.hardware}.rc`.

Actions and Services implicitly declare a new section.  All commands
or options belong to the section most recently declared.  Commands
or options before the first section are ignored.

Services have unique names.  If a second Service is defined
with the same name as an existing one, it is ignored and an error
message is logged.


Init .rc Files
--------------
The init language is used in plain text files that take the .rc file
extension.  There are typically multiple of these in multiple
locations on the system, described below.

`/system/etc/init/hw/init.rc` is the primary .rc file and is loaded by the init executable at the
beginning of its execution.  It is responsible for the initial set up of the system.

Init loads all of the files contained within the
`/{system,system_ext,vendor,odm,product}/etc/init/` directories immediately after loading
the primary `/system/etc/init/hw/init.rc`.  This is explained in more details in the
[Imports](#imports) section of this file.

Legacy devices without the first stage mount mechanism previously were
able to import init scripts during mount_all, however that is deprecated
and not allowed for devices launching after Q.

The intention of these directories is:

   1. /system/etc/init/ is for core system items such as
      SurfaceFlinger, MediaService, and logd.
   2. /vendor/etc/init/ is for SoC vendor items such as actions or
      daemons needed for core SoC functionality.
   3. /odm/etc/init/ is for device manufacturer items such as
      actions or daemons needed for motion sensor or other peripheral
      functionality.

All services whose binaries reside on the system, vendor, or odm
partitions should have their service entries placed into a
corresponding init .rc file, located in the /etc/init/
directory of the partition where they reside.  There is a build
system macro, LOCAL\_INIT\_RC, that handles this for developers.  Each
init .rc file should additionally contain any actions associated with
its service.

An example is the userdebug logcatd.rc and Android.mk files located in the
system/core/logcat directory.  The LOCAL\_INIT\_RC macro in the
Android.mk file places logcatd.rc in /system/etc/init/ during the
build process.  Init loads logcatd.rc during the mount\_all command and
allows the service to be run and the action to be queued when
appropriate.

This break up of init .rc files according to their daemon is preferred
to the previously used monolithic init .rc files.  This approach
ensures that the only service entries that init reads and the only
actions that init performs correspond to services whose binaries are in
fact present on the file system, which was not the case with the
monolithic init .rc files.  This additionally will aid in merge
conflict resolution when multiple services are added to the system, as
each one will go into a separate file.

Versioned RC files within APEXs
-------------------------------

With the arrival of mainline on Android Q, the individual mainline
modules carry their own init.rc files within their boundaries. Init
processes these files according to the naming pattern `/apex/*/etc/*rc`.

Because APEX modules must run on more than one release of Android,
they may require different parameters as part of the services they
define. This is achieved, starting in Android T, by incorporating
the SDK version information in the name of the init file.  The suffix
is changed from `.rc` to `.#rc` where # is the first SDK where that
RC file is accepted. An init file specific to SDK=31 might be named
`init.31rc`. With this scheme, an APEX may include multiple init files. An
example is appropriate.

For an APEX module with the following files in /apex/sample-module/apex/etc/:

   1. init.rc
   2. init.32rc
   4. init.35rc

The selection rule chooses the highest `.#rc` value that does not
exceed the SDK of the currently running system. The unadorned `.rc`
is interpreted as sdk=0.

When this APEX is installed on a device with SDK <=31, the system will
process init.rc.  When installed on a device running SDK 32, 33, or 34,
it will use init.32rc.  When installed on a device running SDKs >= 35,
it will choose init.35rc

This versioning scheme is used only for the init files within APEX
modules; it does not apply to the init files stored in /system/etc/init,
/vendor/etc/init, or other directories.

This naming scheme is available after Android S.

Actions
-------
Actions are named sequences of commands.  Actions have a trigger which
is used to determine when the action is executed.  When an event
occurs which matches an action's trigger, that action is added to
the tail of a to-be-executed queue (unless it is already on the
queue).

Each action in the queue is dequeued in sequence and each command in
that action is executed in sequence.  Init handles other activities
(device creation/destruction, property setting, process restarting)
"between" the execution of the commands in activities.

Actions take the form of:

    on <trigger> [&& <trigger>]*
       <command>
       <command>
       <command>

Actions are added to the queue and executed based on the order that
the file that contains them was parsed (see the Imports section), then
sequentially within an individual file.

For example if a file contains:

    on boot
       setprop a 1
       setprop b 2

    on boot && property:true=true
       setprop c 1
       setprop d 2

    on boot
       setprop e 1
       setprop f 2

Then when the `boot` trigger occurs and assuming the property `true`
equals `true`, then the order of the commands executed will be:

    setprop a 1
    setprop b 2
    setprop c 1
    setprop d 2
    setprop e 1
    setprop f 2


Services
--------
Services are programs which init launches and (optionally) restarts
when they exit.  Services take the form of:

    service <name> <pathname> [ <argument> ]*
       <option>
       <option>
       ...


Options
-------
Options are modifiers to services.  They affect how and when init
runs the service.

`capabilities [ <capability>\* ]`
> Set capabilities when exec'ing this service. 'capability' should be a Linux
  capability without the "CAP\_" prefix, like "NET\_ADMIN" or "SETPCAP". See
  http://man7.org/linux/man-pages/man7/capabilities.7.html for a list of Linux
  capabilities.
  If no capabilities are provided, then all capabilities are removed from this service, even if it
  runs as root.

`class <name> [ <name>\* ]`
> Specify class names for the service.  All services in a
  named class may be started or stopped together.  A service
  is in the class "default" if one is not specified via the
  class option. Additional classnames beyond the (required) first
  one are used to group services.
  The `animation` class should include all services necessary for both
  boot animation and shutdown animation. As these services can be
  launched very early during bootup and can run until the last stage
  of shutdown, access to /data partition is not guaranteed. These
  services can check files under /data but it should not keep files opened
  and should work when /data is not available.

`console [<console>]`
> This service needs a console. The optional second parameter chooses a
  specific console instead of the default. The default "/dev/console" can
  be changed by setting the "androidboot.console" kernel parameter. In
  all cases the leading "/dev/" should be omitted, so "/dev/tty0" would be
  specified as just "console tty0".
  This option connects stdin, stdout, and stderr to the console. It is mutually exclusive with the
  stdio_to_kmsg option, which only connects stdout and stderr to kmsg.

`critical [window=<fatal crash window mins>] [target=<fatal reboot target>]`
> This is a device-critical service. If it exits more than four times in
  _fatal crash window mins_ minutes or before boot completes, the device
  will reboot into _fatal reboot target_.
  The default value of _fatal crash window mins_ is 4, and default value
  of _fatal reboot target_ is 'bootloader'.
  For tests, the fatal reboot can be skipped by setting property
  `init.svc_debug.no_fatal.<service-name>` to `true` for specified critical service.

`disabled`
> This service will not automatically start with its class.
  It must be explicitly started by name or by interface name.

`enter_namespace <type> <path>`
> Enters the namespace of type _type_ located at _path_. Only network namespaces are supported with
  _type_ set to "net". Note that only one namespace of a given _type_ may be entered.

`file <path> <type>`
> Open a file path and pass its fd to the launched process. _type_ must be
  "r", "w" or "rw".  For native executables see libcutils
  android\_get\_control\_file().

`group <groupname> [ <groupname>\* ]`
> Change to 'groupname' before exec'ing this service.  Additional
  groupnames beyond the (required) first one are used to set the
  supplemental groups of the process (via setgroups()).
  Currently defaults to root.  (??? probably should default to nobody)

`interface <interface name> <instance name>`
> Associates this service with a list of the AIDL or HIDL services that it provides. The interface
  name must be a fully-qualified name and not a value name. For instance, this is used to allow
  servicemanager or hwservicemanager to lazily start services. When multiple interfaces are served,
  this tag should be used multiple times. An example of an entry for a HIDL
  interface is `interface vendor.foo.bar@1.0::IBaz default`. For an AIDL interface, use
  `interface aidl <instance name>`. The instance name for an AIDL interface is
  whatever is registered with servicemanager, and these can be listed with `adb
  shell dumpsys -l`.

`ioprio <class> <priority>`
> Sets the IO priority and IO priority class for this service via the SYS_ioprio_set syscall.
  _class_ must be one of "rt", "be", or "idle". _priority_ must be an integer in the range 0 - 7.

`keycodes <keycode> [ <keycode>\* ]`
> Sets the keycodes that will trigger this service. If all of the keys corresponding to the passed
  keycodes are pressed at once, the service will start. This is typically used to start the
  bugreport service.

> This option may take a property instead of a list of keycodes. In this case, only one option is
  provided: the property name in the typical property expansion format. The property must contain
  a comma separated list of keycode values or the text 'none' to indicate that
  this service does not respond to keycodes.

> For example, `keycodes ${some.property.name:-none}` where some.property.name expands
  to "123,124,125". Since keycodes are handled very early in init,
  only PRODUCT_DEFAULT_PROPERTY_OVERRIDES properties can be used.

`memcg.limit_in_bytes <value>` and `memcg.limit_percent <value>`
> Sets the child's memory.limit_in_bytes to the minimum of `limit_in_bytes`
  bytes and `limit_percent` which is interpreted as a percentage of the size
  of the device's physical memory (only if memcg is mounted).
  Values must be equal or greater than 0.

`memcg.limit_property <value>`
> Sets the child's memory.limit_in_bytes to the value of the specified property
  (only if memcg is mounted). This property will override the values specified
  via `memcg.limit_in_bytes` and `memcg.limit_percent`.

`memcg.soft_limit_in_bytes <value>`
> Sets the child's memory.soft_limit_in_bytes to the specified value (only if memcg is mounted),
  which must be equal or greater than 0.

`memcg.swappiness <value>`
> Sets the child's memory.swappiness to the specified value (only if memcg is mounted),
  which must be equal or greater than 0.

`namespace <pid|mnt>`
> Enter a new PID or mount namespace when forking the service.

`oneshot`
> Do not restart the service when it exits.

`onrestart`
> Execute a Command (see below) when service restarts.

`oom_score_adjust <value>`
> Sets the child's /proc/self/oom\_score\_adj to the specified value,
  which must range from -1000 to 1000.

`override`
> Indicates that this service definition is meant to override a previous definition for a service
  with the same name. This is typically meant for services on /odm to override those defined on
  /vendor. The last service definition that init parses with this keyword is the service definition
  will use for this service. Pay close attention to the order in which init.rc files are parsed,
  since it has some peculiarities for backwards compatibility reasons. The 'imports' section of
  this file has more details on the order.

`priority <priority>`
> Scheduling priority of the service process. This value has to be in range
  -20 to 19. Default priority is 0. Priority is set via setpriority().

`reboot_on_failure <target>`
> If this process cannot be started or if the process terminates with an exit code other than
  CLD_EXITED or an status other than '0', reboot the system with the target specified in
  _target_. _target_ takes the same format as the parameter to sys.powerctl. This is particularly
  intended to be used with the `exec_start` builtin for any must-have checks during boot.

`restart_period <seconds>`
> If a non-oneshot service exits, it will be restarted at its start time plus
  this period. It defaults to 5s to rate limit crashing services.
  This can be increased for services that are meant to run periodically. For
  example, it may be set to 3600 to indicate that the service should run every hour
  or 86400 to indicate that the service should run every day.

`rlimit <resource> <cur> <max>`
> This applies the given rlimit to the service. rlimits are inherited by child
  processes, so this effectively applies the given rlimit to the process tree
  started by this service.
  It is parsed similarly to the setrlimit command specified below.

`seclabel <seclabel>`
> Change to 'seclabel' before exec'ing this service.
  Primarily for use by services run from the rootfs, e.g. ueventd, adbd.
  Services on the system partition can instead use policy-defined transitions
  based on their file security context.
  If not specified and no transition is defined in policy, defaults to the init context.

`setenv <name> <value>`
> Set the environment variable _name_ to _value_ in the launched process.

`shutdown <shutdown_behavior>`
> Set shutdown behavior of the service process. When this is not specified,
  the service is killed during shutdown process by using SIGTERM and SIGKILL.
  The service with shutdown_behavior of "critical" is not killed during shutdown
  until shutdown times out. When shutdown times out, even services tagged with
  "shutdown critical" will be killed. When the service tagged with "shutdown critical"
  is not running when shut down starts, it will be started.

`sigstop`
> Send SIGSTOP to the service immediately before exec is called. This is intended for debugging.
  See the below section on debugging for how this can be used.

`socket <name> <type> <perm> [ <user> [ <group> [ <seclabel> ] ] ]`
> Create a UNIX domain socket named /dev/socket/_name_ and pass its fd to the
  launched process.  The socket is created synchronously when the service starts.
  _type_ must be "dgram", "stream" or "seqpacket".  _type_ may end with "+passcred"
  to enable SO_PASSCRED on the socket or "+listen" to synchronously make it a listening socket.
  User and group default to 0.  'seclabel' is the SELinux security context for the
  socket.  It defaults to the service security context, as specified by
  seclabel or computed based on the service executable file security context.
  For native executables see libcutils android\_get\_control\_socket().

`stdio_to_kmsg`
> Redirect stdout and stderr to /dev/kmsg_debug. This is useful for services that do not use native
  Android logging during early boot and whose logs messages we want to capture. This is only enabled
  when /dev/kmsg_debug is enabled, which is only enabled on userdebug and eng builds.
  This is mutually exclusive with the console option, which additionally connects stdin to the
  given console.

`task_profiles <profile> [ <profile>\* ]`
> Set task profiles for the process when it forks. This is designed to replace the use of
  writepid option for moving a process into a cgroup.

`timeout_period <seconds>`
> Provide a timeout after which point the service will be killed. The oneshot keyword is respected
  here, so oneshot services do not automatically restart, however all other services will.
  This is particularly useful for creating a periodic service combined with the restart_period
  option described above.

`updatable`
> Mark that the service can be overridden (via the 'override' option) later in
  the boot sequence by APEXes. When a service with updatable option is started
  before APEXes are all activated, the execution is delayed until the activation
  is finished. A service that is not marked as updatable cannot be overridden by
  APEXes.

`user <username>`
> Change to 'username' before exec'ing this service.
  Currently defaults to root.  (??? probably should default to nobody)
  As of Android M, processes should use this option even if they
  require Linux capabilities.  Previously, to acquire Linux
  capabilities, a process would need to run as root, request the
  capabilities, then drop to its desired uid.  There is a new
  mechanism through fs\_config that allows device manufacturers to add
  Linux capabilities to specific binaries on a file system that should
  be used instead. This mechanism is described on
  <http://source.android.com/devices/tech/config/filesystem.html>.  When
  using this new mechanism, processes can use the user option to
  select their desired uid without ever running as root.
  As of Android O, processes can also request capabilities directly in their .rc
  files. See the "capabilities" option below.

`writepid <file> [ <file>\* ]`
> Write the child's pid to the given files when it forks. Meant for
  cgroup/cpuset usage. If no files under /dev/cpuset/ are specified, but the
  system property 'ro.cpuset.default' is set to a non-empty cpuset name (e.g.
  '/foreground'), then the pid is written to file /dev/cpuset/_cpuset\_name_/tasks.
  The use of this option for moving a process into a cgroup is obsolete. Please
  use task_profiles option instead.


Triggers
--------
Triggers are strings which can be used to match certain kinds of
events and used to cause an action to occur.

Triggers are subdivided into event triggers and property triggers.

Event triggers are strings triggered by the 'trigger' command or by
the QueueEventTrigger() function within the init executable.  These
take the form of a simple string such as 'boot' or 'late-init'.

Property triggers are strings triggered when a named property changes
value to a given new value or when a named property changes value to
any new value.  These take the form of 'property:<name>=<value>' and
'property:<name>=\*' respectively.  Property triggers are additionally
evaluated and triggered accordingly during the initial boot phase of
init.

An Action can have multiple property triggers but may only have one
event trigger.

For example:
`on boot && property:a=b` defines an action that is only executed when
the 'boot' event trigger happens and the property a equals b.

`on property:a=b && property:c=d` defines an action that is executed
at three times:

   1. During initial boot if property a=b and property c=d.
   2. Any time that property a transitions to value b, while property c already equals d.
   3. Any time that property c transitions to value d, while property a already equals b.


Trigger Sequence
----------------

Init uses the following sequence of triggers during early boot. These are the
built-in triggers defined in init.cpp.

   1. `early-init` - The first in the sequence, triggered after cgroups has been configured
      but before ueventd's coldboot is complete.
   2. `init` - Triggered after coldboot is complete.
   3. `charger` - Triggered if `ro.bootmode == "charger"`.
   4. `late-init` - Triggered if `ro.bootmode != "charger"`, or via healthd triggering a boot
      from charging mode.

Remaining triggers are configured in `init.rc` and are not built-in. The default sequence for
these is specified under the "on late-init" event in `init.rc`. Actions internal to `init.rc`
have been omitted.

   1. `early-fs` - Start vold.
   2. `fs` - Vold is up. Mount partitions not marked as first-stage or latemounted.
   3. `post-fs` - Configure anything dependent on early mounts.
   4. `late-fs` - Mount partitions marked as latemounted.
   5. `post-fs-data` - Mount and configure `/data`; set up encryption. `/metadata` is
      reformatted here if it couldn't mount in first-stage init.
   6. `zygote-start` - Start the zygote.
   7. `early-boot` - After zygote has started.
   8. `boot` - After `early-boot` actions have completed.

Commands
--------

`bootchart [start|stop]`
> Start/stop bootcharting. These are present in the default init.rc files,
  but bootcharting is only active if the file /data/bootchart/enabled exists;
  otherwise bootchart start/stop are no-ops.

`chmod <octal-mode> <path>`
> Change file access permissions.

`chown <owner> <group> <path>`
> Change file owner and group.

`class_start <serviceclass>`
> Start all services of the specified class if they are
  not already running.  See the start entry for more information on
  starting services.

`class_stop <serviceclass>`
> Stop and disable all services of the specified class if they are
  currently running.

`class_reset <serviceclass>`
> Stop all services of the specified class if they are
  currently running, without disabling them. They can be restarted
  later using `class_start`.

`class_restart [--only-enabled] <serviceclass>`
> Restarts all services of the specified class. If `--only-enabled` is
  specified, then disabled services are skipped.

`copy <src> <dst>`
> Copies a file. Similar to write, but useful for binary/large
  amounts of data.
  Regarding to the src file, copying from symbolic link file and world-writable
  or group-writable files are not allowed.
  Regarding to the dst file, the default mode created is 0600 if it does not
  exist. And it will be truncated if dst file is a normal regular file and
  already exists.

`copy_per_line <src> <dst>`
> Copies a file line by line. Similar to copy, but useful for dst is a sysfs node
  that doesn't handle multiple lines of data.

`domainname <name>`
> Set the domain name.

`enable <servicename>`
> Turns a disabled service into an enabled one as if the service did not
  specify disabled.
  If the service is supposed to be running, it will be started now.
  Typically used when the bootloader sets a variable that indicates a specific
  service should be started when needed. E.g.

    on property:ro.boot.myfancyhardware=1
        enable my_fancy_service_for_my_fancy_hardware

`exec [ <seclabel> [ <user> [ <group>\* ] ] ] -- <command> [ <argument>\* ]`
> Fork and execute command with the given arguments. The command starts
  after "--" so that an optional security context, user, and supplementary
  groups can be provided. No other commands will be run until this one
  finishes. _seclabel_ can be a - to denote default. Properties are expanded
  within _argument_.
  Init halts executing commands until the forked process exits.

`exec_background [ <seclabel> [ <user> [ <group>\* ] ] ] -- <command> [ <argument>\* ]`
> Fork and execute command with the given arguments. This is handled similarly
  to the `exec` command. The difference is that init does not halt executing
  commands until the process exits for `exec_background`.

`exec_start <service>`
> Start a given service and halt the processing of additional init commands
  until it returns.  The command functions similarly to the `exec` command,
  but uses an existing service definition in place of the exec argument vector.

`export <name> <value>`
> Set the environment variable _name_ equal to _value_ in the
  global environment (which will be inherited by all processes
  started after this command is executed)

`hostname <name>`
> Set the host name.

`ifup <interface>`
> Bring the network interface _interface_ online.

`insmod [-f] <path> [<options>]`
> Install the module at _path_ with the specified options.
  -f: force installation of the module even if the version of the running kernel
  and the version of the kernel for which the module was compiled do not match.

`interface_start <name>` \
`interface_restart <name>` \
`interface_stop <name>`
> Find the service that provides the interface _name_ if it exists and run the `start`, `restart`,
or `stop` commands on it respectively.  _name_ may be either a fully qualified HIDL name, in which
case it is specified as `<interface>/<instance>`, or an AIDL name, in which case it is specified as
`aidl/<interface>` for example `android.hardware.secure_element@1.1::ISecureElement/eSE1` or
`aidl/aidl_lazy_test_1`.

> Note that these commands only act on interfaces specified by the `interface` service option, not
on interfaces registered at runtime.

> Example usage of these commands: \
`interface_start android.hardware.secure_element@1.1::ISecureElement/eSE1`
will start the HIDL Service that provides the `android.hardware.secure_element@1.1` and `eSI1`
instance. \
`interface_start aidl/aidl_lazy_test_1` will start the AIDL service that
provides the `aidl_lazy_test_1` interface.

`load_exports <path>`
> Open the file at _path_ and export global environment variables declared
  there. Each line must be in the format `export <name> <value>`, as described
  above.

`load_system_props`
> (This action is deprecated and no-op.)

`load_persist_props`
> Loads persistent properties when /data has been decrypted.
  This is included in the default init.rc.

`loglevel <level>`
> Sets init's log level to the integer level, from 7 (all logging) to 0
  (fatal logging only). The numeric values correspond to the kernel log
  levels, but this command does not affect the kernel log level. Use the
  `write` command to write to `/proc/sys/kernel/printk` to change that.
  Properties are expanded within _level_.

`mark_post_data`
> Used to mark the point right after /data is mounted.

`mkdir <path> [<mode>] [<owner>] [<group>] [encryption=<action>] [key=<key>]`
> Create a directory at _path_, optionally with the given mode, owner, and
  group. If not provided, the directory is created with permissions 755 and
  owned by the root user and root group. If provided, the mode, owner and group
  will be updated if the directory exists already.
  If the directory does not exist, it will receive the security context from
  the current SELinux policy or its parent if not specified in the policy. If
  the directory exists, its security context will not be changed (even if
  different from the policy).

  > _action_ can be one of:
  * `None`: take no encryption action; directory will be encrypted if parent is.
  * `Require`: encrypt directory, abort boot process if encryption fails
  * `Attempt`: try to set an encryption policy, but continue if it fails
  * `DeleteIfNecessary`: recursively delete directory if necessary to set
  encryption policy.

  > _key_ can be one of:
  * `ref`: use the systemwide DE key
  * `per_boot_ref`: use the key freshly generated on each boot.

`mount_all [ <fstab> ] [--<option>]`
> Calls fs\_mgr\_mount\_all on the given fs\_mgr-format fstab with optional
  options "early" and "late".
  With "--early" set, the init executable will skip mounting entries with
  "latemount" flag and triggering fs encryption state event. With "--late" set,
  init executable will only mount entries with "latemount" flag. By default,
  no option is set, and mount\_all will process all entries in the given fstab.
  If the fstab parameter is not specified, fstab.${ro.boot.fstab_suffix},
  fstab.${ro.hardware} or fstab.${ro.hardware.platform} will be scanned for
  under /odm/etc, /vendor/etc, or / at runtime, in that order.

`mount <type> <device> <dir> [ <flag>\* ] [<options>]`
> Attempt to mount the named device at the directory _dir_
  _flag_s include "ro", "rw", "remount", "noatime", ...
  _options_ include "barrier=1", "noauto\_da\_alloc", "discard", ... as
  a comma separated string, e.g. barrier=1,noauto\_da\_alloc

`perform_apex_config`
> Performs tasks after APEXes are mounted. For example, creates data directories
  for the mounted APEXes, parses config file(s) from them, and updates linker
  configurations. Intended to be used only once when apexd notifies the mount
  event by setting `apexd.status` to ready.

`restart [--only-if-running] <service>`
> Stops and restarts a running service, does nothing if the service is currently
  restarting, otherwise, it just starts the service. If "--only-if-running" is
  specified, the service is only restarted if it is already running.

`restorecon <path> [ <path>\* ]`
> Restore the file named by _path_ to the security context specified
  in the file\_contexts configuration.
  Not required for directories created by the init.rc as these are
  automatically labeled correctly by init.

`restorecon_recursive <path> [ <path>\* ]`
> Recursively restore the directory tree named by _path_ to the
  security contexts specified in the file\_contexts configuration.

`rm <path>`
> Calls unlink(2) on the given path. You might want to
  use "exec -- rm ..." instead (provided the system partition is
  already mounted).

`rmdir <path>`
> Calls rmdir(2) on the given path.

`readahead <file|dir> [--fully]`
> Calls readahead(2) on the file or files within given directory.
  Use option --fully to read the full file content.

`setprop <name> <value>`
> Set system property _name_ to _value_. Properties are expanded
  within _value_.

`setrlimit <resource> <cur> <max>`
> Set the rlimit for a resource. This applies to all processes launched after
  the limit is set. It is intended to be set early in init and applied globally.
  _resource_ is best specified using its text representation ('cpu', 'rtio', etc
  or 'RLIM_CPU', 'RLIM_RTIO', etc). It also may be specified as the int value
  that the resource enum corresponds to.
  _cur_ and _max_ can be 'unlimited' or '-1' to indicate an infinite rlimit.

`start <service>`
> Start a service running if it is not already running.
  Note that this is _not_ synchronous, and even if it were, there is
  no guarantee that the operating system's scheduler will execute the
  service sufficiently to guarantee anything about the service's status.
  See the `exec_start` command for a synchronous version of `start`.

> This creates an important consequence that if the service offers
  functionality to other services, such as providing a
  communication channel, simply starting this service before those
  services is _not_ sufficient to guarantee that the channel has
  been set up before those services ask for it.  There must be a
  separate mechanism to make any such guarantees.

`stop <service>`
> Stop a service from running if it is currently running.

`swapon_all [ <fstab> ]`
> Calls fs\_mgr\_swapon\_all on the given fstab file.
  If the fstab parameter is not specified, fstab.${ro.boot.fstab_suffix},
  fstab.${ro.hardware} or fstab.${ro.hardware.platform} will be scanned for
  under /odm/etc, /vendor/etc, or / at runtime, in that order.

`symlink <target> <path>`
> Create a symbolic link at _path_ with the value _target_

`sysclktz <minutes_west_of_gmt>`
> Set the system clock base (0 if system clock ticks in GMT)

`trigger <event>`
> Trigger an event.  Used to queue an action from another
  action.

`umount <path>`
> Unmount the filesystem mounted at that path.

`umount_all [ <fstab> ]`
> Calls fs\_mgr\_umount\_all on the given fstab file.
  If the fstab parameter is not specified, fstab.${ro.boot.fstab_suffix},
  fstab.${ro.hardware} or fstab.${ro.hardware.platform} will be scanned for
  under /odm/etc, /vendor/etc, or / at runtime, in that order.

`verity_update_state`
> Internal implementation detail used to update dm-verity state and
  set the partition._mount-point_.verified properties used by adb remount
  because fs\_mgr can't set them directly itself. This is required since
  Android 12, because CtsNativeVerifiedBootTestCases will read property
  "partition.${partition}.verified.hash_alg" to check that sha1 is not used.
  See https://r.android.com/1546980 for more details.

`wait <path> [ <timeout> ]`
> Poll for the existence of the given file and return when found,
  or the timeout has been reached. If timeout is not specified it
  currently defaults to five seconds. The timeout value can be
  fractional seconds, specified in floating point notation.

`wait_for_prop <name> <value>`
> Wait for system property _name_ to be _value_. Properties are expanded
  within _value_. If property _name_ is already set to _value_, continue
  immediately.

`write <path> <content>`
> Open the file at _path_ and write a string to it with write(2).
  If the file does not exist, it will be created. If it does exist,
  it will be truncated. Properties are expanded within _content_.


Imports
-------
`import <path>`
> Parse an init config file, extending the current configuration.
  If _path_ is a directory, each file in the directory is parsed as
  a config file. It is not recursive, nested directories will
  not be parsed.

The import keyword is not a command, but rather its own section,
meaning that it does not happen as part of an Action, but rather,
imports are handled as a file is being parsed and follow the below logic.

There are only three times where the init executable imports .rc files:

   1. When it imports `/system/etc/init/hw/init.rc` or the script indicated by the property
      `ro.boot.init_rc` during initial boot.
   2. When it imports `/{system,system_ext,vendor,odm,product}/etc/init/` immediately after
      importing `/system/etc/init/hw/init.rc`.
   3. (Deprecated) When it imports /{system,vendor,odm}/etc/init/ or .rc files
      at specified paths during mount_all, not allowed for devices launching
      after Q.

The order that files are imported is a bit complex for legacy reasons.  The below is guaranteed:

1. `/system/etc/init/hw/init.rc` is parsed then recursively each of its imports are
   parsed.
2. The contents of `/system/etc/init/` are alphabetized and parsed sequentially, with imports
   happening recursively after each file is parsed.
3. Step 2 is repeated for `/system_ext/etc/init`, `/vendor/etc/init`, `/odm/etc/init`,
   `/product/etc/init`

The below pseudocode may explain this more clearly:

    fn Import(file)
      Parse(file)
      for (import : file.imports)
        Import(import)

    Import(/system/etc/init/hw/init.rc)
    Directories = [/system/etc/init, /system_ext/etc/init, /vendor/etc/init, /odm/etc/init, /product/etc/init]
    for (directory : Directories)
      files = <Alphabetical order of directory's contents>
      for (file : files)
        Import(file)

Actions are executed in the order that they are parsed.  For example the `post-fs-data` action(s)
in `/system/etc/init/hw/init.rc` are always the first `post-fs-data` action(s) to be executed in
order of how they appear in that file.  Then the `post-fs-data` actions of the imports of
`/system/etc/init/hw/init.rc` in the order that they're imported, etc.

Properties
----------
Init provides state information with the following properties.

`init.svc.<name>`
> State of a named service ("stopped", "stopping", "running", "restarting")

`dev.mnt.dev.<mount_point>`, `dev.mnt.blk.<mount_point>`, `dev.mnt.rootdisk.<mount_point>`
> Block device base name associated with a *mount_point*.
  The *mount_point* has / replaced by . and if referencing the root mount point
  "/", it will use "/root".
  `dev.mnt.dev.<mount_point>` indicates a block device attached to filesystems.
    (e.g., dm-N or sdaN/mmcblk0pN to access `/sys/fs/ext4/${dev.mnt.dev.<mount_point>}/`)

  `dev.mnt.blk.<mount_point>` indicates the disk partition to the above block device.
    (e.g., sdaN / mmcblk0pN to access `/sys/class/block/${dev.mnt.blk.<mount_point>}/`)

  `dev.mnt.rootdisk.<mount_point>` indicates the root disk to contain the above disk partition.
    (e.g., sda / mmcblk0 to access `/sys/class/block/${dev.mnt.rootdisk.<mount_point>}/queue`)

Init responds to properties that begin with `ctl.`.  These properties take the format of
`ctl.[<target>_]<command>` and the _value_ of the system property is used as a parameter.  The
_target_ is optional and specifies the service option that _value_ is meant to match with.  There is
only one option for _target_, `interface` which indicates that _value_ will refer to an interface
that a service provides and not the service name itself.

For example:

`SetProperty("ctl.start", "logd")` will run the `start` command on `logd`.

`SetProperty("ctl.interface_start", "aidl/aidl_lazy_test_1")` will run the `start` command on the
service that exposes the `aidl aidl_lazy_test_1` interface.

Note that these
properties are only settable; they will have no value when read.

The _commands_ are listed below.

`start` \
`restart` \
`stop` \
These are equivalent to using the `start`, `restart`, and `stop` commands on the service specified
by the _value_ of the property.

`oneshot_on` and `oneshot_off` will turn on or off the _oneshot_
flag for the service specified by the _value_ of the property.  This is
particularly intended for services that are conditionally lazy HALs.  When
they are lazy HALs, oneshot must be on, otherwise oneshot should be off.

`sigstop_on` and `sigstop_off` will turn on or off the _sigstop_ feature for the service
specified by the _value_ of the property.  See the _Debugging init_ section below for more details
about this feature.

Boot timing
-----------
Init records some boot timing information in system properties.

`ro.boottime.init`
> Time after boot in ns (via the CLOCK\_BOOTTIME clock) at which the first
  stage of init started.

`ro.boottime.init.first_stage`
> How long in ns it took to run first stage.

`ro.boottime.init.selinux`
> How long in ns it took to run SELinux stage.

`ro.boottime.init.modules`
> How long in ms it took to load kernel modules.

`ro.boottime.init.cold_boot_wait`
> How long init waited for ueventd's coldboot phase to end.

`ro.boottime.<service-name>`
> Time after boot in ns (via the CLOCK\_BOOTTIME clock) that the service was
  first started.


Bootcharting
------------
This version of init contains code to perform "bootcharting": generating log
files that can be later processed by the tools provided by <http://www.bootchart.org/>.

On the emulator, use the -bootchart _timeout_ option to boot with bootcharting
activated for _timeout_ seconds.

On a device:

    adb shell 'touch /data/bootchart/enabled'

Don't forget to delete this file when you're done collecting data!

The log files are written to /data/bootchart/. A script is provided to
retrieve them and create a bootchart.tgz file that can be used with the
bootchart command-line utility:

    sudo apt-get install pybootchartgui
    # grab-bootchart.sh uses $ANDROID_SERIAL.
    $ANDROID_BUILD_TOP/system/core/init/grab-bootchart.sh

One thing to watch for is that the bootchart will show init as if it started
running at 0s. You'll have to look at dmesg to work out when the kernel
actually started init.


Comparing two bootcharts
------------------------
A handy script named compare-bootcharts.py can be used to compare the
start/end time of selected processes. The aforementioned grab-bootchart.sh
will leave a bootchart tarball named bootchart.tgz at /tmp/android-bootchart.
If two such tarballs are preserved on the host machine under different
directories, the script can list the timestamps differences. For example:

Usage: system/core/init/compare-bootcharts.py _base-bootchart-dir_ _exp-bootchart-dir_

    process: baseline experiment (delta) - Unit is ms (a jiffy is 10 ms on the system)
    ------------------------------------
    /init: 50 40 (-10)
    /system/bin/surfaceflinger: 4320 4470 (+150)
    /system/bin/bootanimation: 6980 6990 (+10)
    zygote64: 10410 10640 (+230)
    zygote: 10410 10640 (+230)
    system_server: 15350 15150 (-200)
    bootanimation ends at: 33790 31230 (-2560)


Systrace
--------
Systrace (<http://developer.android.com/tools/help/systrace.html>) can be
used for obtaining performance analysis reports during boot
time on userdebug or eng builds.

Here is an example of trace events of "wm" and "am" categories:

    $ANDROID_BUILD_TOP/external/chromium-trace/systrace.py \
          wm am --boot

This command will cause the device to reboot. After the device is rebooted and
the boot sequence has finished, the trace report is obtained from the device
and written as trace.html on the host by hitting Ctrl+C.

Limitation: recording trace events is started after persistent properties are loaded, so
the trace events that are emitted before that are not recorded. Several
services such as vold, surfaceflinger, and servicemanager are affected by this
limitation since they are started before persistent properties are loaded.
Zygote initialization and the processes that are forked from the zygote are not
affected.


Debugging init
--------------
When a service starts from init, it may fail to `execv()` the service. This is not typical, and may
point to an error happening in the linker as the new service is started. The linker in Android
prints its logs to `logd` and `stderr`, so they are visible in `logcat`. If the error is encountered
before it is possible to access `logcat`, the `stdio_to_kmsg` service option may be used to direct
the logs that the linker prints to `stderr` to `kmsg`, where they can be read via a serial port.

Launching init services without init is not recommended as init sets up a significant amount of
environment (user, groups, security label, capabilities, etc) that is hard to replicate manually.

If it is required to debug a service from its very start, the `sigstop` service option is added.
This option will send SIGSTOP to a service immediately before calling exec. This gives a window
where developers can attach a debugger, strace, etc before continuing the service with SIGCONT.

This flag can also be dynamically controlled via the ctl.sigstop_on and ctl.sigstop_off properties.

Below is an example of dynamically debugging logd via the above:

    stop logd
    setprop ctl.sigstop_on logd
    start logd
    ps -e | grep logd
    > logd          4343     1   18156   1684 do_signal_stop 538280 T init
    gdbclient.py -p 4343
    b main
    c
    c
    c
    > Breakpoint 1, main (argc=1, argv=0x7ff8c9a488) at system/core/logd/main.cpp:427

Below is an example of doing the same but with strace

    stop logd
    setprop ctl.sigstop_on logd
    start logd
    ps -e | grep logd
    > logd          4343     1   18156   1684 do_signal_stop 538280 T init
    strace -p 4343

    (From a different shell)
    kill -SIGCONT 4343

    > strace runs

Host Init Script Verification
-----------------------------

Init scripts are checked for correctness during build time. Specifically the below is checked.

1) Well formatted action, service and import sections, e.g. no actions without a preceding 'on'
line, and no extraneous lines after an 'import' statement.
2) All commands map to a valid keyword and the argument count is within the correct range.
3) All service options are valid. This is stricter than how commands are checked as the service
options' arguments are fully parsed, e.g. UIDs and GIDs must resolve.

There are other parts of init scripts that are only parsed at runtime and therefore not checked
during build time, among them are the below.

1) The validity of the arguments of commands, e.g. no checking if file paths actually exist, if
SELinux would permit the operation, or if the UIDs and GIDs resolve.
2) No checking if a service exists or has a valid SELinux domain defined
3) No checking if a service has not been previously defined in a different init script.

Early Init Boot Sequence
------------------------
The early init boot sequence is broken up into three stages: first stage init, SELinux setup, and
second stage init.

First stage init is responsible for setting up the bare minimum requirements to load the rest of the
system. Specifically this includes mounting /dev, /proc, mounting 'early mount' partitions (which
needs to include all partitions that contain system code, for example system and vendor), and moving
the system.img mount to / for devices with a ramdisk.

Note that in Android Q, system.img always contains TARGET_ROOT_OUT and always is mounted at / by the
time first stage init finishes. Android Q will also require dynamic partitions and therefore will
require using a ramdisk to boot Android. The recovery ramdisk can be used to boot to Android instead
of a dedicated ramdisk as well.

First stage init has three variations depending on the device configuration:
1) For system-as-root devices, first stage init is part of /system/bin/init and a symlink at /init
points to /system/bin/init for backwards compatibility. These devices do not need to do anything to
mount system.img, since it is by definition already mounted as the rootfs by the kernel.

2) For devices with a ramdisk, first stage init is a static executable located at /init. These
devices mount system.img as /system then perform a switch root operation to move the mount at
/system to /. The contents of the ramdisk are freed after mounting has completed.

3) For devices that use recovery as a ramdisk, first stage init it contained within the shared init
located at /init within the recovery ramdisk. These devices first switch root to
/first_stage_ramdisk to remove the recovery components from the environment, then proceed the same
as 2). Note that the decision to boot normally into Android instead of booting
into recovery mode is made if androidboot.force_normal_boot=1 is present in the
kernel commandline, or in bootconfig with Android S and later.

Once first stage init finishes it execs /system/bin/init with the "selinux_setup" argument. This
phase is where SELinux is optionally compiled and loaded onto the system. selinux.cpp contains more
information on the specifics of this process.

Lastly once that phase finishes, it execs /system/bin/init again with the "second_stage"
argument. At this point the main phase of init runs and continues the boot process via the init.rc
scripts.
