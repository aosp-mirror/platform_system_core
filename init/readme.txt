
Android Init Language
---------------------

The Android Init Language consists of four broad classes of statements,
which are Actions, Commands, Services, and Options.

All of these are line-oriented, consisting of tokens separated by
whitespace.  The c-style backslash escapes may be used to insert
whitespace into a token.  Double quotes may also be used to prevent
whitespace from breaking text into multiple tokens.  The backslash,
when it is the last character on a line, may be used for line-folding.

Lines which start with a # (leading whitespace allowed) are comments.

Actions and Services implicitly declare a new section.  All commands
or options belong to the section most recently declared.  Commands
or options before the first section are ignored.

Actions and Services have unique names.  If a second Action or Service
is declared with the same name as an existing one, it is ignored as
an error.  (??? should we override instead)


Actions
-------
Actions are named sequences of commands.  Actions have a trigger which
is used to determine when the action should occur.  When an event
occurs which matches an action's trigger, that action is added to
the tail of a to-be-executed queue (unless it is already on the
queue).

Each action in the queue is dequeued in sequence and each command in
that action is executed in sequence.  Init handles other activities
(device creation/destruction, property setting, process restarting)
"between" the execution of the commands in activities.

Actions take the form of:

on <trigger>
   <command>
   <command>
   <command>


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

critical
   This is a device-critical service. If it exits more than four times in
   four minutes, the device will reboot into recovery mode.

disabled
   This service will not automatically start with its class.
   It must be explicitly started by name.

setenv <name> <value>
   Set the environment variable <name> to <value> in the launched process.

socket <name> <type> <perm> [ <user> [ <group> ] ]
   Create a unix domain socket named /dev/socket/<name> and pass
   its fd to the launched process.  <type> must be "dgram", "stream" or "seqpacket".
   User and group default to 0.

user <username>
   Change to username before exec'ing this service.
   Currently defaults to root.  (??? probably should default to nobody)
   Currently, if your process requires linux capabilities then you cannot use
   this command. You must instead request the capabilities in-process while
   still root, and then drop to your desired uid.

group <groupname> [ <groupname> ]*
   Change to groupname before exec'ing this service.  Additional
   groupnames beyond the (required) first one are used to set the
   supplemental groups of the process (via setgroups()).
   Currently defaults to root.  (??? probably should default to nobody)

oneshot
   Do not restart the service when it exits.

class <name>
   Specify a class name for the service.  All services in a
   named class may be started or stopped together.  A service
   is in the class "default" if one is not specified via the
   class option.

onrestart
    Execute a Command (see below) when service restarts.

Triggers
--------
   Triggers are strings which can be used to match certain kinds
   of events and used to cause an action to occur.

boot
   This is the first trigger that will occur when init starts
   (after /init.conf is loaded)

<name>=<value>
   Triggers of this form occur when the property <name> is set
   to the specific value <value>.

device-added-<path>
device-removed-<path>
   Triggers of these forms occur when a device node is added
   or removed.

service-exited-<name>
   Triggers of this form occur when the specified service exits.


Commands
--------

exec <path> [ <argument> ]*
   Fork and execute a program (<path>).  This will block until
   the program completes execution.  It is best to avoid exec
   as unlike the builtin commands, it runs the risk of getting
   init "stuck". (??? maybe there should be a timeout?)

export <name> <value>
   Set the environment variable <name> equal to <value> in the
   global environment (which will be inherited by all processes
   started after this command is executed)

ifup <interface>
   Bring the network interface <interface> online.

import <filename>
   Parse an init config file, extending the current configuration.

hostname <name>
   Set the host name.

chdir <directory>
   Change working directory.

chmod <octal-mode> <path>
   Change file access permissions.

chown <owner> <group> <path>
   Change file owner and group.

chroot <directory>
  Change process root directory.

class_start <serviceclass>
   Start all services of the specified class if they are
   not already running.

class_stop <serviceclass>
   Stop all services of the specified class if they are
   currently running.

domainname <name>
   Set the domain name.

insmod <path>
   Install the module at <path>

mkdir <path> [mode] [owner] [group]
   Create a directory at <path>, optionally with the given mode, owner, and
   group. If not provided, the directory is created with permissions 755 and
   owned by the root user and root group.

mount <type> <device> <dir> [ <mountoption> ]*
   Attempt to mount the named device at the directory <dir>
   <device> may be of the form mtd@name to specify a mtd block
   device by name.
   <mountoption>s include "ro", "rw", "remount", "noatime", ...

setkey
   TBD

setprop <name> <value>
   Set system property <name> to <value>.

setrlimit <resource> <cur> <max>
   Set the rlimit for a resource.

start <service>
   Start a service running if it is not already running.

stop <service>
   Stop a service from running if it is currently running.

symlink <target> <path>
   Create a symbolic link at <path> with the value <target>

sysclktz <mins_west_of_gmt>
   Set the system clock base (0 if system clock ticks in GMT)

trigger <event>
   Trigger an event.  Used to queue an action from another
   action.

write <path> <string> [ <string> ]*
   Open the file at <path> and write one or more strings
   to it with write(2)


Properties
----------
Init updates some system properties to provide some insight into
what it's doing:

init.action 
   Equal to the name of the action currently being executed or "" if none

init.command
   Equal to the command being executed or "" if none.

init.svc.<name>
   State of a named service ("stopped", "running", "restarting")


Example init.conf
-----------------

# not complete -- just providing some examples of usage
#
on boot
   export PATH /sbin:/system/sbin:/system/bin
   export LD_LIBRARY_PATH /system/lib

   mkdir /dev
   mkdir /proc
   mkdir /sys

   mount tmpfs tmpfs /dev
   mkdir /dev/pts
   mkdir /dev/socket
   mount devpts devpts /dev/pts
   mount proc proc /proc
   mount sysfs sysfs /sys

   write /proc/cpu/alignment 4

   ifup lo

   hostname localhost
   domainname localhost

   mount yaffs2 mtd@system /system
   mount yaffs2 mtd@userdata /data

   import /system/etc/init.conf

   class_start default

service adbd /sbin/adbd
   user adb
   group adb

service usbd /system/bin/usbd -r
   user usbd
   group usbd
   socket usbd 666

service zygote /system/bin/app_process -Xzygote /system/bin --zygote
   socket zygote 666

service runtime /system/bin/runtime
   user system
   group system

on device-added-/dev/compass
   start akmd

on device-removed-/dev/compass
   stop akmd

service akmd /sbin/akmd
   disabled
   user akmd
   group akmd

Debugging notes
---------------
By default, programs executed by init will drop stdout and stderr into
/dev/null. To help with debugging, you can execute your program via the
Andoird program logwrapper. This will redirect stdout/stderr into the
Android logging system (accessed via logcat).

For example
service akmd /system/bin/logwrapper /sbin/akmd
