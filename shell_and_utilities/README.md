Android's shell and utilities
=============================

Since IceCreamSandwich Android has used
[mksh](https://www.mirbsd.org/mksh.htm) as its shell. Before then it used
[ash](https://en.wikipedia.org/wiki/Almquist_shell) (which actually
remained unused in the tree up to and including KitKat).

Initially Android had a very limited command-line provided by its own
"toolbox" binary. Since Marshmallow almost everything is supplied by
[toybox](http://landley.net/toybox/) instead.

We started moving a few of the more important tools to full
BSD implementations in JellyBean, and continued this work in
Lollipop. Lollipop was a major break with the past in many ways (LP64
support and the switch to ART both having lots of knock-on effects around
the system), so although this was the beginning of the end of toolbox it
(a) didn't stand out given all the other systems-level changes and (b)
in Marshmallow we changed direction and started the move to toybox.

Not everything is provided by toybox, though. For the bzip2 command-line tools
we use the ones that are part of the bzip2 distribution. The awk added in
Android P is Brian Kernighan's "one true" awk.

The lists below show what tools were provided and where they came from in
each release starting with Gingerbread. This doesn't tell the full story,
because the toolbox implementations did have bugs fixed and options added
over the years. Gingerbread's rm, for example, supported `-r`/`-R` but not
`-f`. But this gives you an idea of what was available in any given release,
and how usable it was likely to be.

Also note that in any given release `toybox` probably contains more
commands than there are symlinks for in `/system/bin`. You can get the
full list for a release by running `toybox` directly.


Android 2.3 (Gingerbread)
-------------------------

BSD: cat dd newfs\_msdos

toolbox: chmod chown cmp date df dmesg getevent getprop hd id ifconfig
iftop insmod ioctl ionice kill ln log ls lsmod lsof mkdir mount mv
nandread netstat notify printenv ps reboot renice rm rmdir rmmod route
schedtop sendevent setconsole setprop sleep smd start stop sync top
umount uptime vmstat watchprops wipe


Android 4.0 (IceCreamSandwich)
------------------------------

BSD: cat dd newfs\_msdos

toolbox: chmod chown cmp date df dmesg getevent getprop hd id ifconfig
iftop insmod ioctl ionice kill ln log ls lsmod lsof mkdir mount mv
nandread netstat notify printenv ps reboot renice rm rmdir rmmod route
schedtop sendevent setconsole setprop sleep smd start stop sync top
touch umount uptime vmstat watchprops wipe


Android 4.1-4.3 (JellyBean)
---------------------------

BSD: cat cp dd du grep newfs\_msdos

toolbox: chcon chmod chown clear cmp date df dmesg getenforce getevent
getprop getsebool hd id ifconfig iftop insmod ioctl ionice kill ln
load\_policy log ls lsmod lsof md5 mkdir mount mv nandread netstat notify
printenv ps reboot renice restorecon rm rmdir rmmod route runcon schedtop
sendevent setconsole setenforce setprop setsebool sleep smd start stop
sync top touch umount uptime vmstat watchprops wipe


Android 4.4 (KitKat)
--------------------

BSD: cat cp dd du grep newfs\_msdos

toolbox: chcon chmod chown clear cmp date df dmesg getenforce getevent
getprop getsebool hd id ifconfig iftop insmod ioctl ionice kill ln
load\_policy log ls lsmod lsof md5 mkdir mkswap mount mv nandread netstat
notify printenv ps readlink renice restorecon rm rmdir rmmod route runcon
schedtop sendevent setconsole setenforce setprop setsebool sleep smd start
stop swapoff swapon sync top touch umount uptime vmstat watchprops wipe


Android 5.0 (Lollipop)
----------------------

BSD: cat chown cp dd du grep kill ln mv printenv rm rmdir sleep sync

toolbox: chcon chmod clear cmp date df dmesg getenforce getevent getprop
getsebool hd id ifconfig iftop insmod ioctl ionice load\_policy log ls
lsmod lsof md5 mkdir mknod mkswap mount nandread netstat newfs\_msdos
nohup notify ps readlink renice restorecon rmmod route runcon schedtop
sendevent setenforce setprop setsebool smd start stop swapoff swapon
top touch umount uptime vmstat watchprops wipe


Android 6.0 (Marshmallow)
-------------------------

BSD: dd du grep

toolbox: df getevent iftop ioctl ionice log ls lsof mount nandread
newfs\_msdos ps prlimit renice sendevent start stop top uptime watchprops

toybox: acpi basename blockdev bzcat cal cat chcon chgrp chmod chown
chroot cksum clear comm cmp cp cpio cut date dirname dmesg dos2unix echo
env expand expr fallocate false find free getenforce getprop groups
head hostname hwclock id ifconfig inotifyd insmod kill load\_policy ln
logname losetup lsmod lsusb md5sum mkdir mknod mkswap mktemp modinfo
more mountpoint mv netstat nice nl nohup od paste patch pgrep pidof
pkill pmap printenv printf pwd readlink realpath restorecon rm rmdir
rmmod route runcon sed seq setenforce setprop setsid sha1sum sleep sort
split stat strings swapoff swapon sync sysctl tac tail tar taskset tee
time timeout touch tr true truncate umount uname uniq unix2dos usleep
vmstat wc which whoami xargs yes


Android 7.0 (Nougat)
--------------------

BSD: dd grep

toolbox: getevent iftop ioctl log nandread newfs\_msdos ps prlimit
sendevent start stop top

toybox: acpi base64 basename blockdev bzcat cal cat chcon chgrp chmod
chown chroot cksum clear comm cmp cp cpio cut date df dirname dmesg
dos2unix du echo env expand expr fallocate false find flock free
getenforce getprop groups head hostname hwclock id ifconfig inotifyd
insmod ionice iorenice kill killall load\_policy ln logname losetup ls
lsmod lsof lsusb md5sum mkdir mknod mkswap mktemp modinfo more mount
mountpoint mv netstat nice nl nohup od paste patch pgrep pidof pkill
pmap printenv printf pwd readlink realpath renice restorecon rm rmdir
rmmod route runcon sed seq setenforce setprop setsid sha1sum sleep sort
split stat strings swapoff swapon sync sysctl tac tail tar taskset tee
time timeout touch tr true truncate tty ulimit umount uname uniq unix2dos
uptime usleep vmstat wc which whoami xargs xxd yes


Android 8.0 (Oreo)
------------------

BSD: dd grep

bzip2: bzcat bzip2 bunzip2

toolbox: getevent newfs\_msdos

toybox: acpi base64 basename blockdev cal cat chcon chgrp chmod chown
chroot chrt cksum clear cmp comm cp cpio cut date df diff dirname dmesg
dos2unix du echo env expand expr fallocate false file find flock free
getenforce getprop groups gunzip gzip head hostname hwclock id ifconfig
inotifyd insmod ionice iorenice kill killall ln load\_policy log logname
losetup ls lsmod lsof lspci lsusb md5sum microcom mkdir mkfifo mknod
mkswap mktemp modinfo modprobe more mount mountpoint mv netstat nice
nl nohup od paste patch pgrep pidof pkill pmap printenv printf ps pwd
readlink realpath renice restorecon rm rmdir rmmod runcon sed sendevent
seq setenforce setprop setsid sha1sum sha224sum sha256sum sha384sum
sha512sum sleep sort split start stat stop strings swapoff swapon sync
sysctl tac tail tar taskset tee time timeout top touch tr true truncate
tty ulimit umount uname uniq unix2dos uptime usleep uudecode uuencode
vmstat wc which whoami xargs xxd yes zcat

Android P
---------

BSD: dd grep

bzip2: bzcat bzip2 bunzip2

one-true-awk: awk

toolbox: getevent getprop newfs\_msdos

toybox: acpi base64 basename blockdev cal cat chcon chgrp chmod chown
chroot chrt cksum clear cmp comm cp cpio cut date df diff dirname dmesg
dos2unix du echo env expand expr fallocate false file find flock fmt free
getenforce groups gunzip gzip head hostname hwclock id ifconfig inotifyd
insmod ionice iorenice kill killall ln load\_policy log logname losetup ls
lsmod lsof lspci lsusb md5sum microcom mkdir mkfifo mknod mkswap mktemp
modinfo modprobe more mount mountpoint mv netstat nice nl nohup od paste
patch pgrep pidof pkill pmap printenv printf ps pwd readlink realpath
renice restorecon rm rmdir rmmod runcon sed sendevent seq setenforce
setprop setsid sha1sum sha224sum sha256sum sha384sum sha512sum sleep
sort split start stat stop strings stty swapoff swapon sync sysctl tac
tail tar taskset tee time timeout top touch tr true truncate tty ulimit
umount uname uniq unix2dos uptime usleep uudecode uuencode vmstat wc
which whoami xargs xxd yes zcat

Android Q
---------

BSD: grep fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

one-true-awk: awk

toolbox: getevent getprop

toybox: acpi base64 basename blockdev cal cat chcon chgrp chmod chown
chroot chrt cksum clear cmp comm cp cpio cut date dd df diff dirname
dmesg dos2unix du echo env expand expr fallocate false file find flock
fmt free getenforce groups gunzip gzip head hostname hwclock id ifconfig
inotifyd insmod ionice iorenice kill killall ln load\_policy log logname
losetup ls lsmod lsof lspci lsusb md5sum microcom mkdir mkfifo mknod
mkswap mktemp modinfo modprobe more mount mountpoint mv nc netcat netstat
nice nl nohup nsenter od paste patch pgrep pidof pkill pmap printenv
printf ps pwd readlink realpath renice restorecon rm rmdir rmmod runcon
sed sendevent seq setenforce setprop setsid sha1sum sha224sum sha256sum
sha384sum sha512sum sleep sort split start stat stop strings stty swapoff
swapon sync sysctl tac tail tar taskset tee time timeout top touch tr
true truncate tty ulimit umount uname uniq unix2dos unshare uptime usleep
uudecode uuencode vmstat wc which whoami xargs xxd yes zcat
