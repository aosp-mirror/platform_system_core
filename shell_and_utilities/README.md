# Android's shell and utilities

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
we use the ones that are part of the bzip2 distribution.
The awk added in Android P is the
["one true" awk](https://github.com/onetrueawk/awk).
The bc added in Android Q is
[Gavin Howard's bc](https://github.com/gavinhoward/bc).

The lists below show what tools were provided and where they came from in
each release starting with Gingerbread. This doesn't tell the full story,
because the toolbox implementations did have bugs fixed and options added
over the years. Gingerbread's rm, for example, supported `-r`/`-R` but not
`-f`. But this gives you an idea of what was available in any given release,
and how usable it was likely to be. (**Bold** marks where we switched to toybox
or first added something to toybox.)

Also note that in any given release `toybox` probably contains more
commands than there are symlinks for in `/system/bin`. You can get the
full list for a release by running `toybox` directly.


## Android 15 (API level 35, "Vanilla Ice Cream")

BSD: fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

gavinhoward/bc: bc

one-true-awk: awk

toolbox: getevent getprop setprop start stop

toybox ([0.8.11](https://landley.net/toybox/news.html#08-04-2024)-ish):
[ acpi base64 basename blkdiscard blkid blockdev brctl cal cat chattr
chcon chgrp chmod chown chroot chrt cksum clear cmp comm cp cpio cut
date dd devmem df diff dirname dmesg dos2unix du echo egrep env expand
expr fallocate false fgrep file find flock fmt free freeramdisk fsfreeze
fsync getconf getenforce **getfattr** getopt **gpiodetect** **gpiofind**
**gpioget** **gpioinfo** **gpioset** grep groups gunzip gzip head help hostname
hwclock i2cdetect i2cdump i2cget i2cset **i2ctransfer** iconv id ifconfig
inotifyd insmod install ionice iorenice iotop kill killall ln load\_policy
log logger logname losetup ls lsattr lsmod lsof lspci lsusb makedevs
md5sum **memeater** microcom mkdir mkfifo mknod mkswap mktemp modinfo modprobe
more mount mountpoint mv nbd-client nc netcat netstat nice nl nohup
nproc nsenter od partprobe paste patch pgrep pidof ping ping6 pivot\_root
pkill pmap printenv printf prlimit ps pwd pwdx readelf readlink realpath
renice restorecon rev rfkill rm rmdir rmmod rtcwake runcon sed sendevent
seq setenforce **setfattr** setsid sha1sum sha224sum sha256sum sha384sum
sha512sum sleep sort split stat strings stty swapoff swapon sync sysctl
tac tail tar taskset tee test time timeout top touch tr traceroute
traceroute6 true truncate tty tunctl uclampset ulimit umount uname
uniq unix2dos unlink unshare uptime usleep uudecode uuencode uuidgen
vconfig vi vmstat watch wc which whoami xargs xxd yes zcat

Note: technically getfattr and setfattr were available in earlier versions,
but the symlinks were missing until this release, so they were only available
as `toybox getfattr` and `toybox setfattr` rather than directly.


## Android 14 (API level 34, "Upside Down Cake")

BSD: fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

gavinhoward/bc: bc

one-true-awk: awk

toolbox: getevent getprop setprop start stop

toybox ([0.8.9](http://landley.net/toybox/#10-01-2023)-ish):
[ acpi base64 basename blkdiscard blkid blockdev **brctl** cal cat chattr
chcon chgrp chmod chown chroot chrt cksum clear cmp comm cp cpio cut
date dd devmem df diff dirname dmesg dos2unix du echo egrep env expand
expr fallocate false fgrep file find flock fmt free freeramdisk fsfreeze
fsync getconf getenforce getfattr getopt grep groups gunzip gzip head
help hostname hwclock i2cdetect i2cdump i2cget i2cset iconv id ifconfig
inotifyd insmod install ionice iorenice iotop kill killall ln load\_policy
log **logger** logname losetup ls lsattr lsmod lsof lspci lsusb makedevs
md5sum microcom mkdir mkfifo mknod mkswap mktemp modinfo modprobe
more mount mountpoint mv nbd-client nc netcat netstat nice nl nohup
nproc nsenter od partprobe paste patch pgrep pidof ping ping6 pivot\_root
pkill pmap printenv printf prlimit ps pwd pwdx readelf readlink realpath
renice restorecon rev rfkill rm rmdir rmmod rtcwake runcon sed sendevent
seq setenforce setfattr setsid sha1sum sha224sum sha256sum sha384sum
sha512sum sleep sort split stat strings stty swapoff swapon sync sysctl
tac tail tar taskset tee test time timeout top touch tr traceroute
traceroute6 true truncate tty tunctl uclampset ulimit umount uname
uniq unix2dos unlink unshare uptime usleep uudecode uuencode uuidgen
vconfig vi vmstat watch wc which whoami xargs xxd yes zcat


## Android 13 (33, "Tiramisu")

BSD: fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

gavinhoward/bc: bc

one-true-awk: awk

toolbox: getevent getprop setprop start stop

toybox ([0.8.6](http://landley.net/toybox/#30-11-2021)-ish):
[ acpi base64 basename blkdiscard blkid blockdev cal cat chattr chcon
chgrp chmod chown chroot chrt cksum clear cmp comm cp cpio cut date
dd devmem df diff dirname dmesg dos2unix du echo egrep env expand
expr fallocate false fgrep file find flock fmt free freeramdisk fsfreeze
fsync getconf getenforce getfattr getopt grep groups gunzip gzip head
help hostname hwclock i2cdetect i2cdump i2cget i2cset iconv id ifconfig
inotifyd insmod install ionice iorenice iotop kill killall ln load\_policy
log logname losetup ls lsattr lsmod lsof lspci lsusb makedevs md5sum
microcom mkdir mkfifo mknod mkswap mktemp modinfo modprobe more mount
mountpoint mv nbd-client nc netcat netstat nice nl nohup nproc nsenter
od partprobe paste patch pgrep pidof ping ping6 pivot\_root pkill pmap
printenv printf prlimit ps pwd pwdx readelf readlink realpath renice
restorecon rev rfkill rm rmdir rmmod rtcwake runcon sed sendevent
seq setenforce setfattr setsid sha1sum sha224sum sha256sum sha384sum
sha512sum sleep sort split stat strings stty swapoff swapon sync sysctl
tac tail tar taskset tee test time timeout top touch tr traceroute
traceroute6 true truncate tty tunctl **uclampset** ulimit umount uname
uniq unix2dos unlink unshare uptime usleep uudecode uuencode uuidgen
vconfig vi vmstat watch wc which whoami xargs xxd yes zcat


## Android 12 (31, "Snow Cone")

BSD: fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

gavinhoward/bc: bc

one-true-awk: awk

toolbox: getevent getprop setprop start stop

toybox ([0.8.4](http://landley.net/toybox/#24-10-2020)-ish):
**[** acpi base64 basename **blkdiscard** blkid blockdev cal cat chattr chcon
chgrp chmod chown chroot chrt cksum clear cmp comm cp cpio cut date
dd devmem df diff dirname dmesg dos2unix du echo egrep env expand
expr fallocate false fgrep file find flock fmt free freeramdisk fsfreeze
fsync getconf getenforce getfattr getopt grep groups gunzip gzip head
help hostname hwclock i2cdetect i2cdump i2cget i2cset iconv id ifconfig
inotifyd insmod install ionice iorenice iotop kill killall ln load\_policy
log logname losetup ls lsattr lsmod lsof lspci lsusb makedevs md5sum
microcom mkdir mkfifo mknod mkswap mktemp modinfo modprobe more mount
mountpoint mv nbd-client nc netcat netstat nice nl nohup nproc nsenter
od partprobe paste patch pgrep pidof ping ping6 pivot\_root pkill pmap
printenv printf prlimit ps pwd pwdx readelf readlink realpath renice
restorecon rev rfkill rm rmdir rmmod **rtcwake** runcon sed sendevent
seq setenforce setfattr setsid sha1sum sha224sum sha256sum sha384sum
sha512sum sleep sort split stat strings stty swapoff swapon sync sysctl
tac tail tar taskset tee **test** time timeout top touch tr traceroute
traceroute6 true truncate tty tunctl ulimit umount uname uniq unix2dos
unlink unshare uptime usleep uudecode uuencode uuidgen vconfig vi
vmstat watch wc which whoami xargs xxd yes zcat


## Android 11 (API level 30, "Red Velvet Cake")

BSD: fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

gavinhoward/bc: bc

one-true-awk: awk

toolbox: getevent getprop setprop start stop

toybox ([0.8.3](http://landley.net/toybox/#11-05-2020)-ish):
acpi base64 basename blkid blockdev cal cat chattr chcon chgrp chmod
chown chroot chrt cksum clear cmp comm cp cpio cut date dd **devmem**
df diff dirname dmesg dos2unix du echo egrep env expand expr fallocate
false fgrep file find flock fmt free freeramdisk fsfreeze **fsync** getconf
getenforce getfattr **getopt** grep groups gunzip gzip head help hostname
hwclock i2cdetect i2cdump i2cget i2cset iconv id ifconfig inotifyd
insmod install ionice iorenice iotop kill killall ln load\_policy log
logname losetup ls lsattr lsmod lsof lspci lsusb makedevs md5sum microcom
mkdir mkfifo mknod mkswap mktemp modinfo modprobe more mount mountpoint
mv nbd-client nc netcat netstat nice nl nohup nproc nsenter od partprobe
paste patch pgrep pidof ping ping6 pivot\_root pkill pmap printenv
printf prlimit ps pwd pwdx **readelf** readlink realpath renice restorecon
rev rfkill rm rmdir rmmod runcon sed sendevent seq setenforce setfattr
setsid sha1sum sha224sum sha256sum sha384sum sha512sum sleep sort
split stat strings stty swapoff swapon sync sysctl tac tail tar taskset
tee time timeout top touch tr traceroute traceroute6 true truncate
tty tunctl ulimit umount uname uniq unix2dos unlink unshare uptime
usleep uudecode uuencode uuidgen vconfig **vi** vmstat watch wc which
whoami xargs xxd yes zcat


## Android 10 (API level 29, "Quince Tart")

BSD: grep fsck\_msdos newfs\_msdos

bzip2: bzcat bzip2 bunzip2

one-true-awk: awk

toolbox: getevent getprop

toybox ([0.8.0](http://landley.net/toybox/#08-02-2019)-ish):
acpi base64 basename **bc** **blkid** blockdev cal cat **chattr** chcon chgrp
chmod chown chroot chrt cksum clear cmp comm cp cpio cut date dd df
diff dirname dmesg dos2unix du echo **egrep** env expand expr fallocate
false **fgrep** file find flock fmt free **freeramdisk** **fsfreeze** **getconf**
getenforce **getfattr** grep groups gunzip gzip head **help** hostname hwclock
**i2cdetect** **i2cdump** **i2cget** **i2cset** **iconv** id ifconfig inotifyd insmod
**install** ionice iorenice **iotop** kill killall ln load\_policy log logname
losetup ls **lsattr** lsmod lsof lspci lsusb **makedevs** md5sum microcom
mkdir mkfifo mknod mkswap mktemp modinfo modprobe more mount mountpoint
mv **nbd-client** **nc** **netcat** netstat nice nl nohup **nproc** **nsenter** od **partprobe**
paste patch pgrep pidof **ping** **ping6** **pivot\_root** pkill pmap printenv
printf **prlimit** ps pwd **pwdx** readlink realpath renice restorecon **rev**
**rfkill** rm rmdir rmmod runcon sed sendevent seq setenforce **setfattr**
setprop setsid sha1sum sha224sum sha256sum sha384sum sha512sum sleep
sort split start stat stop strings stty swapoff swapon sync sysctl
tac tail tar taskset tee time timeout top touch tr **traceroute** **traceroute6**
true truncate tty **tunctl** ulimit umount uname uniq unix2dos **unlink**
**unshare** uptime usleep uudecode uuencode **uuidgen** **vconfig** vmstat **watch**
wc which whoami xargs xxd yes zcat


## Android 9.0 (API level 28, "Pie")

BSD: dd grep

bzip2: bzcat bzip2 bunzip2

one-true-awk: awk

toolbox: getevent getprop newfs\_msdos

toybox ([0.7.6](http://landley.net/toybox/#24-02-2018)-ish):
acpi base64 basename blockdev cal cat chcon chgrp chmod chown
chroot chrt cksum clear cmp comm cp cpio cut date df diff dirname dmesg
dos2unix du echo env expand expr fallocate false file find flock **fmt** free
getenforce groups gunzip gzip head hostname hwclock id ifconfig inotifyd
insmod ionice iorenice kill killall ln load\_policy log logname losetup ls
lsmod lsof lspci lsusb md5sum microcom mkdir mkfifo mknod mkswap mktemp
modinfo modprobe more mount mountpoint mv netstat nice nl nohup od paste
patch pgrep pidof pkill pmap printenv printf ps pwd readlink realpath
renice restorecon rm rmdir rmmod runcon sed sendevent seq setenforce
setprop setsid sha1sum sha224sum sha256sum sha384sum sha512sum sleep
sort split start stat stop strings **stty** swapoff swapon sync sysctl tac
tail tar taskset tee time timeout top touch tr true truncate tty ulimit
umount uname uniq unix2dos uptime usleep uudecode uuencode vmstat wc
which whoami xargs xxd yes zcat


## Android 8.0 (API level 26, "Oreo")

BSD: dd grep

bzip2: bzcat bzip2 bunzip2

toolbox: getevent newfs\_msdos

toybox ([0.7.3](http://landley.net/toybox/#21-02-2017)-ish):
acpi base64 basename blockdev cal cat chcon chgrp chmod chown
chroot chrt cksum clear cmp comm cp cpio cut date df **diff** dirname dmesg
dos2unix du echo env expand expr fallocate false **file** find flock free
getenforce getprop groups **gunzip** **gzip** head hostname hwclock id ifconfig
inotifyd insmod ionice iorenice kill killall ln load\_policy **log** logname
losetup ls lsmod lsof **lspci** lsusb md5sum **microcom** mkdir **mkfifo** mknod
mkswap mktemp modinfo **modprobe** more mount mountpoint mv netstat nice
nl nohup od paste patch pgrep pidof pkill pmap printenv printf **ps** pwd
readlink realpath renice restorecon rm rmdir rmmod runcon sed **sendevent**
seq setenforce setprop setsid sha1sum **sha224sum** **sha256sum** **sha384sum**
**sha512sum** sleep sort split start stat stop strings swapoff swapon sync
sysctl tac tail tar taskset tee time timeout **top** touch tr true truncate
tty ulimit umount uname uniq unix2dos uptime usleep **uudecode** **uuencode**
vmstat wc which whoami xargs xxd yes **zcat**


## Android 7.0 (API level 24, "Nougat")

BSD: dd grep

toolbox: getevent iftop ioctl log nandread newfs\_msdos ps prlimit
sendevent start stop top

toybox ([0.7.0](http://landley.net/toybox/#02-02-2016)-ish):
acpi **base64** basename blockdev bzcat cal cat chcon chgrp chmod
chown chroot cksum clear comm cmp cp cpio cut date **df** dirname dmesg
dos2unix **du** echo env expand expr fallocate false find **flock** free
getenforce getprop groups head hostname hwclock id ifconfig inotifyd
insmod **ionice** **iorenice** kill **killall** load\_policy ln logname losetup **ls**
lsmod **lsof** lsusb md5sum mkdir mknod mkswap mktemp modinfo more *mount*
mountpoint mv netstat nice nl nohup od paste patch pgrep pidof pkill
pmap printenv printf pwd readlink realpath **renice** restorecon rm rmdir
rmmod route runcon sed seq setenforce setprop setsid sha1sum sleep sort
split stat strings swapoff swapon sync sysctl tac tail tar taskset tee
time timeout touch tr true truncate **tty** **ulimit** umount uname uniq unix2dos
**uptime** usleep vmstat wc which whoami xargs **xxd** yes


## Android 6.0 (API level 23, "Marshmallow")

BSD: dd du grep

toolbox: df getevent iftop ioctl ionice log ls lsof mount nandread
newfs\_msdos ps prlimit renice sendevent start stop top uptime watchprops

toybox ([0.5.2](http://landley.net/toybox/#25-02-2015)-ish):
acpi basename blockdev bzcat cal cat chcon chgrp chmod chown
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


## Android 5.0 (API level 21, "Lollipop")

BSD: cat chown cp dd du grep kill ln mv printenv rm rmdir sleep sync

toolbox: chcon chmod clear cmp date df dmesg getenforce getevent getprop
getsebool hd id ifconfig iftop insmod ioctl ionice load\_policy log ls
lsmod lsof md5 mkdir mknod mkswap mount nandread netstat newfs\_msdos
nohup notify ps readlink renice restorecon rmmod route runcon schedtop
sendevent setenforce setprop setsebool smd start stop swapoff swapon
top touch umount uptime vmstat watchprops wipe


## Android 4.4 (API level 19, "KitKat")

BSD: cat cp dd du grep newfs\_msdos

toolbox: chcon chmod chown clear cmp date df dmesg getenforce getevent
getprop getsebool hd id ifconfig iftop insmod ioctl ionice kill ln
load\_policy log ls lsmod lsof md5 mkdir mkswap mount mv nandread netstat
notify printenv ps readlink renice restorecon rm rmdir rmmod route runcon
schedtop sendevent setconsole setenforce setprop setsebool sleep smd start
stop swapoff swapon sync top touch umount uptime vmstat watchprops wipe


## Android 4.1-4.3 (API level 16, "Jelly Bean")

BSD: cat cp dd du grep newfs\_msdos

toolbox: chcon chmod chown clear cmp date df dmesg getenforce getevent
getprop getsebool hd id ifconfig iftop insmod ioctl ionice kill ln
load\_policy log ls lsmod lsof md5 mkdir mount mv nandread netstat notify
printenv ps reboot renice restorecon rm rmdir rmmod route runcon schedtop
sendevent setconsole setenforce setprop setsebool sleep smd start stop
sync top touch umount uptime vmstat watchprops wipe


## Android 4.0 (API level 14, "Ice Cream Sandwich")

BSD: cat dd newfs\_msdos

toolbox: chmod chown cmp date df dmesg getevent getprop hd id ifconfig
iftop insmod ioctl ionice kill ln log ls lsmod lsof mkdir mount mv
nandread netstat notify printenv ps reboot renice rm rmdir rmmod route
schedtop sendevent setconsole setprop sleep smd start stop sync top
touch umount uptime vmstat watchprops wipe


## Android 2.3 (API level 9, "Gingerbread")

BSD: cat dd newfs\_msdos

toolbox: chmod chown cmp date df dmesg getevent getprop hd id ifconfig
iftop insmod ioctl ionice kill ln log ls lsmod lsof mkdir mount mv
nandread netstat notify printenv ps reboot renice rm rmdir rmmod route
schedtop sendevent setconsole setprop sleep smd start stop sync top
umount uptime vmstat watchprops wipe
