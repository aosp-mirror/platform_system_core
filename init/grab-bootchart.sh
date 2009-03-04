#!/bin/sh
#
# this script is used to retrieve the bootchart log generated
# by init when compiled with INIT_BOOTCHART=true.
#
# for all details, see //device/system/init/README.BOOTCHART
#
TMPDIR=/tmp/android-bootchart
rm -rf $TMPDIR
mkdir -p $TMPDIR

LOGROOT=/data/bootchart
TARBALL=bootchart.tgz

FILES="header proc_stat.log proc_ps.log proc_diskstats.log kernel_pacct"

for f in $FILES; do
    adb pull $LOGROOT/$f $TMPDIR/$f 2>&1 > /dev/null
done
(cd $TMPDIR && tar -czf $TARBALL $FILES)
cp -f $TMPDIR/$TARBALL ./$TARBALL
echo "look at $TARBALL"
