#! /system/bin/sh

TESTDATA_PATH=/data/nativetest64/libmeminfo_test/testdata1
SMAPS=$TESTDATA_PATH/smaps
OUT1=$TMPDIR/1.txt
OUT2=$TMPDIR/2.txt

showmap -f $SMAPS > $OUT1
showmap2 -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -f <smaps>";
else
    echo "pass: showmap -f <smaps>"
fi

showmap -q -f $SMAPS > $OUT1
showmap2 -q -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -q -f <smaps>";
else
    echo "pass: showmap -q -f <smaps>"
fi

showmap -v -f $SMAPS > $OUT1
showmap2 -v -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -v -f <smaps>";
else
    echo "pass: showmap -v -f <smaps>"
fi

showmap -a -f $SMAPS > $OUT1
showmap2 -a -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -a -f <smaps>";
else
    echo "pass: showmap -a -f <smaps>"
fi

# Note that all tests from here down that have the option
# '-a' added to the command are expected to fail as
# 'showmap2' actually fixes the 64-bit address truncating
# that was already happening with showmap
showmap -a -t -f $SMAPS > $OUT1
showmap2 -a -t -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -a -t -f <smaps>";
else
    echo "pass: showmap -a -t -f <smaps>"
fi

showmap -a -t -v -f $SMAPS > $OUT1
showmap2 -a -t -v -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -a -t -v -f <smaps>";
else
    echo "pass: showmap -a -t -v -f <smaps>"
fi

# Note: This test again is expected to fail as the new
# showmap fixes an issue with -t where the tool was only
# showing maps with private dirty pages. The '-t' option was however
# supposed to show all maps that have 'private' pages, clean or dirty.
showmap -t -f $SMAPS > $OUT1
showmap2 -t -f $SMAPS > $OUT2
diff $OUT1 $OUT2 > /dev/null
ret=$?
if [[ $ret != 0 ]]; then
    echo "fail: showmap -t -f <smaps>";
else
    echo "pass: showmap -t -f <smaps>"
fi


