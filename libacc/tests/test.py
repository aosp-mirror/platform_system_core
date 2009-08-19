#
# Test the acc compiler

import unittest
import subprocess
import os
import sys

gArmInitialized = False
gUseArm = True
gUseX86 = True
gRunOTCCOutput = True


def parseArgv():
    global gUseArm
    global gUseX86
    global gRunOTCCOutput
    for arg in sys.argv[1:]:
        if arg == "--noarm":
            print "--noarm: not testing ARM"
            gUseArm = False
        elif arg == "--nox86":
            print "--nox86: not testing x86"
            gUseX86 = False
        elif arg == "--norunotcc":
            print "--norunotcc detected, not running OTCC output"
            gRunOTCCOutput = False
        else:
            print "Unknown parameter: ", arg
            raise "Unknown parameter"
    sys.argv = sys.argv[0:1]

def compile(args):
    proc = subprocess.Popen(["acc"] + args, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    result = proc.communicate()
    return result

def runCmd(args):
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = proc.communicate()
    return result[0].strip()

def which(item):
    return runCmd(["which", item])

def fileType(item):
    return runCmd(["file", item])

def outputCanRun():
    ft = fileType(which("acc"))
    return ft.find("ELF 32-bit LSB executable, Intel 80386") >= 0

def adb(args):
    return runCmd(["adb"] + args)

def setupArm():
    global gArmInitialized
    if gArmInitialized:
        return
    print "Setting up arm"
    adb(["remount"])
    adb(["shell", "rm", "/system/bin/acc"])
    adb(["shell", "mkdir", "/system/bin/accdata"])
    adb(["shell", "mkdir", "/system/bin/accdata/data"])
    # Clear out old data TODO: handle recursion
    adb(["shell", "rm", "/system/bin/accdata/data/*"])
    # Copy over data
    for root, dirs, files in os.walk("data"):
        for d in dirs:
            adb(["shell", "mkdir", os.path.join(root, d)])
        for f in files:
            adb(["push", os.path.join(root, f), os.path.join("/system/bin/accdata", root, f)])
    # Copy over compiler
    adb(["sync"])
    gArmInitialized = True

def compileArm(args):
    setupArm()
    proc = subprocess.Popen(["adb", "shell", "/system/bin/acc"] + args, stdout=subprocess.PIPE)
    result = proc.communicate()
    return result[0].replace("\r","")

def compare(a, b):
    if a != b:
        firstDiff = firstDifference(a, b)
        print "Strings differ at character %d. Common: %s. Difference '%s' != '%s'" % (
            firstDiff, a[0:firstDiff], safeAccess(a, firstDiff), safeAccess(b, firstDiff))

def safeAccess(s, i):
    if 0 <= i < len(s):
        return s[i]
    else:
        return '?'

def firstDifference(a, b):
    commonLen = min(len(a), len(b))
    for i in xrange(0, commonLen):
        if a[i] != b[i]:
            return i
    return commonLen

# a1 and a2 are the expected stdout and stderr.
# b1 and b2 are the actual stdout and stderr.
# Compare the two, sets. Allow any individual line
# to appear in either stdout or stderr. This is because
# the way we obtain output on the ARM combines both
# streams into one sequence.

def compareOuput(a1,a2,b1,b2):
    while True:
        totalLen = len(a1) + len(a2) + len(b1) + len(b2)
        a1, b1 = matchCommon(a1, b1)
        a1, b2 = matchCommon(a1, b2)
        a2, b1 = matchCommon(a2, b1)
        a2, b2 = matchCommon(a2, b2)
        newTotalLen = len(a1) + len(a2) + len(b1) + len(b2)
        if newTotalLen == 0:
            return True
        if newTotalLen == totalLen:
            print "Failed at %d %d %d %d" % (len(a1), len(a2), len(b1), len(b2))
            print "a1", a1
            print "a2", a2
            print "b1", b1
            print "b2", b2
            return False

def matchCommon(a, b):
    """Remove common items from the beginning of a and b,
       return just the tails that are different."""
    while len(a) > 0 and len(b) > 0 and a[0] == b[0]:
        a = a[1:]
        b = b[1:]
    return a, b

def rewritePaths(args):
    return [rewritePath(x) for x in args]

def rewritePath(p):
    """Take a path that's correct on the x86 and convert to a path
       that's correct on ARM."""
    if p.startswith("data/"):
        p = "/system/bin/accdata/" + p
    return p

class TestACC(unittest.TestCase):

    def checkResult(self, out, err, stdErrResult, stdOutResult=""):
        a1 = out.splitlines()
        a2 = err.splitlines()
        b2 = stdErrResult.splitlines()
        b1 = stdOutResult.splitlines()
        self.assertEqual(True, compareOuput(a1,a2,b1,b2))

    def compileCheck(self, args, stdErrResult, stdOutResult="",
                     targets=['arm', 'x86']):
        global gUseArm
        global gUseX86
        targetSet = frozenset(targets)
        if gUseX86 and 'x86' in targetSet:
            out, err = compile(args)
            self.checkResult(out, err, stdErrResult, stdOutResult)
        if gUseArm and 'arm' in targetSet:
            out = compileArm(rewritePaths(args))
            self.checkResult(out, "", stdErrResult, stdOutResult)

    def compileCheckArm(self, args, result):
        self.assertEqual(compileArm(args), result)

    def testCompileReturnVal(self):
        self.compileCheck(["data/returnval-ansi.c"], "")

    def testCompileOTCCANSII(self):
        self.compileCheck(["data/otcc-ansi.c"], "", "", ['x86'])

    def testRunReturnVal(self):
        self.compileCheck(["-R", "data/returnval-ansi.c"],
        "Executing compiled code:\nresult: 42\n")

    def testStringLiteralConcatenation(self):
        self.compileCheck(["-R", "data/testStringConcat.c"],
        "Executing compiled code:\nresult: 13\n", "Hello, world\n")

    def testRunOTCCANSI(self):
        global gRunOTCCOutput
        if gRunOTCCOutput:
            self.compileCheck(["-R", "data/otcc-ansi.c", "data/returnval.c"],
                "Executing compiled code:\notcc-ansi.c: About to execute compiled code:\natcc-ansi.c: result: 42\nresult: 42\n", "",
                 ['x86'])

    def testRunOTCCANSI2(self):
        global gRunOTCCOutput
        if gRunOTCCOutput:
            self.compileCheck(["-R", "data/otcc-ansi.c", "data/otcc.c", "data/returnval.c"],
                "Executing compiled code:\notcc-ansi.c: About to execute compiled code:\notcc.c: about to execute compiled code.\natcc-ansi.c: result: 42\nresult: 42\n", "",['x86'])

    def testRunConstants(self):
        self.compileCheck(["-R", "data/constants.c"],
            "Executing compiled code:\nresult: 12\n",
            "0 = 0\n010 = 8\n0x10 = 16\n'\\a' = 7\n'\\b' = 8\n'\\f' = 12\n'\\n' = 10\n'\\r' = 13\n'\\t' = 9\n'\\v' = 11\n'\\\\' = 92\n'\\'' = 39\n" +
            "'\\\"' = 34\n'\\?' = 63\n'\\0' = 0\n'\\1' = 1\n'\\12' = 10\n'\\123' = 83\n'\\x0' = 0\n'\\x1' = 1\n'\\x12' = 18\n'\\x123' = 291\n'\\x1f' = 31\n'\\x1F' = 31\n")

    def testRunFloat(self):
        self.compileCheck(["-R", "data/float.c"],
            "Executing compiled code:\nresult: 0\n",
            """Constants: 0 0 0 0.01 0.01 0.1 10 10 0.1
int: 1 float: 2.2 double: 3.3
 ftoi(1.4f)=1
 dtoi(2.4)=2
 itof(3)=3
 itod(4)=4
globals: 1 2 3 4
args: 1 2 3 4
locals: 1 2 3 4
cast rval: 2 4
cast lval: 1.1 2 3.3 4
""")

    def testRunFlops(self):
        self.compileCheck(["-R", "data/flops.c"],
            """Executing compiled code:
result: 0""",
"""-1.1 = -1.1
!1.2 = 0
!0 = 1
double op double:
1 + 2 = 3
1 - 2 = -1
1 * 2 = 2
1 / 2 = 0.5
float op float:
1 + 2 = 3
1 - 2 = -1
1 * 2 = 2
1 / 2 = 0.5
double op float:
1 + 2 = 3
1 - 2 = -1
1 * 2 = 2
1 / 2 = 0.5
double op int:
1 + 2 = 3
1 - 2 = -1
1 * 2 = 2
1 / 2 = 0.5
int op double:
1 + 2 = 3
1 - 2 = -1
1 * 2 = 2
1 / 2 = 0.5
double op double:
1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1
1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0
2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1
double op float:
1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1
1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0
2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1
float op float:
1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1
1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0
2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1
int op double:
1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1
1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0
2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1
double op int:
1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1
1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0
2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1
branching: 1 0 1
testpassi: 1 2 3 4 5 6 7 8 9 10 11 12
testpassf: 1 2 3 4 5 6 7 8 9 10 11 12
testpassd: 1 2 3 4 5 6 7 8 9 10 11 12
testpassi: 1 2 3 4 5 6 7 8 9 10 11 12
testpassf: 1 2 3 4 5 6 7 8 9 10 11 12
testpassd: 1 2 3 4 5 6 7 8 9 10 11 12
testpassi: 1 2 3 4 5 6 7 8 9 10 11 12
testpassf: 1 2 3 4 5 6 7 8 9 10 11 12
testpassd: 1 2 3 4 5 6 7 8 9 10 11 12
testpassidf: 1 2 3
""")
    def testCasts(self):
        self.compileCheck(["-R", "data/casts.c"],
            """Executing compiled code:
result: 0""", """Reading from a pointer: 3 3
Writing to a pointer: 4
Testing casts: 3 3 4.5 4
Testing reading (int*): 4
Testing writing (int*): 8 9
Testing reading (char*): 0x78 0x56 0x34 0x12
Testing writing (char*): 0x87654321
f(10)
Function pointer result: 70
Testing read/write (float*): 8.8 9.9
Testing read/write (double*): 8.8 9.9
""")

    def testChar(self):
        self.compileCheck(["-R", "data/char.c"], """Executing compiled code:
result: 0""", """a = 99, b = 41
ga = 100, gb = 44""")

    def testPointerArithmetic(self):
        self.compileCheck(["-R", "data/pointers.c"], """Executing compiled code:
result: 0""", """Pointer difference: 1 4
Pointer addition: 2
Pointer comparison to zero: 0 0 1
Pointer comparison: 1 0 0 0 1
""")
    def testRollo3(self):
        self.compileCheck(["-R", "data/rollo3.c"], """Executing compiled code:
result: 10""", """""")

    def testFloatDouble(self):
        self.compileCheck(["-R", "data/floatdouble.c"], """Executing compiled code:
result: 0""", """0.002 0.1 10""")

    def testIncDec(self):
        self.compileCheck(["-R", "data/inc.c"], """Executing compiled code:
0
1
2
1
1
2
1
0
result: 0
""","""""")

    def testIops(self):
        self.compileCheck(["-R", "data/iops.c"], """Executing compiled code:
result: 0""", """Literals: 1 -1
++
0
1
2
3
4
5
6
7
8
9
--
10
9
8
7
6
5
4
3
2
1
0
""")

    def testFilm(self):
        self.compileCheck(["-R", "data/film.c"], """Executing compiled code:
result: 0""", """testing...
Total bad: 0
""")

    def testpointers2(self):
        self.compileCheck(["-R", "data/pointers2.c"], """Executing compiled code:
result: 0""", """a = 0, *pa = 0
a = 2, *pa = 2
a = 0, *pa = 0 **ppa = 0
a = 2, *pa = 2 **ppa = 2
a = 0, *pa = 0 **ppa = 0
a = 2, *pa = 2 **ppa = 2
""")

    def testassignmentop(self):
        self.compileCheck(["-R", "data/assignmentop.c"], """Executing compiled code:
result: 0""", """2 *= 5  10
20 /= 5  4
17 %= 5  2
17 += 5  22
17 -= 5  12
17<<= 1  34
17>>= 1  8
17&= 1  1
17^= 1  16
16|= 1  17
*f() = *f() + 10;
f()
f()
a = 10
*f() += 10;
f()
a = 10
""")

    def testcomma(self):
        self.compileCheck(["-R", "data/comma.c"], """Executing compiled code:
result: 0""", """statement: 10
if: a = 0
while: b = 11
for: b = 22
return: 30
arg: 12
""")

    def testBrackets(self):
        self.compileCheck(["-R", "data/brackets.c"], """Executing compiled code:
Errors: 0
2D Errors: 0
result: 0
""","""""")

    def testShort(self):
        self.compileCheck(["-R", "data/short.c"], """Executing compiled code:
result: -2
""","""""")

    def testArray(self):
        self.compileCheck(["-R", "data/array.c"], """Executing compiled code:
localInt: 3
localDouble: 3 3
globalChar: 3
globalDouble: 3
testArgs: 0 2 4
testDecay: Hi!
test2D:
abcdefghijdefghijklm
defghijklmghijklmnop
ghijklmnopjklmnopabc
jklmnopabcmnopabcdef
mnopabcdefpabcdefghi
pabcdefghicdefghijkl
cdefghijklfghijklmno
fghijklmnoijklmnopab
ijklmnopablmnopabcde
lmnopabcdefghijklmno
result: 0
""","""""")

    def testDefines(self):
        self.compileCheck(["-R", "data/defines.c"], """Executing compiled code:
result: 3
""","""""")

    def testFuncArgs(self):
        self.compileCheck(["-R", "data/funcargs.c"], """Executing compiled code:
result: 4
""","""""")

def main():
    parseArgv()
    if not outputCanRun():
        print "Can't run output of acc compiler."
    unittest.main()

if __name__ == '__main__':
    main()

