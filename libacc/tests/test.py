#
# Test the acc compiler

import unittest
import subprocess
import os
import sets

gArmInitialized = False

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

def compareSet(a1,a2,b1,b2):
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
    while len(a) > 0 and len(b) > 0 and a[0] == b[0]:
        a = a[1:]
        b = b[1:]
    return a, b

def rewritePaths(args):
    return [rewritePath(x) for x in args]

def rewritePath(p):
    if p.startswith("data/"):
        p = "/system/bin/accdata/" + p
    return p

class TestACC(unittest.TestCase):
 
    def compileCheckOld(self, args, stdErrResult, stdOutResult=""):
        out, err = compile(args)
        compare(out, stdOutResult)
        compare(err, stdErrResult)
        self.assertEqual(out, stdOutResult)
        self.assertEqual(err, stdErrResult)

    def checkResult(self, out, err, stdErrResult, stdOutResult=""):
        a1 = out.splitlines()
        a2 = err.splitlines()
        b2 = stdErrResult.splitlines()
        b1 = stdOutResult.splitlines()
        self.assertEqual(True, compareSet(a1,a2,b1,b2))
        
    def compileCheck(self, args, stdErrResult, stdOutResult="",
                     targets=['arm', 'x86']):
        targetSet = sets.ImmutableSet(targets)
        if 'x86' in targetSet:
            out, err = compile(args)
            self.checkResult(out, err, stdErrResult, stdOutResult)
        if 'arm' in targetSet:
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
        self.compileCheck(["-R", "data/otcc-ansi.c", "data/returnval.c"], 
            "Executing compiled code:\notcc-ansi.c: About to execute compiled code:\natcc-ansi.c: result: 42\nresult: 42\n", "",
             ['x86'])

    def testRunOTCCANSI2(self):
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
            "int: 1 float: 2.2 double: 3.3\n ftoi(1.4f)=1\n dtoi(2.4)=2\n itof(3)=3\n itod(4)=4\nglobals: 1 2 3 4\nargs: 1 2 3 4\nlocals: 1 2 3 4\ncast rval: 2 4\ncast lval: 1.1 2 3.3 4\n")
        
    def testRunFlops(self):
        self.compileCheck(["-R", "data/flops.c"],
            "Executing compiled code:\nresult: 0\n",
            "-1.1 = -1.1\n" +
            "!1.2 = 0\n" +
            "!0 = 1\n" +
            "double op double:\n" +
            "1 + 2 = 3\n" +
            "1 - 2 = -1\n" +
            "1 * 2 = 2\n" +
            "1 / 2 = 0.5\n" +
            "float op float:\n" +
            "1 + 2 = 3\n" +
            "1 - 2 = -1\n" +
            "1 * 2 = 2\n" +
            "1 / 2 = 0.5\n" +
            "double op float:\n" +
            "1 + 2 = 3\n" +
            "1 - 2 = -1\n" +
            "1 * 2 = 2\n" +
            "1 / 2 = 0.5\n" +
            "double op int:\n" +
            "1 + 2 = 3\n" +
            "1 - 2 = -1\n" +
            "1 * 2 = 2\n" +
            "1 / 2 = 0.5\n" +
            "int op double:\n" +
            "1 + 2 = 3\n" +
            "1 - 2 = -1\n" +
            "1 * 2 = 2\n" +
            "1 / 2 = 0.5\n" +
            "double op double:\n" +
            "1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1\n" +
            "1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0\n" +
            "2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1\n" +
            "double op float:\n" +
            "1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1\n" +
            "1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0\n" +
            "2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1\n" +
            "float op float:\n" +
            "1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1\n" +
            "1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0\n" +
            "2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1\n" +
            "int op double:\n" +
            "1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1\n" +
            "1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0\n" +
            "2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1\n" +
            "double op int:\n" +
            "1 op 2: < 1   <= 1   == 0   >= 0   > 0   != 1\n" +
            "1 op 1: < 0   <= 1   == 1   >= 1   > 0   != 0\n" +
            "2 op 1: < 0   <= 0   == 0   >= 1   > 1   != 1\n" +
            "branching: 1 0 1\n" +
            "testpassi: 1 2 3 4 5 6 7 8\n" +
            "testpassf: 1 2 3 4 5 6 7 8\n" +
            "testpassd: 1 2 3 4 5 6 7 8\n" +
            "testpassidf: 1 2 3\n"
            )
        
    def oldtestArmRunReturnVal(self):
        self.compileCheckArm(["-R", "/system/bin/accdata/data/returnval-ansi.c"],
            "Executing compiled code:\nresult: 42\n")

if __name__ == '__main__':
    if not outputCanRun():
        print "Many tests are expected to fail, because acc is not a 32-bit x86 Linux executable."
    unittest.main()

