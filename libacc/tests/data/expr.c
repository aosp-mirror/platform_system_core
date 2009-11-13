/* Test operators */

testInc() { int a, b; a = 3; b = a++; printf("3++ = %d %d\n", b, a); }
testDec() { int a, b; a = 3; b = a--; printf("3-- = %d %d\n", b, a); }
testTimes(){ printf("%d * %d = %d\n", 10, 4, 10 * 4); }
testDiv(){ printf("%d / %d = %d\n", 11, 4, 11 / 4); }
testMod(){ printf("%d %% %d = %d\n", 11, 4, 11 % 4); }
testPlus(){ printf("%d + %d = %d\n", 10, 4, 10 + 4); }
testMinus(){ printf("%d - %d = %d\n", 10, 4, 10 - 4); }
testShiftLeft(){ printf("%d << %d = %d\n", 10, 4, 10 << 4); }
testShiftRight(){ printf("%d >> %d = %d\n", 100, 4, 100 >> 4); }
testLess(){ printf("%d < %d = %d\n", 10, 4, 10 < 4); }
testLesEqual(){ printf("%d <= %d = %d\n", 10, 4, 10 <= 4); }
testGreater(){ printf("%d > %d = %d\n", 10, 4, 10 > 4); }
testGreaterEqual(){ printf("%d >= %d = %d\n", 10, 4, 10 >= 4); }
testEqualTo(){ printf("%d == %d = %d\n", 10, 4, 10 == 4); }
testNotEqualTo(){ printf("%d != %d = %d\n", 10, 4, 10 != 4); }
testBitAnd(){ printf("%d & %d = %d\n", 10, 7, 10 & 7); }
testBitXor(){ printf("%d ^ %d = %d\n", 10, 7, 10 ^ 7); }
testBitOr(){ printf("%d | %d = %d\n", 10, 4, 10 | 4); }
testAssignment(){ int a, b; a = 3; b = a; printf("b == %d\n", b); }
testLogicalAnd(){ printf("%d && %d = %d\n", 10, 4, 10 && 4); }
testLogicalOr(){ printf("%d || %d = %d\n", 10, 4, 10 || 4); }
testAddressOf(){ int a; printf("&a is %d\n", &a); }
testPointerIndirection(){ int a, b; a = &b; b = 17; printf("*%d  = %d =?= %d\n", a, * (int*) a, b); }
testNegation(){ printf("-%d = %d\n", 10, -10); }
testUnaryPlus(){ printf("+%d = %d\n", 10, +10); }
testUnaryNot(){ printf("!%d = %d\n", 10, !10); }
testBitNot(){ printf("~%d = %d\n", 10, ~10); }

main(a,b) {
    testInc();
    testDec();
    testTimes();
    testDiv();
    testMod();
    testPlus();
    testMinus();
    testShiftLeft();
    testShiftRight();
    testLess();
    testLesEqual();
    testGreater();
    testGreaterEqual();
    testEqualTo();
    testNotEqualTo();
    testBitAnd();
    testBinXor();
    testBitOr();
    testAssignment();
    testLogicalAnd();
    testLogicalOr();
    testAddressOf();
    testPointerIndirection();
    testNegation();
    testUnaryPlus();
    testUnaryNot();
    testBitNot();
    return 0;
}