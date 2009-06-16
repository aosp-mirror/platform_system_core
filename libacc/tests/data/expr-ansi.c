/* Test operators */

void testInc() { int a, b; a = 3; b = a++; printf("3++ = %d %d\n", b, a); }
void testDec() { int a, b; a = 3; b = a--; printf("3-- = %d %d\n", b, a); }
void testTimes(){ printf("%d * %d = %d\n", 10, 4, 10 * 4); }
void testDiv(){ printf("%d / %d = %d\n", 11, 4, 11 / 4); }
void testMod(){ printf("%d %% %d = %d\n", 11, 4, 11 % 4); }
void testPlus(){ printf("%d + %d = %d\n", 10, 4, 10 + 4); }
void testMinus(){ printf("%d - %d = %d\n", 10, 4, 10 - 4); }
void testShiftLeft(){ printf("%d << %d = %d\n", 10, 4, 10 << 4); }
void testShiftRight(){ printf("%d >> %d = %d\n", 100, 4, 100 >> 4); }
void testLess(){ printf("%d < %d = %d\n", 10, 4, 10 < 4); }
void testLesEqual(){ printf("%d <= %d = %d\n", 10, 4, 10 <= 4); }
void testGreater(){ printf("%d > %d = %d\n", 10, 4, 10 > 4); }
void testGreaterEqual(){ printf("%d >= %d = %d\n", 10, 4, 10 >= 4); }
void testEqualTo(){ printf("%d == %d = %d\n", 10, 4, 10 == 4); }
void testNotEqualTo(){ printf("%d != %d = %d\n", 10, 4, 10 != 4); }
void testBitAnd(){ printf("%d & %d = %d\n", 10, 7, 10 & 7); }
void testBitXor(){ printf("%d ^ %d = %d\n", 10, 7, 10 ^ 7); }
void testBitOr(){ printf("%d | %d = %d\n", 10, 4, 10 | 4); }
void testAssignment(){ int a, b; a = 3; b = a; printf("b == %d\n", b); }
void testLogicalAnd(){ printf("%d && %d = %d\n", 10, 4, 10 && 4); }
void testLogicalOr(){ printf("%d || %d = %d\n", 10, 4, 10 || 4); }
void testAddressOf(){ int a; printf("&a is %d\n", &a); }
void testPointerIndirection(){ int a, b; a = &b; b = 17; printf("*%d  = %d =?= %d\n", a, * (int*) a, b); }
void testNegation(){ printf("-%d = %d\n", 10, -10); }
void testUnaryPlus(){ printf("+%d = %d\n", 10, +10); }
void testUnaryNot(){ printf("!%d = %d\n", 10, !10); }
void testBitNot(){ printf("~%d = %d\n", 10, ~10); }

int main(int a, char** b) {
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
