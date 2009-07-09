// Test floating point operations.

void unaryOps() {
    // Unary ops
    printf("-%g = %g\n", 1.1, -1.1);
    printf("!%g = %d\n", 1.2, !1.2);
    printf("!%g = %d\n", 0.0, !0,0);
}

void binaryOps() {
    printf("double op double:\n");
    printf("%g + %g = %g\n", 1.0, 2.0, 1.0 + 2.0);
    printf("%g - %g = %g\n", 1.0, 2.0, 1.0 - 2.0);
    printf("%g * %g = %g\n", 1.0, 2.0, 1.0 * 2.0);
    printf("%g / %g = %g\n", 1.0, 2.0, 1.0 / 2.0);

    printf("float op float:\n");
    printf("%g + %g = %g\n", 1.0f, 2.0f, 1.0f + 2.0f);
    printf("%g - %g = %g\n", 1.0f, 2.0f, 1.0f - 2.0f);
    printf("%g * %g = %g\n", 1.0f, 2.0f, 1.0f * 2.0f);
    printf("%g / %g = %g\n", 1.0f, 2.0f, 1.0f / 2.0f);

    printf("double op float:\n");
    printf("%g + %g = %g\n", 1.0, 2.0f, 1.0 + 2.0f);
    printf("%g - %g = %g\n", 1.0, 2.0f, 1.0 - 2.0f);
    printf("%g * %g = %g\n", 1.0, 2.0f, 1.0 * 2.0f);
    printf("%g / %g = %g\n", 1.0, 2.0f, 1.0 / 2.0f);

    printf("double op int:\n");
    printf("%g + %d = %g\n", 1.0, 2, 1.0 + 2);
    printf("%g - %d = %g\n", 1.0, 2, 1.0 - 2);
    printf("%g * %d = %g\n", 1.0, 2, 1.0 * 2);
    printf("%g / %d = %g\n", 1.0, 2, 1.0 / 2);

    printf("int op double:\n");
    printf("%d + %g = %g\n", 1, 2.0, 1 + 2.0);
    printf("%d - %g = %g\n", 1, 2.0, 1 - 2.0);
    printf("%d * %g = %g\n", 1, 2.0, 1 * 2.0);
    printf("%d / %g = %g\n", 1, 2.0, 1 / 2.0);
}

void comparisonTestdd(double a, double b) {
    printf("%g op %g: < %d   <= %d   == %d   >= %d   > %d   != %d\n",
           a, b, a < b, a <= b, a == b, a >= b, a > b, a != b);
}

void comparisonOpsdd() {
    printf("double op double:\n");
    comparisonTestdd(1.0, 2.0);
    comparisonTestdd(1.0, 1.0);
    comparisonTestdd(2.0, 1.0);
}


void comparisonTestdf(double a, float b) {
    printf("%g op %g: < %d   <= %d   == %d   >= %d   > %d   != %d\n",
           a, b, a < b, a <= b, a == b, a >= b, a > b, a != b);
}

void comparisonOpsdf() {
    printf("double op float:\n");
    comparisonTestdf(1.0, 2.0f);
    comparisonTestdf(1.0, 1.0f);
    comparisonTestdf(2.0, 1.0f);
}

void comparisonTestff(float a, float b) {
    printf("%g op %g: < %d   <= %d   == %d   >= %d   > %d   != %d\n",
           a, b, a < b, a <= b, a == b, a >= b, a > b, a != b);
}

void comparisonOpsff() {
    printf("float op float:\n");
    comparisonTestff(1.0f, 2.0f);
    comparisonTestff(1.0f, 1.0f);
    comparisonTestff(2.0f, 1.0f);
}
void comparisonTestid(int a, double b) {
    printf("%d op %g: < %d   <= %d   == %d   >= %d   > %d   != %d\n",
           a, b, a < b, a <= b, a == b, a >= b, a > b, a != b);
}

void comparisonOpsid() {
    printf("int op double:\n");
    comparisonTestid(1, 2.0f);
    comparisonTestid(1, 1.0f);
    comparisonTestid(2, 1.0f);
}
void comparisonTestdi(double a, int b) {
    printf("%g op %d: < %d   <= %d   == %d   >= %d   > %d   != %d\n",
           a, b, a < b, a <= b, a == b, a >= b, a > b, a != b);
}

void comparisonOpsdi() {
    printf("double op int:\n");
    comparisonTestdi(1.0f, 2);
    comparisonTestdi(1.0f, 1);
    comparisonTestdi(2.0f, 1);
}

void comparisonOps() {
    comparisonOpsdd();
    comparisonOpsdf();
    comparisonOpsff();
    comparisonOpsid();
    comparisonOpsdi();
}

int branch(double d) {
    if (d) {
        return 1;
    }
    return 0;
}

void testBranching() {
    printf("branching: %d %d %d\n", branch(-1.0), branch(0.0), branch(1.0));
}

int main() {
    unaryOps();
    binaryOps();
    comparisonOps();
    testBranching();
    return 0;
}
