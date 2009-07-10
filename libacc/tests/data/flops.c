// Test floating point operations.

void unaryOps() {
    // Unary ops
    printf("-%g = %g\n", 1.1, -1.1);
    printf("!%g = %d\n", 1.2, !1.2);
    printf("!%g = %d\n", 0.0, !0.0);
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
    comparisonTestid(1, 2.0);
    comparisonTestid(1, 1.0);
    comparisonTestid(2, 1.0);
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

void testpassi(int a, int b, int c, int d, int e, int f, int g, int h) {
    printf("testpassi: %d %d %d %d %d %d %d %d\n", a, b, c, d, e, f, g, h);
}

void testpassf(float a, float b, float c, float d, float e, float f, float g, float h) {
    printf("testpassf: %g %g %g %g %g %g %g %g\n", a, b, c, d, e, f, g, h);
}

void testpassd(double a, double b, double c, double d, double e, double f, double g, double h) {
    printf("testpassd: %g %g %g %g %g %g %g %g\n", a, b, c, d, e, f, g, h);
}

void testpassidf(int i, double d, float f) {
    printf("testpassidf: %d %g %g\n", i, d, f);
}

void testParameterPassing() {
    testpassi(1, 2, 3, 4, 5, 6, 7, 8);
    testpassf(1, 2, 3, 4, 5, 6, 7, 8);
    testpassd(1, 2, 3, 4, 5, 6, 7, 8);
    testpassidf(1, 2.0, 3.0f);
}

int main() {
    unaryOps();
    binaryOps();
    comparisonOps();
    testBranching();
    testParameterPassing();
    return 0;
}
