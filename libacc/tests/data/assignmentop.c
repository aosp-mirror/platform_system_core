// Test assignment operations

void testAssignment() {
    int a = 2;
    a *= 5;
    printf("2 *= 5  %d\n", a);
    a = 20;
    a /= 5;
    printf("20 /= 5  %d\n", a);
    a = 17;
    a %= 5;
    printf("17 %%= 5  %d\n", a);
    a = 17;
    a += 5;
    printf("17 += 5  %d\n", a);
    a = 17;
    a-=5;
    printf("17 -= 5  %d\n", a);
    a = 17;
    a<<=1;
    printf("17<<= 1  %d\n", a);
    a = 17;
    a>>=1;
    printf("17>>= 1  %d\n", a);
    a = 17;
    a&=1;
    printf("17&= 1  %d\n", a);
    a = 17;
    a^=1;
    printf("17^= 1  %d\n", a);
    a = 16;
    a^=1;
    printf("16|= 1  %d\n", a);
}

int a;

int* f() {
    printf("f()\n");
    return &a;
}

void testEval() {
    a = 0;
    printf("*f() = *f() + 10;\n");
    *f() = *f() + 10;
    printf("a = %d\n", a);
}

void testOpEval() {
    a = 0;
    printf("*f() += 10;\n");
    *f() += 10;
    printf("a = %d\n", a);
}

int main() {
    testAssignment();
    testEval();
    testOpEval();
    return 0;
}
