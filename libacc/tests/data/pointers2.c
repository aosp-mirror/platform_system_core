// Test multiple levels of indirection

void testsingle() {
    int a = 0;
    int* pa = &a;
    printf("a = %d, *pa = %d\n", a, *pa);
    *pa = 2;
    printf("a = %d, *pa = %d\n", a, *pa);
}

void testdouble() {
    int a = 0;
    int* pa = &a;
    int** ppa = &pa;
    printf("a = %d, *pa = %d **ppa = %d\n", a, *pa, **ppa);
    **ppa = 2;
    printf("a = %d, *pa = %d **ppa = %d\n", a, *pa, **ppa);
}

void testtripple() {
    int a = 0;
    int* pa = &a;
    int** ppa = &pa;
    int*** pppa = &ppa;
    printf("a = %d, *pa = %d **ppa = %d\n ***pppa = %d", a, *pa, **ppa, ***pppa);
    ***pppa = 2;
    printf("a = %d, *pa = %d **ppa = %d\n ***pppa = %d", a, *pa, **ppa, ***pppa);
}

int main() {
    testsingle();
    testdouble();
    testdouble();
    return 0;
}
