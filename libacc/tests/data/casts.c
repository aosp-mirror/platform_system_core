void test1() {
    int a = 3;
    int* pb = &a;
    int c = *pb;
    printf("Reading from a pointer: %d %d\n", a, c);
    *pb = 4;
    printf("Writing to a pointer: %d\n", a);
    printf("Testing casts: %d %g %g %d\n", 3, (float) 3, 4.5, (int) 4.5);
}

void test2() {
    int x = 4;
    int px = &x;
    // int z = * px; // An error, expected a pointer type
    int y = * (int*) px;
    printf("Testing reading (int*): %d\n", y);
}

void test3() {
    int px = (int) malloc(120);
    * (int*) px = 8;
    * (int*) (px + 4) = 9;
    printf("Testing writing (int*): %d %d\n", * (int*) px, * (int*) (px + 4));
    free((void*) px);
}

void test4() {
    int x = 0x12345678;
    int px = &x;
    int a = * (char*) px;
    int b = * (char*) (px + 1);
    int c = * (char*) (px + 2);
    int d = * (char*) (px + 3);
    printf("Testing reading (char*): 0x%02x 0x%02x 0x%02x 0x%02x\n", a, b, c, d);
}

void test5() {
    int x = 0xFFFFFFFF;
    int px = &x;
    * (char*) px = 0x21;
    * (char*) (px + 1) = 0x43;
    * (char*) (px + 2) = 0x65;
    * (char*) (px + 3) = 0x87;
    printf("Testing writing (char*): 0x%08x\n", x);
}

int f(int b) {
    printf("f(%d)\n", b);
    return 7 * b;
}

void test6() {
    int fp = &f;
    int x = (*(int(*)()) fp)(10);
    printf("Function pointer result: %d\n", x);
}

void test7() {
    int px = (int) malloc(120);
    * (float*) px = 8.8f;
    * (float*) (px + 4) = 9.9f;
    printf("Testing read/write (float*): %g %g\n", * (float*) px, * (float*) (px + 4));
    free((void*) px);
}

void test8() {
    int px = (int) malloc(120);
    * (double*) px = 8.8;
    * (double*) (px + 8) = 9.9;
    printf("Testing read/write (double*): %g %g\n", * (double*) px, * (double*) (px + 8));
    free((void*) px);
}


int main() {
    test1();
    test2();
    test3();
    test4();
    test5();
    test6();
    test7();
    test8();
    return 0;
}
