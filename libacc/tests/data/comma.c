int testReturn() {
    return 10, 20, 30;
}

int testArg(int a) {
    return a;
}

void testComma() {
    int a;
    0, a = 10,20;
    printf("statement: %d\n", a);
    a = 1;
    if (a = 0, 1) {
        printf("if: a = %d\n", a);
    }
    int b = 0;
    a = 10;
    while(b++,a--) {}
    printf("while: b = %d\n", b);
    b = 0;
    for(b++,a = 0;b++, a < 10; b++, a++) {}
    printf("for: b = %d\n", b);
    b = testReturn();
    printf("return: %d\n", b);
    b = testArg((a,12));
    printf("arg: %d\n", b);
}



int main() {
    testComma();
    return 0;
}
