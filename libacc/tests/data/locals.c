int a;

int f() {
    int a;
    printf("f 0: a = %d b = %d\n", a, b);
    a = 2;
    printf("f 1: a = %d\n", a);
}

int g(int a) {
    printf("g 0: a = %d\n", a);
    a = 3;
    printf("g 1: a = %d\n", a);
}

int h(int a) {
    int a; // gcc 4.3 says error: 'a' redeclared as different kind of symbol

    printf("h 0: a = %d\n", a);
    a = 4;
    printf("h 1: a = %d\n", a);
}

int globCheck() {
    fprintf(stdout, "globCheck()\n");
}

int fwdCheck() {
    b();
}

int b() {
    printf("b()\n");
}

int main() {
    globCheck();
    fwdCheck();
    printf("main 0: a = %d\n", a);
    a = 5;
    printf("main 1: a = %d\n", a);
    f();
    printf("main 2: a = %d\n", a);
    g(77);
    printf("main 3: a = %d\n", a);
    h(30);
    printf("main 4: a = %d\n", a);
    return 0;
}
