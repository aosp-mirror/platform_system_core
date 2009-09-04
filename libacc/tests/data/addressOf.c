void testStruct() {
    struct str {
        float x;
        float y;
    };

    struct str base;
    int index = 0;

    base.x = 10.0;
    struct str *s = &base;

    float *v = &(*s).x;
    float *v2 = &s[index].x;
    printf("testStruct: %g %g %g\n",base.x, *v, *v2);
}

void testArray() {
    int a[2];
    a[0] = 1;
    a[1] = 2;
    int* p = &a[0];
    int* p2 = a;
    printf("testArray: %d %d %d\n", a[0], *p, *p2);
}

int main() {
    testStruct();
    testArray();
    return 0;
}
