int ftoi(float f) {
    return f;
}

int dtoi(double d) {
    return d;
}

float itof(int i) {
    return i;
}

double itod(int i) {
    return i;
}

int main() {
    printf("int: %d float: %g double: %g\n", 1, 2.2f, 3.3);
    printf(" ftoi(1.4f)=%d\n", ftoi(1.4f));
    printf(" dtoi(2.4f)=%d\n", dtoi(2.4f));
    printf(" itof(3)=%g\n", itof(3));
    printf(" itod(4)=%g\n", itod(4));
    return 0;
}
