int main() {
    int* pa = (int*) malloc(100);
    int* pb = pa + 1;
    int* pc = (int*) 0;
    *pa = 1;
    *pb = 2;
    printf("Pointer difference: %d %d\n", pb - pa, ((int) pb) - ((int) pa));
    int c = * (pa + 1);
    printf("Pointer addition: %d\n", c);
    printf("Pointer comparison to zero: %d %d %d\n", pa == 0, pb == 0, pc == 0);
    printf("Pointer comparison: %d %d %d %d %d\n", pa < pb, pa == pb, pa > pb, ! pb, ! pc);
    free(pa);
    return 0;
}

