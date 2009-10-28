#define A B + B
#define B C

int main() {
    int C = 3;
    printf("A = %d\n", A);
#define C 5
    printf("A = %d\n", A);
    return 0;
}
