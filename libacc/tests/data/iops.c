// Check integer operations

void loops() {
    int y;
    printf("++\n");
    for(y = 0; y < 10; y++) {
        printf("%d\n", y);
    }
    printf("--\n");
    for(y = 10; y >= 0; y--) {
        printf("%d\n", y);
    }
}

void checkLiterals() {
    printf("Literals: %d %d\n", 1, -1);
}

int main() {
    checkLiterals();
    loops();
    return 0;
}
