void testBrackets(int* ar, int len) {
    int i;
    int errors = 0;
    for (i = 0; i < len; i++) {
        ar[i] = i;
    }
    for (i = 0; i < len; i++) {
        if (ar[i] != i) {
            printf("error: [%d] %d != %d\n", i, ar[i], i);
            errors++;
        }
    }
    printf("Errors: %d\n", errors);
}

void testBrackets2D(int** ar2D, int lenX, int lenY) {
    int x, y;
    int errors = 0;
    for (x = 0; x < lenX; x++) {
        for (y = 0; y < lenY; y++) {
            ar2D[x][y] = x * lenY + y;
        }
    }
    for (x = 0; x < lenX; x++) {
        for (y = 0; y < lenY; y++) {
            int expected = x * lenY + y;
            int val = ar2D[x][y];
            if (val != expected) {
                printf("error: [%d][%d] %d != %d\n", x, y, val, expected);
                errors++;
            }
        }
    }
    printf("2D Errors: %d\n", errors);
}

void testHeap() {
    int* ar = (int*) malloc(100);
    testBrackets(ar, 25);
    free(ar);
}

void testHeap2D() {
    int lenX = 10;
    int lenY = 5;
    int* ar = (int*) malloc(lenX * lenY * 4);
    int** ar2D = (int**) malloc(lenX * 4);
    int i;
    for(i = 0; i < lenX; i++) {
        ar2D[i] = ar + lenY * i;
    }
    testBrackets2D(ar2D, lenX, lenY);
    free(ar);
    free(ar2D);
}

int main() {
    testHeap();
    testHeap2D();
    return 0;
}
