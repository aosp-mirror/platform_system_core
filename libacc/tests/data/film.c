// Test logical and bitwise AND and OR

int test(int x, int y) {
    int v = x || y;
    return v;
}

int test2(int x, int y) {
    if(x | y) {
        return 1;
    } else {
        return 0;
    }
}

int test3(int x, int y) {
    int v = x && y;
    return v;
}

int test4(int x, int y) {
    if(x & y) {
        return 1;
    } else {
        return 0;
    }
}

int main(int index)
{
    int x,y;
    printf("testing...\n");
    int totalBad = 0;
    for(y = 0; y < 2; y++) {
        for(x = 0; x < 2; x++) {
            int a = test(x,y);
            int b = test2(x,y);
            if (a != b) {
                printf("Results differ: OR x=%d y=%d a=%d b=%d\n", x, y, a, b);
                totalBad++;
            }
            a = test3(x,y);
            b = test4(x,y);
            if (a != b) {
                printf("Results differ: AND x=%d y=%d a=%d b=%d\n", x, y, a, b);
                totalBad++;
            }
        }
    }
    printf("Total bad: %d\n", totalBad);
    return 0;
}

