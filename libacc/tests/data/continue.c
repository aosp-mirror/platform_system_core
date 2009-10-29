int main() {
    int i, j, sum;
    sum = 0;
    for (i = 0; i < 10; i++) {
        if (i & 1) continue;
        for (j = 0; j < 10; j++) {
            if (j & 1) continue;
            sum += i * j;
        }
    }
    return sum;
}

