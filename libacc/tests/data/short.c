short a = 3;
int main() {
    short* b = &a;
    *b = *b - 5;
    return a;
}
