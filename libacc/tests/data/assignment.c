int main() {
    int a = 0;
    int b = 1;
    a = b = 2; // Test that "b = 2" generates an rvalue.
    if (a = 7) { // Test that a = 7 generates an rvalue.
        b = 3;
    }
    return a;
}
