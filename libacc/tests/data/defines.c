// Simple tests of the C preprocessor

#define A (4 / 2)
#define B 1 // This is a comment. With a / in it.

int main() {
    return A + B;
}
