#define FOO 0x10

int main() {
    printf("0 = %d\n", 0);
    printf("010 = %d\n", 010);
    printf("0x10 = %d\n", FOO);
    printf("'\\a' = %d\n", '\a');
    printf("'\\b' = %d\n", '\b');
    printf("'\\f' = %d\n", '\f');
    printf("'\\n' = %d\n", '\n');
    printf("'\\r' = %d\n", '\r');
    printf("'\\t' = %d\n", '\t');
    printf("'\\v' = %d\n", '\v');
    // Undefined
    // printf("'\\z' = %d\n", '\z');
    printf("'\\\\' = %d\n", '\\');
    printf("'\\'' = %d\n", '\'');
    printf("'\\\"' = %d\n", '\"');
    printf("'\\?' = %d\n", '\?');
    printf("'\\0' = %d\n", '\0');
    printf("'\\1' = %d\n", '\1');
    printf("'\\12' = %d\n", '\12');
    printf("'\\123' = %d\n", '\123');
    printf("'\\x0' = %d\n", '\x0');
    printf("'\\x1' = %d\n", '\x1');
    printf("'\\x12' = %d\n", '\x12');
    printf("'\\x123' = %d\n", '\x123');
    printf("'\\x1f' = %d\n", '\x1f');
    printf("'\\x1F' = %d\n", '\x1F');
}
