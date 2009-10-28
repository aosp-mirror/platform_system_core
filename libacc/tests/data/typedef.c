typedef short COORD;
typedef struct Point {
    COORD x;
    COORD y;
} Point;

void add(Point* result, Point* a, Point* b) {
    result->x = a->x + b->x;
    result->y = a->y + b->y;
}

void print(Point* p) {
    printf("(%d, %d)", p->x, p->y);
}

void set(Point* p, int x, int y) {
    p->x = x;
    p->y = y;
}

int main() {
    typedef char* String;
    String s = "x = %d\n";
    {
       typedef int item;
       item x = 3;
       printf(s, x);
    }
    Point a, b, c;
    set(&a, 1,2);
    set(&b, 3,4);
    add(&c, &a, &b);
    print(&c);
    printf(" = ");
    print(&a);
    printf(" + ");
    print(&b);
    printf("\n");
    return 0;
}
