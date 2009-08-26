// struct definition and declaration
struct a {
    int a;
    int b;
} c;

// Useless, but legal struct declaration
struct {
    int x;
};

// Useful anonymous struct declaration
struct {
    int y;
} anon1, anon2;

// forward declarations
struct a;
struct b;
struct c;

struct b {int a; int b; };

// struct c {b g; }; // syntax error.

// struct s {float c,a,b,c;} s; // duplicate struct member

struct c {struct b g; };

// struct a { int w; }; // error

void testCopying() {
    struct a {int a[10]; char c;} a, b;
    a.c = 37;
    b.c = 38;
    b = a;
    printf("testCopying: %d == %d\n", a.c, b.c);
}

void testUnion() {
    union u;
    union u {float f;int i;} u;
    u.f = 1.0f;
    printf("testUnion: %g == 0x%08x\n", u.f, u.i);
}

struct v {float x, y, z, w; };

void add(struct v* result, struct v* a, struct v* b) {
    result->x = a->x + b->x;
    result->y = a->y + b->y;
    result->z = a->z + b->z;
    result->w = a->w + b->w;
}

void set(struct v* v, float x, float y, float z, float w) {
    v->x = x;
    v->y = y;
    v->z = z;
    v->w = w;
}

void print(struct v* v) {
    printf("(%g, %g, %g, %g)\n", v->x, v->y, v->z, v->w);
}

void testArgs() {
    struct v a, b, c;
    set(&a, 1.0f, 2.0f, 3.0f, 4.0f);
    set(&b, 5.0f, 6.0f, 7.0f, 8.0f);
    add(&c, &a, &b);
    printf("testArgs: ");
    print(&c);
}

int main() {
    anon1.y = 3;
    anon2.y = anon1.y;

    testCopying();
    testUnion();
    testArgs();

    struct c cc;
    cc.g.a = 3;
    c.a = 1;
    c.b = 3;
    struct a {int x, y; } z;
    // struct a {int x, y; } z2;
    z.x = c.a;
    struct a *pA;
    pA = &z;
    pA->x += 5;
    return pA->x;
}
