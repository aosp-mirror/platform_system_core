#ifndef KEYWORD
#define __MAKE_KEYWORD_ENUM__
#define KEYWORD(symbol, flags, nargs) K_##symbol,
enum {
    K_UNKNOWN,
#endif
    KEYWORD(subsystem,      SECTION,    1)
    KEYWORD(devname,        OPTION,     1)
    KEYWORD(dirname,        OPTION,     1)
#ifdef __MAKE_KEYWORD_ENUM__
    KEYWORD_COUNT,
};
#undef __MAKE_KEYWORD_ENUM__
#undef KEYWORD
#endif
