#pragma once

#include <inttypes.h>
#include <stdlib.h>

#include <string>

#include <bootimg.h>

/* util stuff */
double now();
void set_verbose();

// These printf-like functions are implemented in terms of vsnprintf, so they
// use the same attribute for compile-time format string checking.
void die(const char* fmt, ...) __attribute__((__noreturn__))
__attribute__((__format__(__printf__, 1, 2)));

void verbose(const char* fmt, ...) __attribute__((__format__(__printf__, 1, 2)));

void die(const std::string& str) __attribute__((__noreturn__));
