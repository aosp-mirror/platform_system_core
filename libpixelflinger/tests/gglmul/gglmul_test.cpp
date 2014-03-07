/*
 * Copyright (C) 2013 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "private/pixelflinger/ggl_fixed.h"

// gglClampx() tests
struct gglClampx_test_t
{
    GGLfixed input;
    GGLfixed output;
};

gglClampx_test_t gglClampx_tests[] =
{
    {FIXED_ONE + 1, FIXED_ONE},
    {FIXED_ONE, FIXED_ONE},
    {FIXED_ONE - 1, FIXED_ONE - 1},
    {1, 1},
    {0, 0},
    {FIXED_MIN,0}
};

void gglClampx_test()
{
    uint32_t i;

    printf("Testing gglClampx\n");
    for(i = 0; i < sizeof(gglClampx_tests)/sizeof(gglClampx_test_t); ++i)
    {
        gglClampx_test_t *test = &gglClampx_tests[i];
        printf("Test input=0x%08x output=0x%08x :",
                test->input, test->output);
        if(gglClampx(test->input) == test->output)
            printf("Passed\n");
        else
            printf("Failed\n");
    }
}

// gglClz() tests
struct gglClz_test_t
{
    GGLfixed input;
    GGLfixed output;
};

gglClz_test_t gglClz_tests[] =
{
    {0, 32},
    {1, 31},
    {-1,0}
};

void gglClz_test()
{
    uint32_t i;

    printf("Testing gglClz\n");
    for(i = 0; i < sizeof(gglClz_tests)/sizeof(gglClz_test_t); ++i)
    {
        gglClz_test_t *test = &gglClz_tests[i];
        printf("Test input=0x%08x output=%2d :", test->input, test->output);
        if(gglClz(test->input) == test->output)
            printf("Passed\n");
        else
            printf("Failed\n");
    }
}

// gglMulx() tests
struct gglMulx_test_t
{
    GGLfixed x;
    GGLfixed y;
    int      shift;
};

gglMulx_test_t gglMulx_tests[] =
{
    {1,1,1},
    {0,1,1},
    {FIXED_ONE,FIXED_ONE,16},
    {FIXED_MIN,FIXED_MAX,16},
    {FIXED_MAX,FIXED_MAX,16},
    {FIXED_MIN,FIXED_MIN,16},
    {FIXED_HALF,FIXED_ONE,16},
    {FIXED_MAX,FIXED_MAX,31},
    {FIXED_ONE,FIXED_MAX,31}
};

void gglMulx_test()
{
    uint32_t i;
    GGLfixed actual, expected;

    printf("Testing gglMulx\n");
    for(i = 0; i < sizeof(gglMulx_tests)/sizeof(gglMulx_test_t); ++i)
    {
        gglMulx_test_t *test = &gglMulx_tests[i];
        printf("Test x=0x%08x y=0x%08x shift=%2d :",
                test->x, test->y, test->shift);
        actual = gglMulx(test->x, test->y, test->shift);
        expected =
          ((int64_t)test->x * test->y + (1 << (test->shift-1))) >> test->shift;
    if(actual == expected)
        printf(" Passed\n");
    else
        printf(" Failed Actual(0x%08x) Expected(0x%08x)\n",
               actual, expected);
    }
}
// gglMulAddx() tests
struct gglMulAddx_test_t
{
    GGLfixed x;
    GGLfixed y;
    int      shift;
    GGLfixed a;
};

gglMulAddx_test_t gglMulAddx_tests[] =
{
    {1,2,1,1},
    {0,1,1,1},
    {FIXED_ONE,FIXED_ONE,16, 0},
    {FIXED_MIN,FIXED_MAX,16, FIXED_HALF},
    {FIXED_MAX,FIXED_MAX,16, FIXED_MIN},
    {FIXED_MIN,FIXED_MIN,16, FIXED_MAX},
    {FIXED_HALF,FIXED_ONE,16,FIXED_ONE},
    {FIXED_MAX,FIXED_MAX,31, FIXED_HALF},
    {FIXED_ONE,FIXED_MAX,31, FIXED_HALF}
};

void gglMulAddx_test()
{
    uint32_t i;
    GGLfixed actual, expected;

    printf("Testing gglMulAddx\n");
    for(i = 0; i < sizeof(gglMulAddx_tests)/sizeof(gglMulAddx_test_t); ++i)
    {
        gglMulAddx_test_t *test = &gglMulAddx_tests[i];
        printf("Test x=0x%08x y=0x%08x shift=%2d a=0x%08x :",
                test->x, test->y, test->shift, test->a);
        actual = gglMulAddx(test->x, test->y,test->a, test->shift);
        expected = (((int64_t)test->x * test->y) >> test->shift) + test->a;

        if(actual == expected)
            printf(" Passed\n");
        else
            printf(" Failed Actual(0x%08x) Expected(0x%08x)\n",
                    actual, expected);
    }
}
// gglMulSubx() tests
struct gglMulSubx_test_t
{
    GGLfixed x;
    GGLfixed y;
    int      shift;
    GGLfixed a;
};

gglMulSubx_test_t gglMulSubx_tests[] =
{
    {1,2,1,1},
    {0,1,1,1},
    {FIXED_ONE,FIXED_ONE,16, 0},
    {FIXED_MIN,FIXED_MAX,16, FIXED_HALF},
    {FIXED_MAX,FIXED_MAX,16, FIXED_MIN},
    {FIXED_MIN,FIXED_MIN,16, FIXED_MAX},
    {FIXED_HALF,FIXED_ONE,16,FIXED_ONE},
    {FIXED_MAX,FIXED_MAX,31, FIXED_HALF},
    {FIXED_ONE,FIXED_MAX,31, FIXED_HALF}
};

void gglMulSubx_test()
{
    uint32_t i;
    GGLfixed actual, expected;

    printf("Testing gglMulSubx\n");
    for(i = 0; i < sizeof(gglMulSubx_tests)/sizeof(gglMulSubx_test_t); ++i)
    {
        gglMulSubx_test_t *test = &gglMulSubx_tests[i];
        printf("Test x=0x%08x y=0x%08x shift=%2d a=0x%08x :",
                test->x, test->y, test->shift, test->a);
        actual = gglMulSubx(test->x, test->y, test->a, test->shift);
        expected = (((int64_t)test->x * test->y) >> test->shift) - test->a;

        if(actual == expected)
            printf(" Passed\n");
        else
            printf(" Failed Actual(0x%08x) Expected(0x%08x)\n",
                actual, expected);
    }
}

// gglMulii() tests

struct gglMulii_test_t
{
    int32_t x;
    int32_t y;
};

gglMulii_test_t gglMulii_tests[] =
{
    {1,INT32_MIN},
    {1,INT32_MAX},
    {0,INT32_MIN},
    {0,INT32_MAX},
    {INT32_MIN, INT32_MAX},
    {INT32_MAX, INT32_MIN},
    {INT32_MIN, INT32_MIN},
    {INT32_MAX, INT32_MAX}
};

void gglMulii_test()
{
    uint32_t i;
    int64_t actual, expected;

    printf("Testing gglMulii\n");
    for(i = 0; i < sizeof(gglMulii_tests)/sizeof(gglMulii_test_t); ++i)
    {
        gglMulii_test_t *test = &gglMulii_tests[i];
        printf("Test x=0x%08x y=0x%08x :", test->x, test->y);
        actual = gglMulii(test->x, test->y);
        expected = ((int64_t)test->x * test->y);

        if(actual == expected)
            printf(" Passed\n");
        else
            printf(" Failed Actual(%" PRId64 ") Expected(%" PRId64 ")\n",
                    actual, expected);
    }
}

int main(int /*argc*/, char** /*argv*/)
{
    gglClampx_test();
    gglClz_test();
    gglMulx_test();
    gglMulAddx_test();
    gglMulSubx_test();
    gglMulii_test();
    return 0;
}
