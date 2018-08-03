/* libs/pixelflinger/fixed.cpp
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <stdio.h>

#include <private/pixelflinger/ggl_context.h>
#include <private/pixelflinger/ggl_fixed.h>


// ------------------------------------------------------------------------

int32_t gglRecipQNormalized(int32_t x, int* exponent)
{
    const int32_t s = x>>31;
    uint32_t a = s ? -x : x;

    // the result will overflow, so just set it to the biggest/inf value
    if (ggl_unlikely(a <= 2LU)) {
        *exponent = 0;
        return s ? FIXED_MIN : FIXED_MAX;
    }

    // Newton-Raphson iteration:
    // x = r*(2 - a*r)

    const int32_t lz = gglClz(a);
    a <<= lz;  // 0.32
    uint32_t r = a;
    // note: if a == 0x80000000, this means x was a power-of-2, in this
    // case we don't need to compute anything. We get the reciprocal for
    // (almost) free.
    if (a != 0x80000000) {
        r = (0x2E800 << (30-16)) - (r>>(2-1)); // 2.30, r = 2.90625 - 2*a
        // 0.32 + 2.30 = 2.62 -> 2.30
        // 2.30 + 2.30 = 4.60 -> 2.30
        r = (((2LU<<30) - uint32_t((uint64_t(a)*r) >> 32)) * uint64_t(r)) >> 30;
        r = (((2LU<<30) - uint32_t((uint64_t(a)*r) >> 32)) * uint64_t(r)) >> 30;
    }

    // shift right 1-bit to make room for the sign bit
    *exponent = 30-lz-1;
    r >>= 1;
    return s ? -r : r;
}

int32_t gglRecipQ(GGLfixed x, int q)
{
    int shift;
    x = gglRecipQNormalized(x, &shift);
    shift += 16-q;
    if (shift > 0)
        x += 1L << (shift-1);   // rounding
    x >>= shift;
    return x;
}    

// ------------------------------------------------------------------------

static const GGLfixed ggl_sqrt_reciproc_approx_tab[8] = {
    // 1/sqrt(x) with x = 1-N/16, N=[8...1]
    0x16A09, 0x15555, 0x143D1, 0x134BF, 0x1279A, 0x11C01, 0x111AC, 0x10865
};

GGLfixed gglSqrtRecipx(GGLfixed x)
{
    if (x == 0)         return FIXED_MAX;
    if (x == FIXED_ONE) return x;
    const GGLfixed a = x;
    const int32_t lz = gglClz(x);
    x = ggl_sqrt_reciproc_approx_tab[(a>>(28-lz))&0x7];
    const int32_t exp = lz - 16;
    if (exp <= 0)   x >>= -exp>>1;
    else            x <<= (exp>>1) + (exp & 1);        
    if (exp & 1) {
        x = gglMulx(x, ggl_sqrt_reciproc_approx_tab[0])>>1;
    }
    // 2 Newton-Raphson iterations: x = x/2*(3-(a*x)*x)
    x = gglMulx((x>>1),(0x30000 - gglMulx(gglMulx(a,x),x)));
    x = gglMulx((x>>1),(0x30000 - gglMulx(gglMulx(a,x),x)));
    return x;
}

GGLfixed gglSqrtx(GGLfixed a)
{
    // Compute a full precision square-root (24 bits accuracy)
    GGLfixed r = 0;
    GGLfixed bit = 0x800000;
    int32_t bshift = 15;
    do {
        GGLfixed temp = bit + (r<<1);
        if (bshift >= 8)    temp <<= (bshift-8);
        else                temp >>= (8-bshift);
        if (a >= temp) {
            r += bit;
            a -= temp;
        }
        bshift--;
    } while (bit>>=1);
    return r;
}

// ------------------------------------------------------------------------

static const GGLfixed ggl_log_approx_tab[] = {
    // -ln(x)/ln(2) with x = N/16, N=[8...16]
    0xFFFF, 0xd47f, 0xad96, 0x8a62, 0x6a3f, 0x4caf, 0x3151, 0x17d6, 0x0000
};

static const GGLfixed ggl_alog_approx_tab[] = { // domain [0 - 1.0]
	0xffff, 0xeac0, 0xd744, 0xc567, 0xb504, 0xa5fe, 0x9837, 0x8b95, 0x8000
};

GGLfixed gglPowx(GGLfixed x, GGLfixed y)
{
    // prerequisite: 0 <= x <= 1, and y >=0

    // pow(x,y) = 2^(y*log2(x))
    // =  2^(y*log2(x*(2^exp)*(2^-exp))))
    // =  2^(y*(log2(X)-exp))
    // =  2^(log2(X)*y - y*exp)
    // =  2^( - (-log2(X)*y + y*exp) )
    
    int32_t exp = gglClz(x) - 16;
    GGLfixed f = x << exp;
    x = (f & 0x0FFF)<<4;
    f = (f >> 12) & 0x7;
    GGLfixed p = gglMulAddx(
            ggl_log_approx_tab[f+1] - ggl_log_approx_tab[f], x,
            ggl_log_approx_tab[f]);
    p = gglMulAddx(p, y, y*exp);
    exp = gglFixedToIntFloor(p);
    if (exp < 31) {
        p = gglFracx(p);
        x = (p & 0x1FFF)<<3;
        p >>= 13;    
        p = gglMulAddx(
                ggl_alog_approx_tab[p+1] - ggl_alog_approx_tab[p], x,
                ggl_alog_approx_tab[p]);
        p >>= exp;
    } else {
        p = 0;
    }
    return p;
        // ( powf((a*65536.0f), (b*65536.0f)) ) * 65536.0f;
}

// ------------------------------------------------------------------------

int32_t gglDivQ(GGLfixed n, GGLfixed d, int32_t i)
{
    //int32_t r =int32_t((int64_t(n)<<i)/d);
    const int32_t ds = n^d;
    if (n<0) n = -n;
    if (d<0) d = -d;
    int nd = gglClz(d) - gglClz(n);
    i += nd + 1;
    if (nd > 0) d <<= nd;
    else        n <<= -nd;
    uint32_t q = 0;

    int j = i & 7;
    i >>= 3;

    // gcc deals with the code below pretty well.
    // we get 3.75 cycles per bit in the main loop
    // and 8 cycles per bit in the termination loop
    if (ggl_likely(i)) {
        n -= d;
        do {
            q <<= 8;
            if (n>=0)   q |= 128;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 64;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 32;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 16;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 8;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 4;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 2;
            else        n += d;
            n = n*2 - d;
            if (n>=0)   q |= 1;
            else        n += d;
            
            if (--i == 0)
                goto finish;

            n = n*2 - d;
        } while(true);
        do {
            q <<= 1;
            n = n*2 - d;
            if (n>=0)   q |= 1;
            else        n += d;
        finish: ;
        } while (j--);
        return (ds<0) ? -q : q;
    }

    n -= d;
    if (n>=0)   q |= 1;
    else        n += d;
    j--;
    goto finish;
}

// ------------------------------------------------------------------------

// assumes that the int32_t values of a, b, and c are all positive
// use when both a and b are larger than c

template <typename T>
static inline void swap(T& a, T& b) {
    T t(a);
    a = b;
    b = t;
}

static __attribute__((noinline))
int32_t slow_muldiv(uint32_t a, uint32_t b, uint32_t c)
{
	// first we compute a*b as a 64-bit integer
    // (GCC generates umull with the code below)
    uint64_t ab = uint64_t(a)*b;
    uint32_t hi = ab>>32;
    uint32_t lo = ab;
    uint32_t result;

	// now perform the division
	if (hi >= c) {
	overflow:
		result = 0x7fffffff;  // basic overflow
	} else if (hi == 0) {
		result = lo/c;  // note: c can't be 0
		if ((result >> 31) != 0)  // result must fit in 31 bits
			goto overflow;
	} else {
		uint32_t r = hi;
		int bits = 31;
	    result = 0;
		do {
			r = (r << 1) | (lo >> 31);
			lo <<= 1;
			result <<= 1;
			if (r >= c) {
				r -= c;
				result |= 1;
			}
		} while (bits--);
	}
	return int32_t(result);
}

// assumes a >= 0 and c >= b >= 0
static inline
int32_t quick_muldiv(int32_t a, int32_t b, int32_t c)
{
    int32_t r = 0, q = 0, i;
    int leading = gglClz(a);
    i = 32 - leading;
    a <<= leading;
    do {
        r <<= 1;
        if (a < 0)
            r += b;
        a <<= 1;
        q <<= 1;
        if (r >= c) {
            r -= c;
            q++;
        }
        asm(""::); // gcc generates better code this way
        if (r >= c) {
            r -= c;
            q++;
        }
    }
    while (--i);
    return q;
}

// this function computes a*b/c with 64-bit intermediate accuracy
// overflows (e.g. division by 0) are handled and return INT_MAX

int32_t gglMulDivi(int32_t a, int32_t b, int32_t c)
{
	int32_t result;
	int32_t sign = a^b^c;

	if (a < 0) a = -a;
	if (b < 0) b = -b;
	if (c < 0) c = -c;

    if (a < b) {
        swap(a, b);
    }
    
	if (b <= c) result = quick_muldiv(a, b, c);
	else        result = slow_muldiv((uint32_t)a, (uint32_t)b, (uint32_t)c);
	
	if (sign < 0)
		result = -result;
	  
    return result;
}
