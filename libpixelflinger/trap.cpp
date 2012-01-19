/* libs/pixelflinger/trap.cpp
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "trap.h"
#include "picker.h"

#include <cutils/log.h>
#include <cutils/memory.h>

namespace android {

// ----------------------------------------------------------------------------

// enable to see triangles edges
#define DEBUG_TRANGLES  0

// ----------------------------------------------------------------------------

static void pointx_validate(void *con, const GGLcoord* c, GGLcoord r);
static void pointx(void *con, const GGLcoord* c, GGLcoord r);
static void aa_pointx(void *con, const GGLcoord* c, GGLcoord r);
static void aa_nice_pointx(void *con, const GGLcoord* c, GGLcoord r);

static void linex_validate(void *con, const GGLcoord* v0, const GGLcoord* v1, GGLcoord w);
static void linex(void *con, const GGLcoord* v0, const GGLcoord* v1, GGLcoord w);
static void aa_linex(void *con, const GGLcoord* v0, const GGLcoord* v1, GGLcoord w);

static void recti_validate(void* c, GGLint l, GGLint t, GGLint r, GGLint b); 
static void recti(void* c, GGLint l, GGLint t, GGLint r, GGLint b); 

static void trianglex_validate(void*,
        const GGLcoord*, const GGLcoord*, const GGLcoord*);
static void trianglex_small(void*,
        const GGLcoord*, const GGLcoord*, const GGLcoord*);
static void trianglex_big(void*,
        const GGLcoord*, const GGLcoord*, const GGLcoord*);
static void aa_trianglex(void*,
        const GGLcoord*, const GGLcoord*, const GGLcoord*);
static void trianglex_debug(void* con,
        const GGLcoord*, const GGLcoord*, const GGLcoord*);

static void aapolyx(void* con,
        const GGLcoord* pts, int count);

static inline int min(int a, int b) CONST;
static inline int max(int a, int b) CONST;
static inline int min(int a, int b, int c) CONST;
static inline int max(int a, int b, int c) CONST;

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Tools
#endif

inline int min(int a, int b) {
    return a<b ? a : b;
}
inline int max(int a, int b) {
    return a<b ? b : a;
}
inline int min(int a, int b, int c) {
    return min(a,min(b,c));
}
inline int max(int a, int b, int c) {
    return max(a,max(b,c));
}

template <typename T>
static inline void swap(T& a, T& b) {
    T t(a);
    a = b;
    b = t;
}

static void
triangle_dump_points( const GGLcoord*  v0,
                      const GGLcoord*  v1,
                      const GGLcoord*  v2 )
{
    float tri = 1.0f / TRI_ONE;
    ALOGD("  P0=(%.3f, %.3f)  [%08x, %08x]\n"
          "  P1=(%.3f, %.3f)  [%08x, %08x]\n"
          "  P2=(%.3f, %.3f)  [%08x, %08x]\n",
          v0[0]*tri, v0[1]*tri, v0[0], v0[1],
          v1[0]*tri, v1[1]*tri, v1[0], v1[1],
          v2[0]*tri, v2[1]*tri, v2[0], v2[1] );
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Misc
#endif

void ggl_init_trap(context_t* c)
{
    ggl_state_changed(c, GGL_PIXEL_PIPELINE_STATE|GGL_TMU_STATE|GGL_CB_STATE);
}

void ggl_state_changed(context_t* c, int flags)
{
    if (ggl_likely(!c->dirty)) {
        c->procs.pointx     = pointx_validate;
        c->procs.linex      = linex_validate;
        c->procs.recti      = recti_validate;
        c->procs.trianglex  = trianglex_validate;
    }
    c->dirty |= uint32_t(flags);
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Point
#endif

void pointx_validate(void *con, const GGLcoord* v, GGLcoord rad)
{
    GGL_CONTEXT(c, con);
    ggl_pick(c);
    if (c->state.needs.p & GGL_NEED_MASK(P_AA)) {
        if (c->state.enables & GGL_ENABLE_POINT_AA_NICE) {
            c->procs.pointx = aa_nice_pointx;
        } else {
            c->procs.pointx = aa_pointx;
        }
    } else {
        c->procs.pointx = pointx;
    }
    c->procs.pointx(con, v, rad);
}

void pointx(void *con, const GGLcoord* v, GGLcoord rad)
{
    GGL_CONTEXT(c, con);
    GGLcoord halfSize = TRI_ROUND(rad) >> 1;
    if (halfSize == 0)
        halfSize = TRI_HALF;
    GGLcoord xc = v[0]; 
    GGLcoord yc = v[1];
    if (halfSize & TRI_HALF) { // size odd
        xc = TRI_FLOOR(xc) + TRI_HALF;
        yc = TRI_FLOOR(yc) + TRI_HALF;
    } else { // size even
        xc = TRI_ROUND(xc);
        yc = TRI_ROUND(yc);
    }
    GGLint l = (xc - halfSize) >> TRI_FRACTION_BITS;
    GGLint t = (yc - halfSize) >> TRI_FRACTION_BITS;
    GGLint r = (xc + halfSize) >> TRI_FRACTION_BITS;
    GGLint b = (yc + halfSize) >> TRI_FRACTION_BITS;
    recti(c, l, t, r, b);
}

// This way of computing the coverage factor, is more accurate and gives
// better results for small circles, but it is also a lot slower.
// Here we use super-sampling.
static int32_t coverageNice(GGLcoord x, GGLcoord y, 
        GGLcoord rmin, GGLcoord rmax, GGLcoord rr)
{
    const GGLcoord d2 = x*x + y*y;
    if (d2 >= rmax) return 0;
    if (d2 < rmin)  return 0x7FFF;

    const int kSamples              =  4;
    const int kInc                  =  4;    // 1/4 = 0.25
    const int kCoverageUnit         =  1;    // 1/(4^2) = 0.0625
    const GGLcoord kCoordOffset     = -6;    // -0.375

    int hits = 0;
    int x_sample = x + kCoordOffset;
    for (int i=0 ; i<kSamples ; i++, x_sample += kInc) {
        const int xval = rr - (x_sample * x_sample);
        int y_sample = y + kCoordOffset;
        for (int j=0 ; j<kSamples ; j++, y_sample += kInc) {
            if (xval - (y_sample * y_sample) > 0)
                hits += kCoverageUnit;
        }
    }
    return min(0x7FFF, hits << (15 - kSamples));
}


void aa_nice_pointx(void *con, const GGLcoord* v, GGLcoord size)
{
    GGL_CONTEXT(c, con);

    GGLcoord rad = ((size + 1)>>1);
    GGLint l = (v[0] - rad) >> TRI_FRACTION_BITS;
    GGLint t = (v[1] - rad) >> TRI_FRACTION_BITS;
    GGLint r = (v[0] + rad + (TRI_ONE-1)) >> TRI_FRACTION_BITS;
    GGLint b = (v[1] + rad + (TRI_ONE-1)) >> TRI_FRACTION_BITS;
    GGLcoord xstart = TRI_FROM_INT(l) - v[0] + TRI_HALF; 
    GGLcoord ystart = TRI_FROM_INT(t) - v[1] + TRI_HALF; 

    // scissor...
    if (l < GGLint(c->state.scissor.left)) {
        xstart += TRI_FROM_INT(c->state.scissor.left-l);
        l = GGLint(c->state.scissor.left);
    }
    if (t < GGLint(c->state.scissor.top)) {
        ystart += TRI_FROM_INT(c->state.scissor.top-t);
        t = GGLint(c->state.scissor.top);
    }
    if (r > GGLint(c->state.scissor.right)) {
        r = GGLint(c->state.scissor.right);
    }
    if (b > GGLint(c->state.scissor.bottom)) {
        b = GGLint(c->state.scissor.bottom);
    }

    int xc = r - l;
    int yc = b - t;
    if (xc>0 && yc>0) {
        int16_t* covPtr = c->state.buffers.coverage;
        const int32_t sqr2Over2 = 0xC; // rounded up
        GGLcoord rr = rad*rad;
        GGLcoord rmin = (rad - sqr2Over2)*(rad - sqr2Over2);
        GGLcoord rmax = (rad + sqr2Over2)*(rad + sqr2Over2);
        GGLcoord y = ystart;
        c->iterators.xl = l;
        c->iterators.xr = r;
        c->init_y(c, t);
        do {
            // compute coverage factors for each pixel
            GGLcoord x = xstart;
            for (int i=l ; i<r ; i++) {
                covPtr[i] = coverageNice(x, y, rmin, rmax, rr);
                x += TRI_ONE;
            }
            y += TRI_ONE;
            c->scanline(c);
            c->step_y(c);
        } while (--yc);
    }
}

// This is a cheap way of computing the coverage factor for a circle.
// We just lerp between the circles of radii r-sqrt(2)/2 and r+sqrt(2)/2
static inline int32_t coverageFast(GGLcoord x, GGLcoord y,
        GGLcoord rmin, GGLcoord rmax, GGLcoord scale)
{
    const GGLcoord d2 = x*x + y*y;
    if (d2 >= rmax) return 0;
    if (d2 < rmin)  return 0x7FFF;
    return 0x7FFF - (d2-rmin)*scale;
}

void aa_pointx(void *con, const GGLcoord* v, GGLcoord size)
{
    GGL_CONTEXT(c, con);

    GGLcoord rad = ((size + 1)>>1);
    GGLint l = (v[0] - rad) >> TRI_FRACTION_BITS;
    GGLint t = (v[1] - rad) >> TRI_FRACTION_BITS;
    GGLint r = (v[0] + rad + (TRI_ONE-1)) >> TRI_FRACTION_BITS;
    GGLint b = (v[1] + rad + (TRI_ONE-1)) >> TRI_FRACTION_BITS;
    GGLcoord xstart = TRI_FROM_INT(l) - v[0] + TRI_HALF; 
    GGLcoord ystart = TRI_FROM_INT(t) - v[1] + TRI_HALF; 

    // scissor...
    if (l < GGLint(c->state.scissor.left)) {
        xstart += TRI_FROM_INT(c->state.scissor.left-l);
        l = GGLint(c->state.scissor.left);
    }
    if (t < GGLint(c->state.scissor.top)) {
        ystart += TRI_FROM_INT(c->state.scissor.top-t);
        t = GGLint(c->state.scissor.top);
    }
    if (r > GGLint(c->state.scissor.right)) {
        r = GGLint(c->state.scissor.right);
    }
    if (b > GGLint(c->state.scissor.bottom)) {
        b = GGLint(c->state.scissor.bottom);
    }

    int xc = r - l;
    int yc = b - t;
    if (xc>0 && yc>0) {
        int16_t* covPtr = c->state.buffers.coverage;
        rad <<= 4;
        const int32_t sqr2Over2 = 0xB5;    // fixed-point 24.8
        GGLcoord rmin = rad - sqr2Over2;
        GGLcoord rmax = rad + sqr2Over2;
        GGLcoord scale;
        rmin *= rmin;
        rmax *= rmax;
        scale = 0x800000 / (rmax - rmin);
        rmin >>= 8;
        rmax >>= 8;

        GGLcoord y = ystart;
        c->iterators.xl = l;
        c->iterators.xr = r;
        c->init_y(c, t);

        do {
            // compute coverage factors for each pixel
            GGLcoord x = xstart;
            for (int i=l ; i<r ; i++) {
                covPtr[i] = coverageFast(x, y, rmin, rmax, scale);
                x += TRI_ONE;
            }
            y += TRI_ONE;
            c->scanline(c);
            c->step_y(c);
        } while (--yc);
    }
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Line
#endif

void linex_validate(void *con, const GGLcoord* v0, const GGLcoord* v1, GGLcoord w)
{
    GGL_CONTEXT(c, con);
    ggl_pick(c);
    if (c->state.needs.p & GGL_NEED_MASK(P_AA)) {
        c->procs.linex = aa_linex;
    } else {
        c->procs.linex = linex;
    }
    c->procs.linex(con, v0, v1, w);
}

static void linex(void *con, const GGLcoord* v0, const GGLcoord* v1, GGLcoord width)
{
    GGL_CONTEXT(c, con);
    GGLcoord v[4][2];
    v[0][0] = v0[0];    v[0][1] = v0[1];
    v[1][0] = v1[0];    v[1][1] = v1[1];
    v0 = v[0];
    v1 = v[1];
    const GGLcoord dx = abs(v0[0] - v1[0]);
    const GGLcoord dy = abs(v0[1] - v1[1]);
    GGLcoord nx, ny;
    nx = ny = 0;

    GGLcoord halfWidth = TRI_ROUND(width) >> 1;
    if (halfWidth == 0)
        halfWidth = TRI_HALF;

    ((dx > dy) ? ny : nx) = halfWidth;
    v[2][0] = v1[0];    v[2][1] = v1[1];
    v[3][0] = v0[0];    v[3][1] = v0[1];
    v[0][0] += nx;      v[0][1] += ny;
    v[1][0] += nx;      v[1][1] += ny;
    v[2][0] -= nx;      v[2][1] -= ny;
    v[3][0] -= nx;      v[3][1] -= ny;
    trianglex_big(con, v[0], v[1], v[2]);
    trianglex_big(con, v[0], v[2], v[3]);
}

static void aa_linex(void *con, const GGLcoord* v0, const GGLcoord* v1, GGLcoord width)
{
    GGL_CONTEXT(c, con);
    GGLcoord v[4][2];
    v[0][0] = v0[0];    v[0][1] = v0[1];
    v[1][0] = v1[0];    v[1][1] = v1[1];
    v0 = v[0];
    v1 = v[1];
    
    const GGLcoord dx = v0[0] - v1[0];
    const GGLcoord dy = v0[1] - v1[1];
    GGLcoord nx = -dy;
    GGLcoord ny =  dx;

    // generally, this will be well below 1.0
    const GGLfixed norm = gglMulx(width, gglSqrtRecipx(nx*nx+ny*ny), 4);
    nx = gglMulx(nx, norm, 21);
    ny = gglMulx(ny, norm, 21);
    
    v[2][0] = v1[0];    v[2][1] = v1[1];
    v[3][0] = v0[0];    v[3][1] = v0[1];
    v[0][0] += nx;      v[0][1] += ny;
    v[1][0] += nx;      v[1][1] += ny;
    v[2][0] -= nx;      v[2][1] -= ny;
    v[3][0] -= nx;      v[3][1] -= ny;
    aapolyx(con, v[0], 4);        
}


// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Rect
#endif

void recti_validate(void *con, GGLint l, GGLint t, GGLint r, GGLint b)
{
    GGL_CONTEXT(c, con);
    ggl_pick(c);
    c->procs.recti = recti;
    c->procs.recti(con, l, t, r, b);
}

void recti(void* con, GGLint l, GGLint t, GGLint r, GGLint b)
{
    GGL_CONTEXT(c, con);

    // scissor...
    if (l < GGLint(c->state.scissor.left))
        l = GGLint(c->state.scissor.left);
    if (t < GGLint(c->state.scissor.top))
        t = GGLint(c->state.scissor.top);
    if (r > GGLint(c->state.scissor.right))
        r = GGLint(c->state.scissor.right);
    if (b > GGLint(c->state.scissor.bottom))
        b = GGLint(c->state.scissor.bottom);

    int xc = r - l;
    int yc = b - t;
    if (xc>0 && yc>0) {
        c->iterators.xl = l;
        c->iterators.xr = r;
        c->init_y(c, t);
        c->rect(c, yc);
    }
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Triangle / Debugging
#endif

static void scanline_set(context_t* c)
{
    int32_t x = c->iterators.xl;
    size_t ct = c->iterators.xr - x;
    int32_t y = c->iterators.y;
    surface_t* cb = &(c->state.buffers.color);
    const GGLFormat* fp = &(c->formats[cb->format]);
    uint8_t* dst = reinterpret_cast<uint8_t*>(cb->data) +
                            (x + (cb->stride * y)) * fp->size;
    const size_t size = ct * fp->size;
    memset(dst, 0xFF, size);
}

static void trianglex_debug(void* con,
        const GGLcoord* v0, const GGLcoord* v1, const GGLcoord* v2)
{
    GGL_CONTEXT(c, con);
    if (c->state.needs.p & GGL_NEED_MASK(P_AA)) {
        aa_trianglex(con,v0,v1,v2);
    } else {
        trianglex_big(con,v0,v1,v2);
    }
	void (*save_scanline)(context_t*)  = c->scanline;
    c->scanline = scanline_set;
    linex(con, v0, v1, TRI_ONE);
    linex(con, v1, v2, TRI_ONE);
    linex(con, v2, v0, TRI_ONE);
    c->scanline = save_scanline;
}

static void trianglex_xor(void* con,
        const GGLcoord* v0, const GGLcoord* v1, const GGLcoord* v2)
{
    trianglex_big(con,v0,v1,v2);
    trianglex_small(con,v0,v1,v2);
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#pragma mark Triangle
#endif

void trianglex_validate(void *con,
        const GGLcoord* v0, const GGLcoord* v1, const GGLcoord* v2)
{
    GGL_CONTEXT(c, con);
    ggl_pick(c);
    if (c->state.needs.p & GGL_NEED_MASK(P_AA)) {
        c->procs.trianglex = DEBUG_TRANGLES ? trianglex_debug : aa_trianglex;
    } else {
        c->procs.trianglex = DEBUG_TRANGLES ? trianglex_debug : trianglex_big;
    }
    c->procs.trianglex(con, v0, v1, v2);
}

// ----------------------------------------------------------------------------

void trianglex_small(void* con,
        const GGLcoord* v0, const GGLcoord* v1, const GGLcoord* v2)
{
    GGL_CONTEXT(c, con);

    // vertices are in 28.4 fixed point, which allows
    // us to use 32 bits multiplies below.
    int32_t x0 = v0[0];
    int32_t y0 = v0[1];
    int32_t x1 = v1[0];
    int32_t y1 = v1[1];
    int32_t x2 = v2[0];
    int32_t y2 = v2[1];

    int32_t dx01 = x0 - x1;
    int32_t dy20 = y2 - y0;
    int32_t dy01 = y0 - y1;
    int32_t dx20 = x2 - x0;

    // The code below works only with CCW triangles
    // so if we get a CW triangle, we need to swap two of its vertices
    if (dx01*dy20 < dy01*dx20) {
        swap(x0, x1);
        swap(y0, y1);
        dx01 = x0 - x1;
        dy01 = y0 - y1;
        dx20 = x2 - x0;
        dy20 = y2 - y0;
    }
    int32_t dx12 = x1 - x2;
    int32_t dy12 = y1 - y2;

    // bounding box & scissor
    const int32_t bminx = TRI_FLOOR(min(x0, x1, x2)) >> TRI_FRACTION_BITS;
    const int32_t bminy = TRI_FLOOR(min(y0, y1, y2)) >> TRI_FRACTION_BITS;
    const int32_t bmaxx = TRI_CEIL( max(x0, x1, x2)) >> TRI_FRACTION_BITS;
    const int32_t bmaxy = TRI_CEIL( max(y0, y1, y2)) >> TRI_FRACTION_BITS;
    const int32_t minx = max(bminx, c->state.scissor.left);
    const int32_t miny = max(bminy, c->state.scissor.top);
    const int32_t maxx = min(bmaxx, c->state.scissor.right);
    const int32_t maxy = min(bmaxy, c->state.scissor.bottom);
    if ((minx >= maxx) || (miny >= maxy))
        return; // too small or clipped out...

    // step equations to the bounding box and snap to pixel center
    const int32_t my = (miny << TRI_FRACTION_BITS) + TRI_HALF;
    const int32_t mx = (minx << TRI_FRACTION_BITS) + TRI_HALF;
    int32_t ey0 = dy01 * (x0 - mx) - dx01 * (y0 - my);
    int32_t ey1 = dy12 * (x1 - mx) - dx12 * (y1 - my);
    int32_t ey2 = dy20 * (x2 - mx) - dx20 * (y2 - my);

    // right-exclusive fill rule, to avoid rare cases
    // of over drawing
    if (dy01<0 || (dy01 == 0 && dx01>0)) ey0++;
    if (dy12<0 || (dy12 == 0 && dx12>0)) ey1++;
    if (dy20<0 || (dy20 == 0 && dx20>0)) ey2++;
    
    c->init_y(c, miny);
    for (int32_t y = miny; y < maxy; y++) {
        register int32_t ex0 = ey0;
        register int32_t ex1 = ey1;
        register int32_t ex2 = ey2;    
        register int32_t xl, xr;
        for (xl=minx ; xl<maxx ; xl++) {
            if (ex0>0 && ex1>0 && ex2>0)
                break; // all strictly positive
            ex0 -= dy01 << TRI_FRACTION_BITS;
            ex1 -= dy12 << TRI_FRACTION_BITS;
            ex2 -= dy20 << TRI_FRACTION_BITS;
        }
        xr = xl;
        for ( ; xr<maxx ; xr++) {
            if (!(ex0>0 && ex1>0 && ex2>0))
                break; // not all strictly positive
            ex0 -= dy01 << TRI_FRACTION_BITS;
            ex1 -= dy12 << TRI_FRACTION_BITS;
            ex2 -= dy20 << TRI_FRACTION_BITS;
        }

        if (xl < xr) {
            c->iterators.xl = xl;
            c->iterators.xr = xr;
            c->scanline(c);
        }
        c->step_y(c);

        ey0 += dx01 << TRI_FRACTION_BITS;
        ey1 += dx12 << TRI_FRACTION_BITS;
        ey2 += dx20 << TRI_FRACTION_BITS;
    }
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#endif

// the following routine fills a triangle via edge stepping, which
// unfortunately requires divisions in the setup phase to get right,
// it should probably only be used for relatively large trianges


// x = y*DX/DY    (ou DX and DY are constants, DY > 0, et y >= 0)
// 
// for an equation of the type:
//      x' = y*K/2^p     (with K and p constants "carefully chosen")
// 
// We can now do a DDA without precision loss. We define 'e' by:
//      x' - x = y*(DX/DY - K/2^p) = y*e
// 
// If we choose K = round(DX*2^p/DY) then,
//      abs(e) <= 1/2^(p+1) by construction
// 
// therefore abs(x'-x) = y*abs(e) <= y/2^(p+1) <= DY/2^(p+1) <= DMAX/2^(p+1)
// 
// which means that if DMAX <= 2^p, therefore abs(x-x') <= 1/2, including
// at the last line. In fact, it's even a strict inequality except in one
// extrem case (DY == DMAX et e = +/- 1/2)
// 
// Applying that to our coordinates, we need 2^p >= 4096*16 = 65536
// so p = 16 is enough, we're so lucky!

const int TRI_ITERATORS_BITS = 16;

struct Edge
{
  int32_t  x;      // edge position in 16.16 coordinates
  int32_t  x_incr; // on each step, increment x by that amount
  int32_t  y_top;  // starting scanline, 16.4 format
  int32_t  y_bot;
};

static void
edge_dump( Edge*  edge )
{
  ALOGI( "  top=%d (%.3f)  bot=%d (%.3f)  x=%d (%.3f)  ix=%d (%.3f)",
        edge->y_top, edge->y_top/float(TRI_ONE),
		edge->y_bot, edge->y_bot/float(TRI_ONE),
		edge->x, edge->x/float(FIXED_ONE),
		edge->x_incr, edge->x_incr/float(FIXED_ONE) );
}

static void
triangle_dump_edges( Edge*  edges,
                     int            count )
{ 
    ALOGI( "%d edge%s:\n", count, count == 1 ? "" : "s" );
	for ( ; count > 0; count--, edges++ )
	  edge_dump( edges );
}

// the following function sets up an edge, it assumes
// that ymin and ymax are in already in the 'reduced'
// format
static __attribute__((noinline))
void edge_setup(
        Edge*           edges,
        int*            pcount,
        const GGLcoord* p1,
        const GGLcoord* p2,
        int32_t         ymin,
        int32_t         ymax )
{
	const GGLfixed*  top = p1;
	const GGLfixed*  bot = p2;
	Edge*    edge = edges + *pcount;

	if (top[1] > bot[1]) {
        swap(top, bot);
	}

	int  y1 = top[1] | 1;
	int  y2 = bot[1] | 1;
	int  dy = y2 - y1;

	if ( dy == 0 || y1 > ymax || y2 < ymin )
		return;

	if ( y1 > ymin )
		ymin = TRI_SNAP_NEXT_HALF(y1);
	
	if ( y2 < ymax )
		ymax = TRI_SNAP_PREV_HALF(y2);

	if ( ymin > ymax )  // when the edge doesn't cross any scanline
	  return;

	const int x1 = top[0];
	const int dx = bot[0] - x1;
    const int shift = TRI_ITERATORS_BITS - TRI_FRACTION_BITS;

	// setup edge fields
    // We add 0.5 to edge->x here because it simplifies the rounding
    // in triangle_sweep_edges() -- this doesn't change the ordering of 'x'
	edge->x      = (x1 << shift) + (1LU << (TRI_ITERATORS_BITS-1));
	edge->x_incr = 0;
	edge->y_top  = ymin;
	edge->y_bot  = ymax;

	if (ggl_likely(ymin <= ymax && dx)) {
        edge->x_incr = gglDivQ16(dx, dy);
    }
    if (ggl_likely(y1 < ymin)) {
        int32_t xadjust = (edge->x_incr * (ymin-y1)) >> TRI_FRACTION_BITS;
        edge->x += xadjust;
    }
  
	++*pcount;
}


static void
triangle_sweep_edges( Edge*  left,
                      Edge*  right,
					  int            ytop,
					  int            ybot,
					  context_t*     c )
{
    int count = ((ybot - ytop)>>TRI_FRACTION_BITS) + 1;
    if (count<=0) return;

    // sort the edges horizontally
    if ((left->x > right->x) || 
        ((left->x == right->x) && (left->x_incr > right->x_incr))) {
        swap(left, right);
    }

    int left_x = left->x;
    int right_x = right->x;
    const int left_xi = left->x_incr;
    const int right_xi  = right->x_incr;
    left->x  += left_xi * count;
    right->x += right_xi * count;

	const int xmin = c->state.scissor.left;
	const int xmax = c->state.scissor.right;
    do {
        // horizontal scissoring
        const int32_t xl = max(left_x  >> TRI_ITERATORS_BITS, xmin);
        const int32_t xr = min(right_x >> TRI_ITERATORS_BITS, xmax);
        left_x  += left_xi;
        right_x += right_xi;
        // invoke the scanline rasterizer
        if (ggl_likely(xl < xr)) {
            c->iterators.xl = xl;
            c->iterators.xr = xr;
            c->scanline(c);
        }
		c->step_y(c);
	} while (--count);
}


void trianglex_big(void* con,
        const GGLcoord* v0, const GGLcoord* v1, const GGLcoord* v2)
{
    GGL_CONTEXT(c, con);

    Edge edges[3];
	int num_edges = 0;
	int32_t ymin = TRI_FROM_INT(c->state.scissor.top)    + TRI_HALF;
	int32_t ymax = TRI_FROM_INT(c->state.scissor.bottom) - TRI_HALF;
	    
	edge_setup( edges, &num_edges, v0, v1, ymin, ymax );
	edge_setup( edges, &num_edges, v0, v2, ymin, ymax );
	edge_setup( edges, &num_edges, v1, v2, ymin, ymax );

    if (ggl_unlikely(num_edges<2))  // for really tiny triangles that don't
		return;                     // cross any scanline centers

    Edge* left  = &edges[0];
    Edge* right = &edges[1];
    Edge* other = &edges[2];
    int32_t y_top = min(left->y_top, right->y_top);
    int32_t y_bot = max(left->y_bot, right->y_bot);

	if (ggl_likely(num_edges==3)) {
        y_top = min(y_top, edges[2].y_top);
        y_bot = max(y_bot, edges[2].y_bot);
		if (edges[0].y_top > y_top) {
            other = &edges[0];
            left  = &edges[2];
		} else if (edges[1].y_top > y_top) {
            other = &edges[1];
            right = &edges[2];
		}
    }

    c->init_y(c, y_top >> TRI_FRACTION_BITS);

    int32_t y_mid = min(left->y_bot, right->y_bot);
    triangle_sweep_edges( left, right, y_top, y_mid, c );

    // second scanline sweep loop, if necessary
    y_mid += TRI_ONE;
    if (y_mid <= y_bot) {
        ((left->y_bot == y_bot) ? right : left) = other;
        if (other->y_top < y_mid) {
            other->x += other->x_incr;
        }
        triangle_sweep_edges( left, right, y_mid, y_bot, c );
    }
}

void aa_trianglex(void* con,
        const GGLcoord* a, const GGLcoord* b, const GGLcoord* c)
{
    GGLcoord pts[6] = { a[0], a[1], b[0], b[1], c[0], c[1] };
    aapolyx(con, pts, 3);
}

// ----------------------------------------------------------------------------
#if 0
#pragma mark -
#endif

struct AAEdge
{
    GGLfixed x;         // edge position in 12.16 coordinates
    GGLfixed x_incr;    // on each y step, increment x by that amount
    GGLfixed y_incr;    // on each x step, increment y by that amount
    int16_t y_top;      // starting scanline, 12.4 format
    int16_t y_bot;      // starting scanline, 12.4 format
    void dump();
};

void AAEdge::dump()
{
    float tri  = 1.0f / TRI_ONE;
    float iter = 1.0f / (1<<TRI_ITERATORS_BITS);
    float fix  = 1.0f / FIXED_ONE;
    ALOGD(   "x=%08x (%.3f), "
            "x_incr=%08x (%.3f), y_incr=%08x (%.3f), "
            "y_top=%08x (%.3f), y_bot=%08x (%.3f) ",
        x, x*fix,
        x_incr, x_incr*iter,
        y_incr, y_incr*iter,
        y_top, y_top*tri,
        y_bot, y_bot*tri );
}

// the following function sets up an edge, it assumes
// that ymin and ymax are in already in the 'reduced'
// format
static __attribute__((noinline))
void aa_edge_setup(
        AAEdge*         edges,
        int*            pcount,
        const GGLcoord* p1,
        const GGLcoord* p2,
        int32_t         ymin,
        int32_t         ymax )
{
    const GGLfixed*  top = p1;
    const GGLfixed*  bot = p2;
    AAEdge* edge = edges + *pcount;

    if (top[1] > bot[1])
        swap(top, bot);

    int  y1 = top[1];
    int  y2 = bot[1];
    int  dy = y2 - y1;

    if (dy==0 || y1>ymax || y2<ymin)
        return;

    if (y1 > ymin)
        ymin = y1;
    
    if (y2 < ymax)
        ymax = y2;

    const int x1 = top[0];
    const int dx = bot[0] - x1;
    const int shift = FIXED_BITS - TRI_FRACTION_BITS;

    // setup edge fields
    edge->x      = x1 << shift;
    edge->x_incr = 0;
    edge->y_top  = ymin;
    edge->y_bot  = ymax;
    edge->y_incr = 0x7FFFFFFF;

    if (ggl_likely(ymin <= ymax && dx)) {
        edge->x_incr = gglDivQ16(dx, dy);
        if (dx != 0) {
            edge->y_incr = abs(gglDivQ16(dy, dx));
        }
    }
    if (ggl_likely(y1 < ymin)) {
        int32_t xadjust = (edge->x_incr * (ymin-y1))
                >> (TRI_FRACTION_BITS + TRI_ITERATORS_BITS - FIXED_BITS);
        edge->x += xadjust;
    }
  
    ++*pcount;
}


typedef int (*compar_t)(const void*, const void*);
static int compare_edges(const AAEdge *e0, const AAEdge *e1) {
    if (e0->y_top > e1->y_top)      return 1;
    if (e0->y_top < e1->y_top)      return -1;
    if (e0->x > e1->x)              return 1;
    if (e0->x < e1->x)              return -1;
    if (e0->x_incr > e1->x_incr)    return 1;
    if (e0->x_incr < e1->x_incr)    return -1;
    return 0; // same edges, should never happen
}

static inline 
void SET_COVERAGE(int16_t*& p, int32_t value, ssize_t n)
{
    android_memset16((uint16_t*)p, value, n*2);
    p += n;
}

static inline 
void ADD_COVERAGE(int16_t*& p, int32_t value)
{
    value = *p + value;
    if (value >= 0x8000)
        value = 0x7FFF;
    *p++ = value;
}

static inline
void SUB_COVERAGE(int16_t*& p, int32_t value)
{
    value = *p - value;
    value &= ~(value>>31);
    *p++ = value;
}

void aapolyx(void* con,
        const GGLcoord* pts, int count)
{
    /*
     * NOTE: This routine assumes that the polygon has been clipped to the
     * viewport already, that is, no vertex lies outside of the framebuffer.
     * If this happens, the code below won't corrupt memory but the 
     * coverage values may not be correct.
     */
    
    GGL_CONTEXT(c, con);

    // we do only quads for now (it's used for thick lines)
    if ((count>4) || (count<2)) return;

    // take scissor into account
    const int xmin = c->state.scissor.left;
    const int xmax = c->state.scissor.right;
    if (xmin >= xmax) return;

    // generate edges from the vertices
    int32_t ymin = TRI_FROM_INT(c->state.scissor.top);
    int32_t ymax = TRI_FROM_INT(c->state.scissor.bottom);
    if (ymin >= ymax) return;

    AAEdge edges[4];
    int num_edges = 0;
    GGLcoord const * p = pts;
    for (int i=0 ; i<count-1 ; i++, p+=2) {
        aa_edge_setup(edges, &num_edges, p, p+2, ymin, ymax);
    }
    aa_edge_setup(edges, &num_edges, p, pts, ymin, ymax );
    if (ggl_unlikely(num_edges<2))
        return;

    // sort the edge list top to bottom, left to right.
    qsort(edges, num_edges, sizeof(AAEdge), (compar_t)compare_edges);

    int16_t* const covPtr = c->state.buffers.coverage;
    memset(covPtr+xmin, 0, (xmax-xmin)*sizeof(*covPtr));

    // now, sweep all edges in order
    // start with the 2 first edges. We know that they share their top
    // vertex, by construction.
    int i = 2;
    AAEdge* left  = &edges[0];
    AAEdge* right = &edges[1];
    int32_t yt = left->y_top;
    GGLfixed l = left->x;
    GGLfixed r = right->x;
    int retire = 0;
    int16_t* coverage;

    // at this point we can initialize the rasterizer    
    c->init_y(c, yt>>TRI_FRACTION_BITS);
    c->iterators.xl = xmax;
    c->iterators.xr = xmin;

    do {
        int32_t y = min(min(left->y_bot, right->y_bot), TRI_FLOOR(yt + TRI_ONE));
        const int32_t shift = TRI_FRACTION_BITS + TRI_ITERATORS_BITS - FIXED_BITS;
        const int cf_shift = (1 + TRI_FRACTION_BITS*2 + TRI_ITERATORS_BITS - 15);

        // compute xmin and xmax for the left edge
        GGLfixed l_min = gglMulAddx(left->x_incr, y - left->y_top, left->x, shift);
        GGLfixed l_max = l;
        l = l_min;
        if (l_min > l_max)
            swap(l_min, l_max);

        // compute xmin and xmax for the right edge
        GGLfixed r_min = gglMulAddx(right->x_incr, y - right->y_top, right->x, shift);
        GGLfixed r_max = r;
        r = r_min;
        if (r_min > r_max)
            swap(r_min, r_max);

        // make sure we're not touching coverage values outside of the
        // framebuffer
        l_min &= ~(l_min>>31);
        r_min &= ~(r_min>>31);
        l_max &= ~(l_max>>31);
        r_max &= ~(r_max>>31);
        if (gglFixedToIntFloor(l_min) >= xmax) l_min = gglIntToFixed(xmax)-1;
        if (gglFixedToIntFloor(r_min) >= xmax) r_min = gglIntToFixed(xmax)-1;
        if (gglFixedToIntCeil(l_max) >= xmax)  l_max = gglIntToFixed(xmax)-1;
        if (gglFixedToIntCeil(r_max) >= xmax)  r_max = gglIntToFixed(xmax)-1;

        // compute the integer versions of the above
        const GGLfixed l_min_i = gglFloorx(l_min);
        const GGLfixed l_max_i = gglCeilx (l_max);
        const GGLfixed r_min_i = gglFloorx(r_min);
        const GGLfixed r_max_i = gglCeilx (r_max);

        // clip horizontally using the scissor
        const int xml = max(xmin, gglFixedToIntFloor(l_min_i));
        const int xmr = min(xmax, gglFixedToIntFloor(r_max_i));

        // if we just stepped to a new scanline, render the previous one.
        // and clear the coverage buffer
        if (retire) {
            if (c->iterators.xl < c->iterators.xr)
                c->scanline(c);
            c->step_y(c);
            memset(covPtr+xmin, 0, (xmax-xmin)*sizeof(*covPtr));
            c->iterators.xl = xml;
            c->iterators.xr = xmr;
        } else {
            // update the horizontal range of this scanline
            c->iterators.xl = min(c->iterators.xl, xml);
            c->iterators.xr = max(c->iterators.xr, xmr);
        }

        coverage = covPtr + gglFixedToIntFloor(l_min_i);
        if (l_min_i == gglFloorx(l_max)) {
            
            /*
             *  fully traverse this pixel vertically
             *       l_max
             *  +-----/--+  yt
             *  |    /   |  
             *  |   /    |
             *  |  /     |
             *  +-/------+  y
             *   l_min  (l_min_i + TRI_ONE)
             */
              
            GGLfixed dx = l_max - l_min;
            int32_t dy = y - yt;
            int cf = gglMulx((dx >> 1) + (l_min_i + FIXED_ONE - l_max), dy,
                FIXED_BITS + TRI_FRACTION_BITS - 15);
            ADD_COVERAGE(coverage, cf);
            // all pixels on the right have cf = 1.0
        } else {
            /*
             *  spans several pixels in one scanline
             *            l_max
             *  +--------+--/-----+  yt
             *  |        |/       |
             *  |       /|        |
             *  |     /  |        |
             *  +---/----+--------+  y
             *   l_min (l_min_i + TRI_ONE)
             */

            // handle the first pixel separately...
            const int32_t y_incr = left->y_incr;
            int32_t dx = TRI_FROM_FIXED(l_min_i - l_min) + TRI_ONE;
            int32_t cf = (dx * dx * y_incr) >> cf_shift;
            ADD_COVERAGE(coverage, cf);

            // following pixels get covered by y_incr, but we need
            // to fix-up the cf to account for previous partial pixel
            dx = TRI_FROM_FIXED(l_min - l_min_i);
            cf -= (dx * dx * y_incr) >> cf_shift;
            for (int x = l_min_i+FIXED_ONE ; x < l_max_i-FIXED_ONE ; x += FIXED_ONE) {
                cf += y_incr >> (TRI_ITERATORS_BITS-15);
                ADD_COVERAGE(coverage, cf);
            }
            
            // and the last pixel
            dx = TRI_FROM_FIXED(l_max - l_max_i) - TRI_ONE;
            cf += (dx * dx * y_incr) >> cf_shift;
            ADD_COVERAGE(coverage, cf);
        }
        
        // now, fill up all fully covered pixels
        coverage = covPtr + gglFixedToIntFloor(l_max_i);
        int cf = ((y - yt) << (15 - TRI_FRACTION_BITS));
        if (ggl_likely(cf >= 0x8000)) {
            SET_COVERAGE(coverage, 0x7FFF, ((r_max - l_max_i)>>FIXED_BITS)+1);
        } else {
            for (int x=l_max_i ; x<r_max ; x+=FIXED_ONE) {
                ADD_COVERAGE(coverage, cf);
            }
        }
        
        // subtract the coverage of the right edge
        coverage = covPtr + gglFixedToIntFloor(r_min_i); 
        if (r_min_i == gglFloorx(r_max)) {
            GGLfixed dx = r_max - r_min;
            int32_t dy = y - yt;
            int cf = gglMulx((dx >> 1) + (r_min_i + FIXED_ONE - r_max), dy,
                FIXED_BITS + TRI_FRACTION_BITS - 15);
            SUB_COVERAGE(coverage, cf);
            // all pixels on the right have cf = 1.0
        } else {
            // handle the first pixel separately...
            const int32_t y_incr = right->y_incr;
            int32_t dx = TRI_FROM_FIXED(r_min_i - r_min) + TRI_ONE;
            int32_t cf = (dx * dx * y_incr) >> cf_shift;
            SUB_COVERAGE(coverage, cf);
            
            // following pixels get covered by y_incr, but we need
            // to fix-up the cf to account for previous partial pixel
            dx = TRI_FROM_FIXED(r_min - r_min_i);
            cf -= (dx * dx * y_incr) >> cf_shift;
            for (int x = r_min_i+FIXED_ONE ; x < r_max_i-FIXED_ONE ; x += FIXED_ONE) {
                cf += y_incr >> (TRI_ITERATORS_BITS-15);
                SUB_COVERAGE(coverage, cf);
            }
            
            // and the last pixel
            dx = TRI_FROM_FIXED(r_max - r_max_i) - TRI_ONE;
            cf += (dx * dx * y_incr) >> cf_shift;
            SUB_COVERAGE(coverage, cf);
        }

        // did we reach the end of an edge? if so, get a new one.
        if (y == left->y_bot || y == right->y_bot) {
            // bail out if we're done
            if (i>=num_edges)
                break;
            if (y == left->y_bot)
                left = &edges[i++];
            if (y == right->y_bot)
                right = &edges[i++];
        }

        // next scanline
        yt = y;
        
        // did we just finish a scanline?        
        retire = (y << (32-TRI_FRACTION_BITS)) == 0;
    } while (true);

    // render the last scanline
    if (c->iterators.xl < c->iterators.xr)
        c->scanline(c);
}

}; // namespace android
