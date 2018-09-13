/* libs/pixelflinger/buffer.cpp
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

#include <android-base/macros.h>

#include "buffer.h"

namespace android {
// ----------------------------------------------------------------------------

static void read_pixel(const surface_t* s, context_t* c,
        uint32_t x, uint32_t y, pixel_t* pixel);
static void write_pixel(const surface_t* s, context_t* c,
        uint32_t x, uint32_t y, const pixel_t* pixel);
static void readRGB565(const surface_t* s, context_t* c,
        uint32_t x, uint32_t y, pixel_t* pixel);
static void readABGR8888(const surface_t* s, context_t* c,
        uint32_t x, uint32_t y, pixel_t* pixel);

static uint32_t logic_op(int op, uint32_t s, uint32_t d);
static uint32_t extract(uint32_t v, int h, int l, int bits);
static uint32_t expand(uint32_t v, int sbits, int dbits);
static uint32_t downshift_component(uint32_t in, uint32_t v,
        int sh, int sl, int dh, int dl, int ch, int cl, int dither);

// ----------------------------------------------------------------------------

void ggl_init_texture(context_t* c)
{
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; i++) {
        texture_t& t = c->state.texture[i];
        t.s_coord = GGL_ONE_TO_ONE;
        t.t_coord = GGL_ONE_TO_ONE;
        t.s_wrap = GGL_REPEAT;
        t.t_wrap = GGL_REPEAT;
        t.min_filter = GGL_NEAREST;
        t.mag_filter = GGL_NEAREST;
        t.env = GGL_MODULATE;
    }
    c->activeTMU = &(c->state.texture[0]);
}

void ggl_set_surface(context_t* c, surface_t* dst, const GGLSurface* src)
{
    dst->width = src->width;
    dst->height = src->height;
    dst->stride = src->stride;
    dst->data = src->data;
    dst->format = src->format;
    dst->dirty = 1;
    if (__builtin_expect(dst->stride < 0, false)) {
        const GGLFormat& pixelFormat(c->formats[dst->format]);
        const int32_t bpr = -dst->stride * pixelFormat.size;
        dst->data += bpr * (dst->height-1);
    }
}

static void pick_read_write(surface_t* s)
{
    // Choose best reader/writers.
    switch (s->format) {
        case GGL_PIXEL_FORMAT_RGBA_8888:    s->read = readABGR8888;  break;
        case GGL_PIXEL_FORMAT_RGB_565:      s->read = readRGB565;    break;
        default:                            s->read = read_pixel;    break;
    }
    s->write = write_pixel;
}

void ggl_pick_texture(context_t* c)
{
    for (int i=0 ; i<GGL_TEXTURE_UNIT_COUNT ; ++i) {
        surface_t& s = c->state.texture[i].surface;
        if ((!c->state.texture[i].enable) || (!s.dirty))
            continue;
        s.dirty = 0;
        pick_read_write(&s);
        generated_tex_vars_t& gen = c->generated_vars.texture[i];
        gen.width   = s.width;
        gen.height  = s.height;
        gen.stride  = s.stride;
        gen.data    = uintptr_t(s.data);
    }
}

void ggl_pick_cb(context_t* c)
{
    surface_t& s = c->state.buffers.color;
    if (s.dirty) {
        s.dirty = 0;
        pick_read_write(&s);
    }
}

// ----------------------------------------------------------------------------

void read_pixel(const surface_t* s, context_t* c,
        uint32_t x, uint32_t y, pixel_t* pixel)
{
    assert((x < s->width) && (y < s->height));

    const GGLFormat* f = &(c->formats[s->format]);
    int32_t index = x + (s->stride * y);
    uint8_t* const data = s->data + index * f->size;
    uint32_t v = 0;
    switch (f->size) {
        case 1:		v = *data;									break;
        case 2:		v = *(uint16_t*)data;						break;
        case 3:		v = (data[2]<<16)|(data[1]<<8)|data[0];     break;
        case 4:		v = GGL_RGBA_TO_HOST(*(uint32_t*)data);		break;
    }
    for (int i=0 ; i<4 ; i++) {
        pixel->s[i] = f->c[i].h - f->c[i].l;
        if (pixel->s[i])
            pixel->c[i] = extract(v,  f->c[i].h,  f->c[i].l, f->size*8);
    }
}

void readRGB565(const surface_t* s, context_t* /*c*/,
        uint32_t x, uint32_t y, pixel_t* pixel)
{
    uint16_t v = *(reinterpret_cast<uint16_t*>(s->data) + (x + (s->stride * y)));
    pixel->c[0] = 0;
    pixel->c[1] = v>>11;
    pixel->c[2] = (v>>5)&0x3F;
    pixel->c[3] = v&0x1F;
    pixel->s[0] = 0;
    pixel->s[1] = 5;
    pixel->s[2] = 6;
    pixel->s[3] = 5;
}

void readABGR8888(const surface_t* s, context_t* /*c*/,
        uint32_t x, uint32_t y, pixel_t* pixel)
{
    uint32_t v = *(reinterpret_cast<uint32_t*>(s->data) + (x + (s->stride * y)));
    v = GGL_RGBA_TO_HOST(v);
    pixel->c[0] = v>>24;        // A
    pixel->c[1] = v&0xFF;       // R
    pixel->c[2] = (v>>8)&0xFF;  // G
    pixel->c[3] = (v>>16)&0xFF; // B
    pixel->s[0] = 
    pixel->s[1] = 
    pixel->s[2] = 
    pixel->s[3] = 8;
}

void write_pixel(const surface_t* s, context_t* c,
        uint32_t x, uint32_t y, const pixel_t* pixel)
{
    assert((x < s->width) && (y < s->height));

    int dither = -1;
    if (c->state.enables & GGL_ENABLE_DITHER) {
        dither = c->ditherMatrix[ (x & GGL_DITHER_MASK) +
                ((y & GGL_DITHER_MASK)<<GGL_DITHER_ORDER_SHIFT) ];
    }

    const GGLFormat* f = &(c->formats[s->format]);
    int32_t index = x + (s->stride * y);
    uint8_t* const data = s->data + index * f->size;
        
    uint32_t mask = 0;
    uint32_t v = 0;
    for (int i=0 ; i<4 ; i++) {
        const int component_mask = 1 << i;
        if (f->components>=GGL_LUMINANCE &&
                (i==GGLFormat::GREEN || i==GGLFormat::BLUE)) {
            // destinations L formats don't have G or B
            continue;
        }
        const int l = f->c[i].l;
        const int h = f->c[i].h;
        if (h && (c->state.mask.color & component_mask)) {
            mask |= (((1<<(h-l))-1)<<l);
            uint32_t u = pixel->c[i];
            int32_t pixelSize = pixel->s[i];
            if (pixelSize < (h-l)) {
                u = expand(u, pixelSize, h-l);
                pixelSize = h-l;
            }
            v = downshift_component(v, u, pixelSize, 0, h, l, 0, 0, dither);
        }
    }

    if ((c->state.mask.color != 0xF) || 
        (c->state.enables & GGL_ENABLE_LOGIC_OP)) {
        uint32_t d = 0;
        switch (f->size) {
            case 1:	d = *data;									break;
            case 2:	d = *(uint16_t*)data;						break;
            case 3:	d = (data[2]<<16)|(data[1]<<8)|data[0];     break;
            case 4:	d = GGL_RGBA_TO_HOST(*(uint32_t*)data);		break;
        }
        if (c->state.enables & GGL_ENABLE_LOGIC_OP) {
            v = logic_op(c->state.logic_op.opcode, v, d);            
            v &= mask;
        }
        v |= (d & ~mask);
    }

    switch (f->size) {
        case 1:		*data = v;									break;
        case 2:		*(uint16_t*)data = v;						break;
        case 3:
            data[0] = v;
            data[1] = v>>8;
            data[2] = v>>16;
            break;
        case 4:		*(uint32_t*)data = GGL_HOST_TO_RGBA(v);     break;
    }
}

static uint32_t logic_op(int op, uint32_t s, uint32_t d)
{
    switch(op) {
    case GGL_CLEAR:         return 0;
    case GGL_AND:           return s & d;
    case GGL_AND_REVERSE:   return s & ~d;
    case GGL_COPY:          return s;
    case GGL_AND_INVERTED:  return ~s & d;
    case GGL_NOOP:          return d;
    case GGL_XOR:           return s ^ d;
    case GGL_OR:            return s | d;
    case GGL_NOR:           return ~(s | d);
    case GGL_EQUIV:         return ~(s ^ d);
    case GGL_INVERT:        return ~d;
    case GGL_OR_REVERSE:    return s | ~d;
    case GGL_COPY_INVERTED: return ~s;
    case GGL_OR_INVERTED:   return ~s | d;
    case GGL_NAND:          return ~(s & d);
    case GGL_SET:           return ~0;
    };
    return s;
}            


uint32_t ggl_expand(uint32_t v, int sbits, int dbits)
{
    return expand(v, sbits, dbits);
}

uint32_t ggl_pack_color(context_t* c, int32_t format,
        GGLcolor r, GGLcolor g, GGLcolor b, GGLcolor a)
{
    const GGLFormat* f = &(c->formats[format]);
    uint32_t p = 0;
    const int32_t hbits = GGL_COLOR_BITS;
    const int32_t lbits = GGL_COLOR_BITS - 8;
    p = downshift_component(p, r,   hbits, lbits,  f->rh, f->rl, 0, 1, -1);
    p = downshift_component(p, g,   hbits, lbits,  f->gh, f->gl, 0, 1, -1);
    p = downshift_component(p, b,   hbits, lbits,  f->bh, f->bl, 0, 1, -1);
    p = downshift_component(p, a,   hbits, lbits,  f->ah, f->al, 0, 1, -1);
    switch (f->size) {
        case 1:
            p |= p << 8;
            FALLTHROUGH_INTENDED;
        case 2:
            p |= p << 16;
    }
    return p;
}

// ----------------------------------------------------------------------------

// extract a component from a word
uint32_t extract(uint32_t v, int h, int l, int bits)
{
	assert(h);
	if (l) {
		v >>= l;
	}
	if (h != bits) {
		v &= (1<<(h-l))-1;
	}
	return v;
}

// expand a component from sbits to dbits
uint32_t expand(uint32_t v, int sbits, int dbits)
{
    if (dbits > sbits) {
        assert(sbits);
        if (sbits==1) {
            v = (v<<dbits) - v;
        } else {
            if (dbits % sbits) {
                v <<= (dbits-sbits);
                dbits -= sbits;
                do {
                    v |= v>>sbits;
                    dbits -= sbits;
                    sbits *= 2;
                } while (dbits>0);
            } else {
                dbits -= sbits;
                do {
                    v |= v<<sbits;
                    dbits -= sbits;
                    if (sbits*2 < dbits) {
                        sbits *= 2;
                    }
                } while (dbits > 0);
            }
        }
    }
	return v;
}

// downsample a component from sbits to dbits
// and shift / construct the pixel
uint32_t downshift_component(	uint32_t in, uint32_t v,
                                int sh, int sl,		// src
                                int dh, int dl,		// dst
                                int ch, int cl,		// clear
                                int dither)
{
	const int sbits = sh-sl;
	const int dbits = dh-dl;
    
	assert(sbits>=dbits);


    if (sbits>dbits) {
        if (dither>=0) {
            v -= (v>>dbits);				// fix up
            const int shift = (GGL_DITHER_BITS - (sbits-dbits));
            if (shift >= 0)   v += (dither >> shift) << sl;
            else              v += (dither << (-shift)) << sl;
        } else {
            // don't do that right now, so we can reproduce the same
            // artifacts we get on ARM (Where we don't do this)
            // -> this is not really needed if we don't dither
            //if (dBits > 1) { // result already OK if dBits==1
            //    v -= (v>>dbits);				// fix up
            //    v += 1 << ((sbits-dbits)-1);	// rounding
            //}
        }
    }


	// we need to clear the high bits of the source
	if (ch) {
		v <<= 32-sh;
		sl += 32-sh;
        sh = 32;
	}
	
	if (dl) {
		if (cl || (sbits>dbits)) {
			v >>= sh-dbits;
			sl = 0;
			sh = dbits;
            in |= v<<dl;
		} else {
			// sbits==dbits and we don't need to clean the lower bits
			// so we just have to shift the component to the right location
            int shift = dh-sh;
            in |= v<<shift;
		}
	} else {
		// destination starts at bit 0
		// ie: sh-dh == sh-dbits
		int shift = sh-dh;
		if (shift > 0)      in |= v>>shift;
		else if (shift < 0) in |= v<<shift;
		else                in |= v;
	}
	return in;
}

// ----------------------------------------------------------------------------
}; // namespace android
