/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <android-base/stringprintf.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>

#include "charger.sysprop.h"
#include "healthd_draw.h"

#define LOGE(x...) KLOG_ERROR("charger", x);
#define LOGW(x...) KLOG_WARNING("charger", x);
#define LOGV(x...) KLOG_DEBUG("charger", x);

static bool get_split_screen() {
    return android::sysprop::ChargerProperties::draw_split_screen().value_or(false);
}

static int get_split_offset() {
    int64_t value = android::sysprop::ChargerProperties::draw_split_offset().value_or(0);
    if (value < static_cast<int64_t>(std::numeric_limits<int>::min())) {
        LOGW("draw_split_offset = %" PRId64 " overflow for an int; resetting to %d.\n", value,
             std::numeric_limits<int>::min());
        value = std::numeric_limits<int>::min();
    }
    if (value > static_cast<int64_t>(std::numeric_limits<int>::max())) {
        LOGW("draw_split_offset = %" PRId64 " overflow for an int; resetting to %d.\n", value,
             std::numeric_limits<int>::max());
        value = std::numeric_limits<int>::max();
    }
    return static_cast<int>(value);
}

HealthdDraw::HealthdDraw(animation* anim)
    : kSplitScreen(get_split_screen()), kSplitOffset(get_split_offset()) {
    int ret = gr_init();

    if (ret < 0) {
        LOGE("gr_init failed\n");
        graphics_available = false;
        return;
    }

    graphics_available = true;
    sys_font = gr_sys_font();
    if (sys_font == nullptr) {
        LOGW("No system font, screen fallback text not available\n");
    } else {
        gr_font_size(sys_font, &char_width_, &char_height_);
    }

    screen_width_ = gr_fb_width() / (kSplitScreen ? 2 : 1);
    screen_height_ = gr_fb_height();

    int res;
    if (!anim->text_clock.font_file.empty() &&
        (res = gr_init_font(anim->text_clock.font_file.c_str(), &anim->text_clock.font)) < 0) {
        LOGE("Could not load time font (%d)\n", res);
    }
    if (!anim->text_percent.font_file.empty() &&
        (res = gr_init_font(anim->text_percent.font_file.c_str(), &anim->text_percent.font)) < 0) {
        LOGE("Could not load percent font (%d)\n", res);
    }
}

HealthdDraw::~HealthdDraw() {}

void HealthdDraw::redraw_screen(const animation* batt_anim, GRSurface* surf_unknown) {
    if (!graphics_available) return;
    clear_screen();

    /* try to display *something* */
    if (batt_anim->cur_status == BATTERY_STATUS_UNKNOWN || batt_anim->cur_level < 0 ||
        batt_anim->num_frames == 0)
        draw_unknown(surf_unknown);
    else
        draw_battery(batt_anim);
    gr_flip();
}

void HealthdDraw::blank_screen(bool blank) {
    if (!graphics_available) return;
    gr_fb_blank(blank);
}

void HealthdDraw::clear_screen(void) {
    if (!graphics_available) return;
    gr_color(0, 0, 0, 255);
    gr_clear();
}

int HealthdDraw::draw_surface_centered(GRSurface* surface) {
    if (!graphics_available) return 0;

    int w = gr_get_width(surface);
    int h = gr_get_height(surface);
    int x = (screen_width_ - w) / 2 + kSplitOffset;
    int y = (screen_height_ - h) / 2;

    LOGV("drawing surface %dx%d+%d+%d\n", w, h, x, y);
    gr_blit(surface, 0, 0, w, h, x, y);
    if (kSplitScreen) {
        x += screen_width_ - 2 * kSplitOffset;
        LOGV("drawing surface %dx%d+%d+%d\n", w, h, x, y);
        gr_blit(surface, 0, 0, w, h, x, y);
    }

    return y + h;
}

int HealthdDraw::draw_text(const GRFont* font, int x, int y, const char* str) {
    if (!graphics_available) return 0;
    int str_len_px = gr_measure(font, str);

    if (x < 0) x = (screen_width_ - str_len_px) / 2;
    if (y < 0) y = (screen_height_ - char_height_) / 2;
    gr_text(font, x + kSplitOffset, y, str, false /* bold */);
    if (kSplitScreen) gr_text(font, x - kSplitOffset + screen_width_, y, str, false /* bold */);

    return y + char_height_;
}

void HealthdDraw::determine_xy(const animation::text_field& field,
                               const int length, int* x, int* y) {
  *x = field.pos_x;

  int str_len_px = length * field.font->char_width;
  if (field.pos_x == CENTER_VAL) {
    *x = (screen_width_ - str_len_px) / 2;
  } else if (field.pos_x >= 0) {
    *x = field.pos_x;
  } else {  // position from max edge
    *x = screen_width_ + field.pos_x - str_len_px - kSplitOffset;
  }

  *y = field.pos_y;

  if (field.pos_y == CENTER_VAL) {
    *y = (screen_height_ - field.font->char_height) / 2;
  } else if (field.pos_y >= 0) {
    *y = field.pos_y;
  } else {  // position from max edge
    *y = screen_height_ + field.pos_y - field.font->char_height;
  }
}

void HealthdDraw::draw_clock(const animation* anim) {
    static constexpr char CLOCK_FORMAT[] = "%H:%M";
    static constexpr int CLOCK_LENGTH = 6;

    const animation::text_field& field = anim->text_clock;

    if (!graphics_available || field.font == nullptr || field.font->char_width == 0 ||
        field.font->char_height == 0)
        return;

    time_t rawtime;
    time(&rawtime);
    tm* time_info = localtime(&rawtime);

    char clock_str[CLOCK_LENGTH];
    size_t length = strftime(clock_str, CLOCK_LENGTH, CLOCK_FORMAT, time_info);
    if (length != CLOCK_LENGTH - 1) {
        LOGE("Could not format time\n");
        return;
    }

    int x, y;
    determine_xy(field, length, &x, &y);

    LOGV("drawing clock %s %d %d\n", clock_str, x, y);
    gr_color(field.color_r, field.color_g, field.color_b, field.color_a);
    draw_text(field.font, x, y, clock_str);
}

void HealthdDraw::draw_percent(const animation* anim) {
    if (!graphics_available) return;
    int cur_level = anim->cur_level;
    if (anim->cur_status == BATTERY_STATUS_FULL) {
        cur_level = 100;
    }

    if (cur_level < 0) return;

    const animation::text_field& field = anim->text_percent;
    if (field.font == nullptr || field.font->char_width == 0 || field.font->char_height == 0) {
        return;
    }

    std::string str = base::StringPrintf("%d%%", cur_level);

    int x, y;
    determine_xy(field, str.size(), &x, &y);

    LOGV("drawing percent %s %d %d\n", str.c_str(), x, y);
    gr_color(field.color_r, field.color_g, field.color_b, field.color_a);
    draw_text(field.font, x, y, str.c_str());
}

void HealthdDraw::draw_battery(const animation* anim) {
    if (!graphics_available) return;
    const animation::frame& frame = anim->frames[anim->cur_frame];

    if (anim->num_frames != 0) {
        draw_surface_centered(frame.surface);
        LOGV("drawing frame #%d min_cap=%d time=%d\n", anim->cur_frame, frame.min_level,
             frame.disp_time);
    }
    draw_clock(anim);
    draw_percent(anim);
}

void HealthdDraw::draw_unknown(GRSurface* surf_unknown) {
  int y;
  if (surf_unknown) {
      draw_surface_centered(surf_unknown);
  } else if (sys_font) {
      gr_color(0xa4, 0xc6, 0x39, 255);
      y = draw_text(sys_font, -1, -1, "Charging!");
      draw_text(sys_font, -1, y + 25, "?\?/100");
  } else {
      LOGW("Charging, level unknown\n");
  }
}
