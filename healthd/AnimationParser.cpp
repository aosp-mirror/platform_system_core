/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "AnimationParser.h"

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <cutils/klog.h>

#include "animation.h"

#define LOGE(x...) do { KLOG_ERROR("charger", x); } while (0)
#define LOGW(x...) do { KLOG_WARNING("charger", x); } while (0)
#define LOGV(x...) do { KLOG_DEBUG("charger", x); } while (0)

namespace android {

// Lines consisting of only whitespace or whitespace followed by '#' can be ignored.
bool can_ignore_line(const char* str) {
    for (int i = 0; str[i] != '\0' && str[i] != '#'; i++) {
        if (!isspace(str[i])) return false;
    }
    return true;
}

bool remove_prefix(std::string_view line, const char* prefix, const char** rest) {
    const char* str = line.data();
    int start;
    char c;

    std::string format = base::StringPrintf(" %s%%n%%c", prefix);
    if (sscanf(str, format.c_str(), &start, &c) != 1) {
        return false;
    }

    *rest = &str[start];
    return true;
}

bool parse_text_field(const char* in, animation::text_field* field) {
    int* x = &field->pos_x;
    int* y = &field->pos_y;
    int* r = &field->color_r;
    int* g = &field->color_g;
    int* b = &field->color_b;
    int* a = &field->color_a;

    int start = 0, end = 0;

    if (sscanf(in, "c c %d %d %d %d %n%*s%n", r, g, b, a, &start, &end) == 4) {
        *x = CENTER_VAL;
        *y = CENTER_VAL;
    } else if (sscanf(in, "c %d %d %d %d %d %n%*s%n", y, r, g, b, a, &start, &end) == 5) {
        *x = CENTER_VAL;
    } else if (sscanf(in, "%d c %d %d %d %d %n%*s%n", x, r, g, b, a, &start, &end) == 5) {
        *y = CENTER_VAL;
    } else if (sscanf(in, "%d %d %d %d %d %d %n%*s%n", x, y, r, g, b, a, &start, &end) != 6) {
        return false;
    }

    if (end == 0) return false;

    field->font_file.assign(&in[start], end - start);

    return true;
}

bool parse_animation_desc(const std::string& content, animation* anim) {
    static constexpr const char* animation_prefix = "animation: ";
    static constexpr const char* fail_prefix = "fail: ";
    static constexpr const char* clock_prefix = "clock_display: ";
    static constexpr const char* percent_prefix = "percent_display: ";

    std::vector<animation::frame> frames;

    for (const auto& line : base::Split(content, "\n")) {
        animation::frame frame;
        const char* rest;

        if (can_ignore_line(line.c_str())) {
            continue;
        } else if (remove_prefix(line, animation_prefix, &rest)) {
            int start = 0, end = 0;
            if (sscanf(rest, "%d %d %n%*s%n", &anim->num_cycles, &anim->first_frame_repeats,
                    &start, &end) != 2 ||
                end == 0) {
                LOGE("Bad animation format: %s\n", line.c_str());
                return false;
            } else {
                anim->animation_file.assign(&rest[start], end - start);
            }
        } else if (remove_prefix(line, fail_prefix, &rest)) {
            anim->fail_file.assign(rest);
        } else if (remove_prefix(line, clock_prefix, &rest)) {
            if (!parse_text_field(rest, &anim->text_clock)) {
                LOGE("Bad clock_display format: %s\n", line.c_str());
                return false;
            }
        } else if (remove_prefix(line, percent_prefix, &rest)) {
            if (!parse_text_field(rest, &anim->text_percent)) {
                LOGE("Bad percent_display format: %s\n", line.c_str());
                return false;
            }
        } else if (sscanf(line.c_str(), " frame: %d %d %d",
                &frame.disp_time, &frame.min_level, &frame.max_level) == 3) {
            frames.push_back(std::move(frame));
        } else {
            LOGE("Malformed animation description line: %s\n", line.c_str());
            return false;
        }
    }

    if (anim->animation_file.empty() || frames.empty()) {
        LOGE("Bad animation description. Provide the 'animation: ' line and at least one 'frame: ' "
             "line.\n");
        return false;
    }

    anim->num_frames = frames.size();
    anim->frames = new animation::frame[frames.size()];
    std::copy(frames.begin(), frames.end(), anim->frames);

    return true;
}

}  // namespace android
