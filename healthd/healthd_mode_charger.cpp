/*
 * Copyright (C) 2011-2017 The Android Open Source Project
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

#include "healthd_mode_charger.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <optional>

#include <android-base/file.h>
#include <android-base/macros.h>

#include <linux/netlink.h>
#include <sys/socket.h>

#include <cutils/android_get_control_file.h>
#include <cutils/klog.h>
#include <cutils/misc.h>
#include <cutils/properties.h>
#include <cutils/uevent.h>
#include <sys/reboot.h>

#include <suspend/autosuspend.h>

#include "AnimationParser.h"
#include "charger.sysprop.h"
#include "charger_utils.h"
#include "healthd_draw.h"

#include <android/hardware/health/2.0/IHealthInfoCallback.h>
#include <health/utils.h>
#include <health2impl/HalHealthLoop.h>
#include <health2impl/Health.h>
#include <healthd/healthd.h>

using namespace android;
using android::hardware::Return;
using android::hardware::health::GetHealthServiceOrDefault;
using android::hardware::health::HealthLoop;
using android::hardware::health::V1_0::BatteryStatus;
using android::hardware::health::V2_0::Result;
using android::hardware::health::V2_1::IHealth;
using IHealth_2_0 = android::hardware::health::V2_0::IHealth;
using HealthInfo_1_0 = android::hardware::health::V1_0::HealthInfo;
using HealthInfo_2_1 = android::hardware::health::V2_1::HealthInfo;

// main healthd loop
extern int healthd_main(void);

// minui globals
char* locale;

#ifndef max
#define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define MSEC_PER_SEC (1000LL)
#define NSEC_PER_MSEC (1000000LL)

#define BATTERY_UNKNOWN_TIME (2 * MSEC_PER_SEC)
#define POWER_ON_KEY_TIME (2 * MSEC_PER_SEC)
#define UNPLUGGED_SHUTDOWN_TIME (10 * MSEC_PER_SEC)
#define UNPLUGGED_DISPLAY_TIME (3 * MSEC_PER_SEC)
#define MAX_BATT_LEVEL_WAIT_TIME (3 * MSEC_PER_SEC)
#define UNPLUGGED_SHUTDOWN_TIME_PROP "ro.product.charger.unplugged_shutdown_time"

#define LAST_KMSG_MAX_SZ (32 * 1024)

#define LOGE(x...) KLOG_ERROR("charger", x);
#define LOGW(x...) KLOG_WARNING("charger", x);
#define LOGV(x...) KLOG_DEBUG("charger", x);

namespace android {

// Resources in /product/etc/res overrides resources in /res.
// If the device is using the Generic System Image (GSI), resources may exist in
// both paths.
static constexpr const char* product_animation_desc_path =
        "/product/etc/res/values/charger/animation.txt";
static constexpr const char* product_animation_root = "/product/etc/res/images/";
static constexpr const char* animation_desc_path = "/res/values/charger/animation.txt";

static const animation BASE_ANIMATION = {
    .text_clock =
        {
            .pos_x = 0,
            .pos_y = 0,

            .color_r = 255,
            .color_g = 255,
            .color_b = 255,
            .color_a = 255,

            .font = nullptr,
        },
    .text_percent =
        {
            .pos_x = 0,
            .pos_y = 0,

            .color_r = 255,
            .color_g = 255,
            .color_b = 255,
            .color_a = 255,
        },

    .run = false,

    .frames = nullptr,
    .cur_frame = 0,
    .num_frames = 0,
    .first_frame_repeats = 2,

    .cur_cycle = 0,
    .num_cycles = 3,

    .cur_level = 0,
    .cur_status = BATTERY_STATUS_UNKNOWN,
};

void Charger::InitDefaultAnimationFrames() {
    owned_frames_ = {
            {
                    .disp_time = 750,
                    .min_level = 0,
                    .max_level = 19,
                    .surface = NULL,
            },
            {
                    .disp_time = 750,
                    .min_level = 0,
                    .max_level = 39,
                    .surface = NULL,
            },
            {
                    .disp_time = 750,
                    .min_level = 0,
                    .max_level = 59,
                    .surface = NULL,
            },
            {
                    .disp_time = 750,
                    .min_level = 0,
                    .max_level = 79,
                    .surface = NULL,
            },
            {
                    .disp_time = 750,
                    .min_level = 80,
                    .max_level = 95,
                    .surface = NULL,
            },
            {
                    .disp_time = 750,
                    .min_level = 0,
                    .max_level = 100,
                    .surface = NULL,
            },
    };
}

Charger::Charger(const sp<IHealth>& service)
    : HalHealthLoop("charger", service), batt_anim_(BASE_ANIMATION) {}

Charger::~Charger() {}

/* current time in milliseconds */
static int64_t curr_time_ms() {
    timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm);
    return tm.tv_sec * MSEC_PER_SEC + (tm.tv_nsec / NSEC_PER_MSEC);
}

#define MAX_KLOG_WRITE_BUF_SZ 256

static void dump_last_kmsg(void) {
    std::string buf;
    char* ptr;
    size_t len;

    LOGW("\n");
    LOGW("*************** LAST KMSG ***************\n");
    LOGW("\n");
    const char* kmsg[] = {
        // clang-format off
        "/sys/fs/pstore/console-ramoops-0",
        "/sys/fs/pstore/console-ramoops",
        "/proc/last_kmsg",
        // clang-format on
    };
    for (size_t i = 0; i < arraysize(kmsg) && buf.empty(); ++i) {
        auto fd = android_get_control_file(kmsg[i]);
        if (fd >= 0) {
            android::base::ReadFdToString(fd, &buf);
        } else {
            android::base::ReadFileToString(kmsg[i], &buf);
        }
    }

    if (buf.empty()) {
        LOGW("last_kmsg not found. Cold reset?\n");
        goto out;
    }

    len = min(buf.size(), LAST_KMSG_MAX_SZ);
    ptr = &buf[buf.size() - len];

    while (len > 0) {
        size_t cnt = min(len, MAX_KLOG_WRITE_BUF_SZ);
        char yoink;
        char* nl;

        nl = (char*)memrchr(ptr, '\n', cnt - 1);
        if (nl) cnt = nl - ptr + 1;

        yoink = ptr[cnt];
        ptr[cnt] = '\0';
        klog_write(6, "<4>%s", ptr);
        ptr[cnt] = yoink;

        len -= cnt;
        ptr += cnt;
    }

out:
    LOGW("\n");
    LOGW("************* END LAST KMSG *************\n");
    LOGW("\n");
}

static int request_suspend(bool enable) {
    if (!android::sysprop::ChargerProperties::enable_suspend().value_or(false)) {
        return 0;
    }

    if (enable)
        return autosuspend_enable();
    else
        return autosuspend_disable();
}

static void kick_animation(animation* anim) {
    anim->run = true;
}

static void reset_animation(animation* anim) {
    anim->cur_cycle = 0;
    anim->cur_frame = 0;
    anim->run = false;
}

void Charger::UpdateScreenState(int64_t now) {
    int disp_time;

    if (!batt_anim_.run || now < next_screen_transition_) return;

    // If battery level is not ready, keep checking in the defined time
    if (health_info_.batteryLevel == 0 && health_info_.batteryStatus == BatteryStatus::UNKNOWN) {
        if (wait_batt_level_timestamp_ == 0) {
            // Set max delay time and skip drawing screen
            wait_batt_level_timestamp_ = now + MAX_BATT_LEVEL_WAIT_TIME;
            LOGV("[%" PRId64 "] wait for battery capacity ready\n", now);
            return;
        } else if (now <= wait_batt_level_timestamp_) {
            // Do nothing, keep waiting
            return;
        }
        // If timeout and battery level is still not ready, draw unknown battery
    }

    if (healthd_draw_ == nullptr) {
        std::optional<bool> out_screen_on;
        service()->shouldKeepScreenOn([&](Result res, bool screen_on) {
            if (res == Result::SUCCESS) {
                *out_screen_on = screen_on;
            }
        });
        if (out_screen_on.has_value()) {
            if (!*out_screen_on) {
                LOGV("[%" PRId64 "] leave screen off\n", now);
                batt_anim_.run = false;
                next_screen_transition_ = -1;
                if (charger_online()) request_suspend(true);
                return;
            }
        }

        healthd_draw_.reset(new HealthdDraw(&batt_anim_));

        if (android::sysprop::ChargerProperties::disable_init_blank().value_or(false)) {
            healthd_draw_->blank_screen(true);
            screen_blanked_ = true;
        }
    }

    /* animation is over, blank screen and leave */
    if (batt_anim_.num_cycles > 0 && batt_anim_.cur_cycle == batt_anim_.num_cycles) {
        reset_animation(&batt_anim_);
        next_screen_transition_ = -1;
        healthd_draw_->blank_screen(true);
        screen_blanked_ = true;
        LOGV("[%" PRId64 "] animation done\n", now);
        if (charger_online()) request_suspend(true);
        return;
    }

    disp_time = batt_anim_.frames[batt_anim_.cur_frame].disp_time;

    if (screen_blanked_) {
        healthd_draw_->blank_screen(false);
        screen_blanked_ = false;
    }

    /* animation starting, set up the animation */
    if (batt_anim_.cur_frame == 0) {
        LOGV("[%" PRId64 "] animation starting\n", now);
        batt_anim_.cur_level = health_info_.batteryLevel;
        batt_anim_.cur_status = (int)health_info_.batteryStatus;
        if (health_info_.batteryLevel >= 0 && batt_anim_.num_frames != 0) {
            /* find first frame given current battery level */
            for (int i = 0; i < batt_anim_.num_frames; i++) {
                if (batt_anim_.cur_level >= batt_anim_.frames[i].min_level &&
                    batt_anim_.cur_level <= batt_anim_.frames[i].max_level) {
                    batt_anim_.cur_frame = i;
                    break;
                }
            }

            if (charger_online()) {
                // repeat the first frame first_frame_repeats times
                disp_time = batt_anim_.frames[batt_anim_.cur_frame].disp_time *
                            batt_anim_.first_frame_repeats;
            } else {
                disp_time = UNPLUGGED_DISPLAY_TIME / batt_anim_.num_cycles;
            }

            LOGV("cur_frame=%d disp_time=%d\n", batt_anim_.cur_frame, disp_time);
        }
    }

    /* draw the new frame (@ cur_frame) */
    healthd_draw_->redraw_screen(&batt_anim_, surf_unknown_);

    /* if we don't have anim frames, we only have one image, so just bump
     * the cycle counter and exit
     */
    if (batt_anim_.num_frames == 0 || batt_anim_.cur_level < 0) {
        LOGW("[%" PRId64 "] animation missing or unknown battery status\n", now);
        next_screen_transition_ = now + BATTERY_UNKNOWN_TIME;
        batt_anim_.cur_cycle++;
        return;
    }

    /* schedule next screen transition */
    next_screen_transition_ = curr_time_ms() + disp_time;

    /* advance frame cntr to the next valid frame only if we are charging
     * if necessary, advance cycle cntr, and reset frame cntr
     */
    if (charger_online()) {
        batt_anim_.cur_frame++;

        while (batt_anim_.cur_frame < batt_anim_.num_frames &&
               (batt_anim_.cur_level < batt_anim_.frames[batt_anim_.cur_frame].min_level ||
                batt_anim_.cur_level > batt_anim_.frames[batt_anim_.cur_frame].max_level)) {
            batt_anim_.cur_frame++;
        }
        if (batt_anim_.cur_frame >= batt_anim_.num_frames) {
            batt_anim_.cur_cycle++;
            batt_anim_.cur_frame = 0;

            /* don't reset the cycle counter, since we use that as a signal
             * in a test above to check if animation is over
             */
        }
    } else {
        /* Stop animating if we're not charging.
         * If we stop it immediately instead of going through this loop, then
         * the animation would stop somewhere in the middle.
         */
        batt_anim_.cur_frame = 0;
        batt_anim_.cur_cycle++;
    }
}

int Charger::SetKeyCallback(int code, int value) {
    int64_t now = curr_time_ms();
    int down = !!value;

    if (code > KEY_MAX) return -1;

    /* ignore events that don't modify our state */
    if (keys_[code].down == down) return 0;

    /* only record the down even timestamp, as the amount
     * of time the key spent not being pressed is not useful */
    if (down) keys_[code].timestamp = now;
    keys_[code].down = down;
    keys_[code].pending = true;
    if (down) {
        LOGV("[%" PRId64 "] key[%d] down\n", now, code);
    } else {
        int64_t duration = now - keys_[code].timestamp;
        int64_t secs = duration / 1000;
        int64_t msecs = duration - secs * 1000;
        LOGV("[%" PRId64 "] key[%d] up (was down for %" PRId64 ".%" PRId64 "sec)\n", now, code,
             secs, msecs);
    }

    return 0;
}

void Charger::UpdateInputState(input_event* ev) {
    if (ev->type != EV_KEY) return;
    SetKeyCallback(ev->code, ev->value);
}

void Charger::SetNextKeyCheck(key_state* key, int64_t timeout) {
    int64_t then = key->timestamp + timeout;

    if (next_key_check_ == -1 || then < next_key_check_) next_key_check_ = then;
}

void Charger::ProcessKey(int code, int64_t now) {
    key_state* key = &keys_[code];

    if (code == KEY_POWER) {
        if (key->down) {
            int64_t reboot_timeout = key->timestamp + POWER_ON_KEY_TIME;
            if (now >= reboot_timeout) {
                /* We do not currently support booting from charger mode on
                   all devices. Check the property and continue booting or reboot
                   accordingly. */
                if (property_get_bool("ro.enable_boot_charger_mode", false)) {
                    LOGW("[%" PRId64 "] booting from charger mode\n", now);
                    property_set("sys.boot_from_charger_mode", "1");
                } else {
                    if (batt_anim_.cur_level >= boot_min_cap_) {
                        LOGW("[%" PRId64 "] rebooting\n", now);
                        reboot(RB_AUTOBOOT);
                    } else {
                        LOGV("[%" PRId64
                             "] ignore power-button press, battery level "
                             "less than minimum\n",
                             now);
                    }
                }
            } else {
                /* if the key is pressed but timeout hasn't expired,
                 * make sure we wake up at the right-ish time to check
                 */
                SetNextKeyCheck(key, POWER_ON_KEY_TIME);

                /* Turn on the display and kick animation on power-key press
                 * rather than on key release
                 */
                kick_animation(&batt_anim_);
                request_suspend(false);
            }
        } else {
            /* if the power key got released, force screen state cycle */
            if (key->pending) {
                kick_animation(&batt_anim_);
                request_suspend(false);
            }
        }
    }

    key->pending = false;
}

void Charger::HandleInputState(int64_t now) {
    ProcessKey(KEY_POWER, now);

    if (next_key_check_ != -1 && now > next_key_check_) next_key_check_ = -1;
}

void Charger::HandlePowerSupplyState(int64_t now) {
    int timer_shutdown = UNPLUGGED_SHUTDOWN_TIME;
    if (!have_battery_state_) return;

    if (!charger_online()) {
        request_suspend(false);
        if (next_pwr_check_ == -1) {
            /* Last cycle would have stopped at the extreme top of battery-icon
             * Need to show the correct level corresponding to capacity.
             *
             * Reset next_screen_transition_ to update screen immediately.
             * Reset & kick animation to show complete animation cycles
             * when charger disconnected.
             */
            timer_shutdown =
                    property_get_int32(UNPLUGGED_SHUTDOWN_TIME_PROP, UNPLUGGED_SHUTDOWN_TIME);
            next_screen_transition_ = now - 1;
            reset_animation(&batt_anim_);
            kick_animation(&batt_anim_);
            next_pwr_check_ = now + timer_shutdown;
            LOGW("[%" PRId64 "] device unplugged: shutting down in %" PRId64 " (@ %" PRId64 ")\n",
                 now, (int64_t)timer_shutdown, next_pwr_check_);
        } else if (now >= next_pwr_check_) {
            LOGW("[%" PRId64 "] shutting down\n", now);
            reboot(RB_POWER_OFF);
        } else {
            /* otherwise we already have a shutdown timer scheduled */
        }
    } else {
        /* online supply present, reset shutdown timer if set */
        if (next_pwr_check_ != -1) {
            /* Reset next_screen_transition_ to update screen immediately.
             * Reset & kick animation to show complete animation cycles
             * when charger connected again.
             */
            request_suspend(false);
            next_screen_transition_ = now - 1;
            reset_animation(&batt_anim_);
            kick_animation(&batt_anim_);
            LOGW("[%" PRId64 "] device plugged in: shutdown cancelled\n", now);
        }
        next_pwr_check_ = -1;
    }
}

void Charger::Heartbeat() {
    // charger* charger = &charger_state;
    int64_t now = curr_time_ms();

    HandleInputState(now);
    HandlePowerSupplyState(now);

    /* do screen update last in case any of the above want to start
     * screen transitions (animations, etc)
     */
    UpdateScreenState(now);
}

void Charger::OnHealthInfoChanged(const HealthInfo_2_1& health_info) {
    set_charger_online(health_info);

    if (!have_battery_state_) {
        have_battery_state_ = true;
        next_screen_transition_ = curr_time_ms() - 1;
        request_suspend(false);
        reset_animation(&batt_anim_);
        kick_animation(&batt_anim_);
    }
    health_info_ = health_info.legacy.legacy;

    AdjustWakealarmPeriods(charger_online());
}

int Charger::PrepareToWait(void) {
    int64_t now = curr_time_ms();
    int64_t next_event = INT64_MAX;
    int64_t timeout;

    LOGV("[%" PRId64 "] next screen: %" PRId64 " next key: %" PRId64 " next pwr: %" PRId64 "\n",
         now, next_screen_transition_, next_key_check_, next_pwr_check_);

    if (next_screen_transition_ != -1) next_event = next_screen_transition_;
    if (next_key_check_ != -1 && next_key_check_ < next_event) next_event = next_key_check_;
    if (next_pwr_check_ != -1 && next_pwr_check_ < next_event) next_event = next_pwr_check_;

    if (next_event != -1 && next_event != INT64_MAX)
        timeout = max(0, next_event - now);
    else
        timeout = -1;

    return (int)timeout;
}

int Charger::InputCallback(int fd, unsigned int epevents) {
    input_event ev;
    int ret;

    ret = ev_get_input(fd, epevents, &ev);
    if (ret) return -1;
    UpdateInputState(&ev);
    return 0;
}

static void charger_event_handler(HealthLoop* /*charger_loop*/, uint32_t /*epevents*/) {
    int ret;

    ret = ev_wait(-1);
    if (!ret) ev_dispatch();
}

void Charger::InitAnimation() {
    bool parse_success;

    std::string content;
    if (base::ReadFileToString(product_animation_desc_path, &content)) {
        parse_success = parse_animation_desc(content, &batt_anim_);
        batt_anim_.set_resource_root(product_animation_root);
    } else if (base::ReadFileToString(animation_desc_path, &content)) {
        parse_success = parse_animation_desc(content, &batt_anim_);
    } else {
        LOGW("Could not open animation description at %s\n", animation_desc_path);
        parse_success = false;
    }

    if (!parse_success) {
        LOGW("Could not parse animation description. Using default animation.\n");
        batt_anim_ = BASE_ANIMATION;
        batt_anim_.animation_file.assign("charger/battery_scale");
        InitDefaultAnimationFrames();
        batt_anim_.frames = owned_frames_.data();
        batt_anim_.num_frames = owned_frames_.size();
    }
    if (batt_anim_.fail_file.empty()) {
        batt_anim_.fail_file.assign("charger/battery_fail");
    }

    LOGV("Animation Description:\n");
    LOGV("  animation: %d %d '%s' (%d)\n", batt_anim_.num_cycles, batt_anim_.first_frame_repeats,
         batt_anim_.animation_file.c_str(), batt_anim_.num_frames);
    LOGV("  fail_file: '%s'\n", batt_anim_.fail_file.c_str());
    LOGV("  clock: %d %d %d %d %d %d '%s'\n", batt_anim_.text_clock.pos_x,
         batt_anim_.text_clock.pos_y, batt_anim_.text_clock.color_r, batt_anim_.text_clock.color_g,
         batt_anim_.text_clock.color_b, batt_anim_.text_clock.color_a,
         batt_anim_.text_clock.font_file.c_str());
    LOGV("  percent: %d %d %d %d %d %d '%s'\n", batt_anim_.text_percent.pos_x,
         batt_anim_.text_percent.pos_y, batt_anim_.text_percent.color_r,
         batt_anim_.text_percent.color_g, batt_anim_.text_percent.color_b,
         batt_anim_.text_percent.color_a, batt_anim_.text_percent.font_file.c_str());
    for (int i = 0; i < batt_anim_.num_frames; i++) {
        LOGV("  frame %.2d: %d %d %d\n", i, batt_anim_.frames[i].disp_time,
             batt_anim_.frames[i].min_level, batt_anim_.frames[i].max_level);
    }
}

void Charger::Init(struct healthd_config* config) {
    int ret;
    int i;
    int epollfd;

    dump_last_kmsg();

    LOGW("--------------- STARTING CHARGER MODE ---------------\n");

    ret = ev_init(
            std::bind(&Charger::InputCallback, this, std::placeholders::_1, std::placeholders::_2));
    if (!ret) {
        epollfd = ev_get_epollfd();
        RegisterEvent(epollfd, &charger_event_handler, EVENT_WAKEUP_FD);
    }

    InitAnimation();

    ret = res_create_display_surface(batt_anim_.fail_file.c_str(), &surf_unknown_);
    if (ret < 0) {
        LOGE("Cannot load custom battery_fail image. Reverting to built in: %d\n", ret);
        ret = res_create_display_surface("charger/battery_fail", &surf_unknown_);
        if (ret < 0) {
            LOGE("Cannot load built in battery_fail image\n");
            surf_unknown_ = NULL;
        }
    }

    GRSurface** scale_frames;
    int scale_count;
    int scale_fps;  // Not in use (charger/battery_scale doesn't have FPS text
                    // chunk). We are using hard-coded frame.disp_time instead.
    ret = res_create_multi_display_surface(batt_anim_.animation_file.c_str(), &scale_count,
                                           &scale_fps, &scale_frames);
    if (ret < 0) {
        LOGE("Cannot load battery_scale image\n");
        batt_anim_.num_frames = 0;
        batt_anim_.num_cycles = 1;
    } else if (scale_count != batt_anim_.num_frames) {
        LOGE("battery_scale image has unexpected frame count (%d, expected %d)\n", scale_count,
             batt_anim_.num_frames);
        batt_anim_.num_frames = 0;
        batt_anim_.num_cycles = 1;
    } else {
        for (i = 0; i < batt_anim_.num_frames; i++) {
            batt_anim_.frames[i].surface = scale_frames[i];
        }
    }
    ev_sync_key_state(std::bind(&Charger::SetKeyCallback, this, std::placeholders::_1,
                                std::placeholders::_2));

    next_screen_transition_ = -1;
    next_key_check_ = -1;
    next_pwr_check_ = -1;
    wait_batt_level_timestamp_ = 0;

    // Retrieve healthd_config from the existing health HAL.
    HalHealthLoop::Init(config);

    boot_min_cap_ = config->boot_min_cap;
}

}  // namespace android

int healthd_charger_main(int argc, char** argv) {
    int ch;

    while ((ch = getopt(argc, argv, "cr")) != -1) {
        switch (ch) {
            case 'c':
                // -c is now a noop
                break;
            case 'r':
                // -r is now a noop
                break;
            case '?':
            default:
                LOGE("Unrecognized charger option: %c\n", optopt);
                exit(1);
        }
    }

    Charger charger(GetHealthServiceOrDefault());
    return charger.StartLoop();
}
