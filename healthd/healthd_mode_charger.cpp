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

#include <functional>

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

#ifdef CHARGER_ENABLE_SUSPEND
#include <suspend/autosuspend.h>
#endif

#include "AnimationParser.h"
#include "healthd_draw.h"

#include <health2/Health.h>
#include <healthd/healthd.h>

using namespace android;

// main healthd loop
extern int healthd_main(void);

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

#define LAST_KMSG_MAX_SZ (32 * 1024)

#define LOGE(x...) KLOG_ERROR("charger", x);
#define LOGW(x...) KLOG_WARNING("charger", x);
#define LOGV(x...) KLOG_DEBUG("charger", x);

// Resources in /product/etc/res overrides resources in /res.
// If the device is using the Generic System Image (GSI), resources may exist in
// both paths.
static constexpr const char* product_animation_desc_path =
        "/product/etc/res/values/charger/animation.txt";
static constexpr const char* product_animation_root = "/product/etc/res/images/";
static constexpr const char* animation_desc_path = "/res/values/charger/animation.txt";

struct key_state {
    bool pending;
    bool down;
    int64_t timestamp;
};

struct charger {
    bool have_battery_state;
    bool charger_connected;
    bool screen_blanked;
    int64_t next_screen_transition;
    int64_t next_key_check;
    int64_t next_pwr_check;
    int64_t wait_batt_level_timestamp;

    key_state keys[KEY_MAX + 1];

    animation* batt_anim;
    GRSurface* surf_unknown;
    int boot_min_cap;
};

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

static animation::frame default_animation_frames[] = {
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

static animation battery_animation = BASE_ANIMATION;

static charger charger_state;
static healthd_config* healthd_config;
static android::BatteryProperties* batt_prop;
static std::unique_ptr<HealthdDraw> healthd_draw;

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

#ifdef CHARGER_ENABLE_SUSPEND
static int request_suspend(bool enable) {
    if (enable)
        return autosuspend_enable();
    else
        return autosuspend_disable();
}
#else
static int request_suspend(bool /*enable*/) {
    return 0;
}
#endif

static void kick_animation(animation* anim) {
    anim->run = true;
}

static void reset_animation(animation* anim) {
    anim->cur_cycle = 0;
    anim->cur_frame = 0;
    anim->run = false;
}

static void update_screen_state(charger* charger, int64_t now) {
    animation* batt_anim = charger->batt_anim;
    int disp_time;

    if (!batt_anim->run || now < charger->next_screen_transition) return;

    // If battery level is not ready, keep checking in the defined time
    if (batt_prop == nullptr ||
        (batt_prop->batteryLevel == 0 && batt_prop->batteryStatus == BATTERY_STATUS_UNKNOWN)) {
        if (charger->wait_batt_level_timestamp == 0) {
            // Set max delay time and skip drawing screen
            charger->wait_batt_level_timestamp = now + MAX_BATT_LEVEL_WAIT_TIME;
            LOGV("[%" PRId64 "] wait for battery capacity ready\n", now);
            return;
        } else if (now <= charger->wait_batt_level_timestamp) {
            // Do nothing, keep waiting
            return;
        }
        // If timeout and battery level is still not ready, draw unknown battery
    }

    if (healthd_draw == nullptr) {
        if (healthd_config && healthd_config->screen_on) {
            if (!healthd_config->screen_on(batt_prop)) {
                LOGV("[%" PRId64 "] leave screen off\n", now);
                batt_anim->run = false;
                charger->next_screen_transition = -1;
                if (charger->charger_connected) request_suspend(true);
                return;
            }
        }

        healthd_draw.reset(new HealthdDraw(batt_anim));

#ifndef CHARGER_DISABLE_INIT_BLANK
        healthd_draw->blank_screen(true);
        charger->screen_blanked = true;
#endif
    }

    /* animation is over, blank screen and leave */
    if (batt_anim->num_cycles > 0 && batt_anim->cur_cycle == batt_anim->num_cycles) {
        reset_animation(batt_anim);
        charger->next_screen_transition = -1;
        healthd_draw->blank_screen(true);
        charger->screen_blanked = true;
        LOGV("[%" PRId64 "] animation done\n", now);
        if (charger->charger_connected) request_suspend(true);
        return;
    }

    disp_time = batt_anim->frames[batt_anim->cur_frame].disp_time;

    if (charger->screen_blanked) {
        healthd_draw->blank_screen(false);
        charger->screen_blanked = false;
    }

    /* animation starting, set up the animation */
    if (batt_anim->cur_frame == 0) {
        LOGV("[%" PRId64 "] animation starting\n", now);
        if (batt_prop) {
            batt_anim->cur_level = batt_prop->batteryLevel;
            batt_anim->cur_status = batt_prop->batteryStatus;
            if (batt_prop->batteryLevel >= 0 && batt_anim->num_frames != 0) {
                /* find first frame given current battery level */
                for (int i = 0; i < batt_anim->num_frames; i++) {
                    if (batt_anim->cur_level >= batt_anim->frames[i].min_level &&
                        batt_anim->cur_level <= batt_anim->frames[i].max_level) {
                        batt_anim->cur_frame = i;
                        break;
                    }
                }

                if (charger->charger_connected) {
                    // repeat the first frame first_frame_repeats times
                    disp_time = batt_anim->frames[batt_anim->cur_frame].disp_time *
                                batt_anim->first_frame_repeats;
                } else {
                    disp_time = UNPLUGGED_DISPLAY_TIME / batt_anim->num_cycles;
                }

                LOGV("cur_frame=%d disp_time=%d\n", batt_anim->cur_frame, disp_time);
            }
        }
    }

    /* draw the new frame (@ cur_frame) */
    healthd_draw->redraw_screen(charger->batt_anim, charger->surf_unknown);

    /* if we don't have anim frames, we only have one image, so just bump
     * the cycle counter and exit
     */
    if (batt_anim->num_frames == 0 || batt_anim->cur_level < 0) {
        LOGW("[%" PRId64 "] animation missing or unknown battery status\n", now);
        charger->next_screen_transition = now + BATTERY_UNKNOWN_TIME;
        batt_anim->cur_cycle++;
        return;
    }

    /* schedule next screen transition */
    charger->next_screen_transition = curr_time_ms() + disp_time;

    /* advance frame cntr to the next valid frame only if we are charging
     * if necessary, advance cycle cntr, and reset frame cntr
     */
    if (charger->charger_connected) {
        batt_anim->cur_frame++;

        while (batt_anim->cur_frame < batt_anim->num_frames &&
               (batt_anim->cur_level < batt_anim->frames[batt_anim->cur_frame].min_level ||
                batt_anim->cur_level > batt_anim->frames[batt_anim->cur_frame].max_level)) {
            batt_anim->cur_frame++;
        }
        if (batt_anim->cur_frame >= batt_anim->num_frames) {
            batt_anim->cur_cycle++;
            batt_anim->cur_frame = 0;

            /* don't reset the cycle counter, since we use that as a signal
             * in a test above to check if animation is over
             */
        }
    } else {
        /* Stop animating if we're not charging.
         * If we stop it immediately instead of going through this loop, then
         * the animation would stop somewhere in the middle.
         */
        batt_anim->cur_frame = 0;
        batt_anim->cur_cycle++;
    }
}

static int set_key_callback(charger* charger, int code, int value) {
    int64_t now = curr_time_ms();
    int down = !!value;

    if (code > KEY_MAX) return -1;

    /* ignore events that don't modify our state */
    if (charger->keys[code].down == down) return 0;

    /* only record the down even timestamp, as the amount
     * of time the key spent not being pressed is not useful */
    if (down) charger->keys[code].timestamp = now;
    charger->keys[code].down = down;
    charger->keys[code].pending = true;
    if (down) {
        LOGV("[%" PRId64 "] key[%d] down\n", now, code);
    } else {
        int64_t duration = now - charger->keys[code].timestamp;
        int64_t secs = duration / 1000;
        int64_t msecs = duration - secs * 1000;
        LOGV("[%" PRId64 "] key[%d] up (was down for %" PRId64 ".%" PRId64 "sec)\n", now, code,
             secs, msecs);
    }

    return 0;
}

static void update_input_state(charger* charger, input_event* ev) {
    if (ev->type != EV_KEY) return;
    set_key_callback(charger, ev->code, ev->value);
}

static void set_next_key_check(charger* charger, key_state* key, int64_t timeout) {
    int64_t then = key->timestamp + timeout;

    if (charger->next_key_check == -1 || then < charger->next_key_check)
        charger->next_key_check = then;
}

static void process_key(charger* charger, int code, int64_t now) {
    key_state* key = &charger->keys[code];

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
                    if (charger->batt_anim->cur_level >= charger->boot_min_cap) {
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
                set_next_key_check(charger, key, POWER_ON_KEY_TIME);

                /* Turn on the display and kick animation on power-key press
                 * rather than on key release
                 */
                kick_animation(charger->batt_anim);
                request_suspend(false);
            }
        } else {
            /* if the power key got released, force screen state cycle */
            if (key->pending) {
                kick_animation(charger->batt_anim);
                request_suspend(false);
            }
        }
    }

    key->pending = false;
}

static void handle_input_state(charger* charger, int64_t now) {
    process_key(charger, KEY_POWER, now);

    if (charger->next_key_check != -1 && now > charger->next_key_check)
        charger->next_key_check = -1;
}

static void handle_power_supply_state(charger* charger, int64_t now) {
    if (!charger->have_battery_state) return;

    if (!charger->charger_connected) {
        request_suspend(false);
        if (charger->next_pwr_check == -1) {
            /* Last cycle would have stopped at the extreme top of battery-icon
             * Need to show the correct level corresponding to capacity.
             *
             * Reset next_screen_transition to update screen immediately.
             * Reset & kick animation to show complete animation cycles
             * when charger disconnected.
             */
            charger->next_screen_transition = now - 1;
            reset_animation(charger->batt_anim);
            kick_animation(charger->batt_anim);
            charger->next_pwr_check = now + UNPLUGGED_SHUTDOWN_TIME;
            LOGW("[%" PRId64 "] device unplugged: shutting down in %" PRId64 " (@ %" PRId64 ")\n",
                 now, (int64_t)UNPLUGGED_SHUTDOWN_TIME, charger->next_pwr_check);
        } else if (now >= charger->next_pwr_check) {
            LOGW("[%" PRId64 "] shutting down\n", now);
            reboot(RB_POWER_OFF);
        } else {
            /* otherwise we already have a shutdown timer scheduled */
        }
    } else {
        /* online supply present, reset shutdown timer if set */
        if (charger->next_pwr_check != -1) {
            /* Reset next_screen_transition to update screen immediately.
             * Reset & kick animation to show complete animation cycles
             * when charger connected again.
             */
            request_suspend(false);
            charger->next_screen_transition = now - 1;
            reset_animation(charger->batt_anim);
            kick_animation(charger->batt_anim);
            LOGW("[%" PRId64 "] device plugged in: shutdown cancelled\n", now);
        }
        charger->next_pwr_check = -1;
    }
}

void healthd_mode_charger_heartbeat() {
    charger* charger = &charger_state;
    int64_t now = curr_time_ms();

    handle_input_state(charger, now);
    handle_power_supply_state(charger, now);

    /* do screen update last in case any of the above want to start
     * screen transitions (animations, etc)
     */
    update_screen_state(charger, now);
}

void healthd_mode_charger_battery_update(android::BatteryProperties* props) {
    charger* charger = &charger_state;

    charger->charger_connected =
        props->chargerAcOnline || props->chargerUsbOnline || props->chargerWirelessOnline;

    if (!charger->have_battery_state) {
        charger->have_battery_state = true;
        charger->next_screen_transition = curr_time_ms() - 1;
        request_suspend(false);
        reset_animation(charger->batt_anim);
        kick_animation(charger->batt_anim);
    }
    batt_prop = props;
}

int healthd_mode_charger_preparetowait(void) {
    charger* charger = &charger_state;
    int64_t now = curr_time_ms();
    int64_t next_event = INT64_MAX;
    int64_t timeout;

    LOGV("[%" PRId64 "] next screen: %" PRId64 " next key: %" PRId64 " next pwr: %" PRId64 "\n",
         now, charger->next_screen_transition, charger->next_key_check, charger->next_pwr_check);

    if (charger->next_screen_transition != -1) next_event = charger->next_screen_transition;
    if (charger->next_key_check != -1 && charger->next_key_check < next_event)
        next_event = charger->next_key_check;
    if (charger->next_pwr_check != -1 && charger->next_pwr_check < next_event)
        next_event = charger->next_pwr_check;

    if (next_event != -1 && next_event != INT64_MAX)
        timeout = max(0, next_event - now);
    else
        timeout = -1;

    return (int)timeout;
}

static int input_callback(charger* charger, int fd, unsigned int epevents) {
    input_event ev;
    int ret;

    ret = ev_get_input(fd, epevents, &ev);
    if (ret) return -1;
    update_input_state(charger, &ev);
    return 0;
}

static void charger_event_handler(uint32_t /*epevents*/) {
    int ret;

    ret = ev_wait(-1);
    if (!ret) ev_dispatch();
}

animation* init_animation() {
    bool parse_success;

    std::string content;
    if (base::ReadFileToString(product_animation_desc_path, &content)) {
        parse_success = parse_animation_desc(content, &battery_animation);
        battery_animation.set_resource_root(product_animation_root);
    } else if (base::ReadFileToString(animation_desc_path, &content)) {
        parse_success = parse_animation_desc(content, &battery_animation);
    } else {
        LOGW("Could not open animation description at %s\n", animation_desc_path);
        parse_success = false;
    }

    if (!parse_success) {
        LOGW("Could not parse animation description. Using default animation.\n");
        battery_animation = BASE_ANIMATION;
        battery_animation.animation_file.assign("charger/battery_scale");
        battery_animation.frames = default_animation_frames;
        battery_animation.num_frames = ARRAY_SIZE(default_animation_frames);
    }
    if (battery_animation.fail_file.empty()) {
        battery_animation.fail_file.assign("charger/battery_fail");
    }

    LOGV("Animation Description:\n");
    LOGV("  animation: %d %d '%s' (%d)\n", battery_animation.num_cycles,
         battery_animation.first_frame_repeats, battery_animation.animation_file.c_str(),
         battery_animation.num_frames);
    LOGV("  fail_file: '%s'\n", battery_animation.fail_file.c_str());
    LOGV("  clock: %d %d %d %d %d %d '%s'\n", battery_animation.text_clock.pos_x,
         battery_animation.text_clock.pos_y, battery_animation.text_clock.color_r,
         battery_animation.text_clock.color_g, battery_animation.text_clock.color_b,
         battery_animation.text_clock.color_a, battery_animation.text_clock.font_file.c_str());
    LOGV("  percent: %d %d %d %d %d %d '%s'\n", battery_animation.text_percent.pos_x,
         battery_animation.text_percent.pos_y, battery_animation.text_percent.color_r,
         battery_animation.text_percent.color_g, battery_animation.text_percent.color_b,
         battery_animation.text_percent.color_a, battery_animation.text_percent.font_file.c_str());
    for (int i = 0; i < battery_animation.num_frames; i++) {
        LOGV("  frame %.2d: %d %d %d\n", i, battery_animation.frames[i].disp_time,
             battery_animation.frames[i].min_level, battery_animation.frames[i].max_level);
    }

    return &battery_animation;
}

void healthd_mode_charger_init(struct healthd_config* config) {
    using android::hardware::health::V2_0::implementation::Health;

    int ret;
    charger* charger = &charger_state;
    int i;
    int epollfd;

    dump_last_kmsg();

    LOGW("--------------- STARTING CHARGER MODE ---------------\n");

    ret = ev_init(std::bind(&input_callback, charger, std::placeholders::_1, std::placeholders::_2));
    if (!ret) {
        epollfd = ev_get_epollfd();
        healthd_register_event(epollfd, charger_event_handler, EVENT_WAKEUP_FD);
    }

    animation* anim = init_animation();
    charger->batt_anim = anim;

    ret = res_create_display_surface(anim->fail_file.c_str(), &charger->surf_unknown);
    if (ret < 0) {
        LOGE("Cannot load custom battery_fail image. Reverting to built in: %d\n", ret);
        ret = res_create_display_surface("charger/battery_fail", &charger->surf_unknown);
        if (ret < 0) {
            LOGE("Cannot load built in battery_fail image\n");
            charger->surf_unknown = NULL;
        }
    }

    GRSurface** scale_frames;
    int scale_count;
    int scale_fps;  // Not in use (charger/battery_scale doesn't have FPS text
                    // chunk). We are using hard-coded frame.disp_time instead.
    ret = res_create_multi_display_surface(anim->animation_file.c_str(), &scale_count, &scale_fps,
                                           &scale_frames);
    if (ret < 0) {
        LOGE("Cannot load battery_scale image\n");
        anim->num_frames = 0;
        anim->num_cycles = 1;
    } else if (scale_count != anim->num_frames) {
        LOGE("battery_scale image has unexpected frame count (%d, expected %d)\n", scale_count,
             anim->num_frames);
        anim->num_frames = 0;
        anim->num_cycles = 1;
    } else {
        for (i = 0; i < anim->num_frames; i++) {
            anim->frames[i].surface = scale_frames[i];
        }
    }
    ev_sync_key_state(
        std::bind(&set_key_callback, charger, std::placeholders::_1, std::placeholders::_2));

    charger->next_screen_transition = -1;
    charger->next_key_check = -1;
    charger->next_pwr_check = -1;
    charger->wait_batt_level_timestamp = 0;

    // Initialize Health implementation (which initializes the internal BatteryMonitor).
    Health::initInstance(config);

    healthd_config = config;
    charger->boot_min_cap = config->boot_min_cap;
}

static struct healthd_mode_ops charger_ops = {
        .init = healthd_mode_charger_init,
        .preparetowait = healthd_mode_charger_preparetowait,
        .heartbeat = healthd_mode_charger_heartbeat,
        .battery_update = healthd_mode_charger_battery_update,
};

int healthd_charger_main(int argc, char** argv) {
    int ch;

    healthd_mode_ops = &charger_ops;

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

    return healthd_main();
}
