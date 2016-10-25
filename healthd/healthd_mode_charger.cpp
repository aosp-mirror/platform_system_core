/*
 * Copyright (C) 2011-2013 The Android Open Source Project
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
#include <linux/input.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>

#include <sys/socket.h>
#include <linux/netlink.h>

#include <batteryservice/BatteryService.h>
#include <cutils/android_reboot.h>
#include <cutils/klog.h>
#include <cutils/misc.h>
#include <cutils/uevent.h>
#include <cutils/properties.h>

#ifdef CHARGER_ENABLE_SUSPEND
#include <suspend/autosuspend.h>
#endif

#include "animation.h"
#include "AnimationParser.h"
#include "minui/minui.h"

#include <healthd/healthd.h>

using namespace android;

char *locale;

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#define ARRAY_SIZE(x)           (sizeof(x)/sizeof(x[0]))

#define MSEC_PER_SEC            (1000LL)
#define NSEC_PER_MSEC           (1000000LL)

#define BATTERY_UNKNOWN_TIME    (2 * MSEC_PER_SEC)
#define POWER_ON_KEY_TIME       (2 * MSEC_PER_SEC)
#define UNPLUGGED_SHUTDOWN_TIME (10 * MSEC_PER_SEC)

#define LAST_KMSG_PATH          "/proc/last_kmsg"
#define LAST_KMSG_PSTORE_PATH   "/sys/fs/pstore/console-ramoops"
#define LAST_KMSG_MAX_SZ        (32 * 1024)

#define LOGE(x...) do { KLOG_ERROR("charger", x); } while (0)
#define LOGW(x...) do { KLOG_WARNING("charger", x); } while (0)
#define LOGV(x...) do { KLOG_DEBUG("charger", x); } while (0)

static constexpr const char* animation_desc_path = "/res/values/charger/animation.txt";

struct key_state {
    bool pending;
    bool down;
    int64_t timestamp;
};

struct charger {
    bool have_battery_state;
    bool charger_connected;
    int64_t next_screen_transition;
    int64_t next_key_check;
    int64_t next_pwr_check;

    struct key_state keys[KEY_MAX + 1];

    struct animation *batt_anim;
    GRSurface* surf_unknown;
    int boot_min_cap;
};

static const struct animation BASE_ANIMATION = {
    .text_clock = {
        .pos_x = 0,
        .pos_y = 0,

        .color_r = 255,
        .color_g = 255,
        .color_b = 255,
        .color_a = 255,

        .font = nullptr,
    },
    .text_percent = {
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


static struct animation::frame default_animation_frames[] = {
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

static struct animation battery_animation = BASE_ANIMATION;

static struct charger charger_state;
static struct healthd_config *healthd_config;
static struct android::BatteryProperties *batt_prop;
static int char_width;
static int char_height;
static bool minui_inited;

/* current time in milliseconds */
static int64_t curr_time_ms(void)
{
    struct timespec tm;
    clock_gettime(CLOCK_MONOTONIC, &tm);
    return tm.tv_sec * MSEC_PER_SEC + (tm.tv_nsec / NSEC_PER_MSEC);
}

static void clear_screen(void)
{
    gr_color(0, 0, 0, 255);
    gr_clear();
}

#define MAX_KLOG_WRITE_BUF_SZ 256

static void dump_last_kmsg(void)
{
    char *buf;
    char *ptr;
    unsigned sz = 0;
    int len;

    LOGW("\n");
    LOGW("*************** LAST KMSG ***************\n");
    LOGW("\n");
    buf = (char *)load_file(LAST_KMSG_PSTORE_PATH, &sz);

    if (!buf || !sz) {
        buf = (char *)load_file(LAST_KMSG_PATH, &sz);
        if (!buf || !sz) {
            LOGW("last_kmsg not found. Cold reset?\n");
            goto out;
        }
    }

    len = min(sz, LAST_KMSG_MAX_SZ);
    ptr = buf + (sz - len);

    while (len > 0) {
        int cnt = min(len, MAX_KLOG_WRITE_BUF_SZ);
        char yoink;
        char *nl;

        nl = (char *)memrchr(ptr, '\n', cnt - 1);
        if (nl)
            cnt = nl - ptr + 1;

        yoink = ptr[cnt];
        ptr[cnt] = '\0';
        klog_write(6, "<4>%s", ptr);
        ptr[cnt] = yoink;

        len -= cnt;
        ptr += cnt;
    }

    free(buf);

out:
    LOGW("\n");
    LOGW("************* END LAST KMSG *************\n");
    LOGW("\n");
}

#ifdef CHARGER_ENABLE_SUSPEND
static int request_suspend(bool enable)
{
    if (enable)
        return autosuspend_enable();
    else
        return autosuspend_disable();
}
#else
static int request_suspend(bool /*enable*/)
{
    return 0;
}
#endif

static int draw_text(const char *str, int x, int y)
{
    int str_len_px = gr_measure(gr_sys_font(), str);

    if (x < 0)
        x = (gr_fb_width() - str_len_px) / 2;
    if (y < 0)
        y = (gr_fb_height() - char_height) / 2;
    gr_text(gr_sys_font(), x, y, str, 0);

    return y + char_height;
}

static void android_green(void)
{
    gr_color(0xa4, 0xc6, 0x39, 255);
}

// Negative x or y coordinates position the text away from the opposite edge that positive ones do.
void determine_xy(const animation::text_field& field, const int length, int* x, int* y)
{
    *x = field.pos_x;
    *y = field.pos_y;

    int str_len_px = length * field.font->char_width;
    if (field.pos_x == CENTER_VAL) {
        *x = (gr_fb_width() - str_len_px) / 2;
    } else if (field.pos_x >= 0) {
        *x = field.pos_x;
    } else {  // position from max edge
        *x = gr_fb_width() + field.pos_x - str_len_px;
    }

    if (field.pos_y == CENTER_VAL) {
        *y = (gr_fb_height() - field.font->char_height) / 2;
    } else if (field.pos_y >= 0) {
        *y = field.pos_y;
    } else {  // position from max edge
        *y = gr_fb_height() + field.pos_y - field.font->char_height;
    }
}

static void draw_clock(const animation& anim)
{
    static constexpr char CLOCK_FORMAT[] = "%H:%M";
    static constexpr int CLOCK_LENGTH = 6;

    const animation::text_field& field = anim.text_clock;

    if (field.font == nullptr || field.font->char_width == 0 || field.font->char_height == 0) return;

    time_t rawtime;
    time(&rawtime);
    struct tm* time_info = localtime(&rawtime);

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
    gr_text(field.font, x, y, clock_str, false);
}

static void draw_percent(const animation& anim)
{
    int cur_level = anim.cur_level;
    if (anim.cur_status == BATTERY_STATUS_FULL) {
        cur_level = 100;
    }

    if (cur_level <= 0) return;

    const animation::text_field& field = anim.text_percent;
    if (field.font == nullptr || field.font->char_width == 0 || field.font->char_height == 0) {
        return;
    }

    std::string str = base::StringPrintf("%d%%", cur_level);

    int x, y;
    determine_xy(field, str.size(), &x, &y);

    LOGV("drawing percent %s %d %d\n", str.c_str(), x, y);
    gr_color(field.color_r, field.color_g, field.color_b, field.color_a);
    gr_text(field.font, x, y, str.c_str(), false);
}

/* returns the last y-offset of where the surface ends */
static int draw_surface_centered(GRSurface* surface)
{
    int w;
    int h;
    int x;
    int y;

    w = gr_get_width(surface);
    h = gr_get_height(surface);
    x = (gr_fb_width() - w) / 2 ;
    y = (gr_fb_height() - h) / 2 ;

    LOGV("drawing surface %dx%d+%d+%d\n", w, h, x, y);
    gr_blit(surface, 0, 0, w, h, x, y);
    return y + h;
}

static void draw_unknown(struct charger *charger)
{
    int y;
    if (charger->surf_unknown) {
        draw_surface_centered(charger->surf_unknown);
    } else {
        android_green();
        y = draw_text("Charging!", -1, -1);
        draw_text("?\?/100", -1, y + 25);
    }
}

static void draw_battery(const struct charger* charger)
{
    const struct animation& anim = *charger->batt_anim;
    const struct animation::frame& frame = anim.frames[anim.cur_frame];

    if (anim.num_frames != 0) {
        draw_surface_centered(frame.surface);
        LOGV("drawing frame #%d min_cap=%d time=%d\n",
             anim.cur_frame, frame.min_level,
             frame.disp_time);
    }
    draw_clock(anim);
    draw_percent(anim);
}

static void redraw_screen(struct charger *charger)
{
    struct animation *batt_anim = charger->batt_anim;

    clear_screen();

    /* try to display *something* */
    if (batt_anim->cur_level < 0 || batt_anim->num_frames == 0)
        draw_unknown(charger);
    else
        draw_battery(charger);
    gr_flip();
}

static void kick_animation(struct animation *anim)
{
    anim->run = true;
}

static void reset_animation(struct animation *anim)
{
    anim->cur_cycle = 0;
    anim->cur_frame = 0;
    anim->run = false;
}

static void init_status_display(struct animation* anim)
{
    int res;

    if (!anim->text_clock.font_file.empty()) {
        if ((res =
                gr_init_font(anim->text_clock.font_file.c_str(), &anim->text_clock.font)) < 0) {
            LOGE("Could not load time font (%d)\n", res);
        }
    }

    if (!anim->text_percent.font_file.empty()) {
        if ((res =
                gr_init_font(anim->text_percent.font_file.c_str(), &anim->text_percent.font)) < 0) {
            LOGE("Could not load percent font (%d)\n", res);
        }
    }
}

static void update_screen_state(struct charger *charger, int64_t now)
{
    struct animation *batt_anim = charger->batt_anim;
    int disp_time;

    if (!batt_anim->run || now < charger->next_screen_transition) return;

    if (!minui_inited) {
        if (healthd_config && healthd_config->screen_on) {
            if (!healthd_config->screen_on(batt_prop)) {
                LOGV("[%" PRId64 "] leave screen off\n", now);
                batt_anim->run = false;
                charger->next_screen_transition = -1;
                if (charger->charger_connected)
                    request_suspend(true);
                return;
            }
        }

        gr_init();
        gr_font_size(gr_sys_font(), &char_width, &char_height);
        init_status_display(batt_anim);

#ifndef CHARGER_DISABLE_INIT_BLANK
        gr_fb_blank(true);
#endif
        minui_inited = true;
    }

    /* animation is over, blank screen and leave */
    if (batt_anim->num_cycles > 0 && batt_anim->cur_cycle == batt_anim->num_cycles) {
        reset_animation(batt_anim);
        charger->next_screen_transition = -1;
        gr_fb_blank(true);
        LOGV("[%" PRId64 "] animation done\n", now);
        if (charger->charger_connected)
            request_suspend(true);
        return;
    }

    disp_time = batt_anim->frames[batt_anim->cur_frame].disp_time;

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

                // repeat the first frame first_frame_repeats times
                disp_time = batt_anim->frames[batt_anim->cur_frame].disp_time *
                    batt_anim->first_frame_repeats;
            }
        }
    }

    /* unblank the screen  on first cycle */
    if (batt_anim->cur_cycle == 0)
        gr_fb_blank(false);

    /* draw the new frame (@ cur_frame) */
    redraw_screen(charger);

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
    charger->next_screen_transition = now + disp_time;

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

static int set_key_callback(int code, int value, void *data)
{
    struct charger *charger = (struct charger *)data;
    int64_t now = curr_time_ms();
    int down = !!value;

    if (code > KEY_MAX)
        return -1;

    /* ignore events that don't modify our state */
    if (charger->keys[code].down == down)
        return 0;

    /* only record the down even timestamp, as the amount
     * of time the key spent not being pressed is not useful */
    if (down)
        charger->keys[code].timestamp = now;
    charger->keys[code].down = down;
    charger->keys[code].pending = true;
    if (down) {
        LOGV("[%" PRId64 "] key[%d] down\n", now, code);
    } else {
        int64_t duration = now - charger->keys[code].timestamp;
        int64_t secs = duration / 1000;
        int64_t msecs = duration - secs * 1000;
        LOGV("[%" PRId64 "] key[%d] up (was down for %" PRId64 ".%" PRId64 "sec)\n",
             now, code, secs, msecs);
    }

    return 0;
}

static void update_input_state(struct charger *charger,
                               struct input_event *ev)
{
    if (ev->type != EV_KEY)
        return;
    set_key_callback(ev->code, ev->value, charger);
}

static void set_next_key_check(struct charger *charger,
                               struct key_state *key,
                               int64_t timeout)
{
    int64_t then = key->timestamp + timeout;

    if (charger->next_key_check == -1 || then < charger->next_key_check)
        charger->next_key_check = then;
}

static void process_key(struct charger *charger, int code, int64_t now)
{
    struct key_state *key = &charger->keys[code];

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
                        android_reboot(ANDROID_RB_RESTART, 0, 0);
                    } else {
                        LOGV("[%" PRId64 "] ignore power-button press, battery level "
                            "less than minimum\n", now);
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
            }
        }
    }

    key->pending = false;
}

static void handle_input_state(struct charger *charger, int64_t now)
{
    process_key(charger, KEY_POWER, now);

    if (charger->next_key_check != -1 && now > charger->next_key_check)
        charger->next_key_check = -1;
}

static void handle_power_supply_state(struct charger *charger, int64_t now)
{
    if (!charger->have_battery_state)
        return;

    if (!charger->charger_connected) {

        /* Last cycle would have stopped at the extreme top of battery-icon
         * Need to show the correct level corresponding to capacity.
         */
        kick_animation(charger->batt_anim);
        request_suspend(false);
        if (charger->next_pwr_check == -1) {
            charger->next_pwr_check = now + UNPLUGGED_SHUTDOWN_TIME;
            LOGW("[%" PRId64 "] device unplugged: shutting down in %" PRId64 " (@ %" PRId64 ")\n",
                 now, (int64_t)UNPLUGGED_SHUTDOWN_TIME, charger->next_pwr_check);
        } else if (now >= charger->next_pwr_check) {
            LOGW("[%" PRId64 "] shutting down\n", now);
            android_reboot(ANDROID_RB_POWEROFF, 0, 0);
        } else {
            /* otherwise we already have a shutdown timer scheduled */
        }
    } else {
        /* online supply present, reset shutdown timer if set */
        if (charger->next_pwr_check != -1) {
            LOGW("[%" PRId64 "] device plugged in: shutdown cancelled\n", now);
            kick_animation(charger->batt_anim);
        }
        charger->next_pwr_check = -1;
    }
}

void healthd_mode_charger_heartbeat()
{
    struct charger *charger = &charger_state;
    int64_t now = curr_time_ms();

    handle_input_state(charger, now);
    handle_power_supply_state(charger, now);

    /* do screen update last in case any of the above want to start
     * screen transitions (animations, etc)
     */
    update_screen_state(charger, now);
}

void healthd_mode_charger_battery_update(
    struct android::BatteryProperties *props)
{
    struct charger *charger = &charger_state;

    charger->charger_connected =
        props->chargerAcOnline || props->chargerUsbOnline ||
        props->chargerWirelessOnline;

    if (!charger->have_battery_state) {
        charger->have_battery_state = true;
        charger->next_screen_transition = curr_time_ms() - 1;
        reset_animation(charger->batt_anim);
        kick_animation(charger->batt_anim);
    }
    batt_prop = props;
}

int healthd_mode_charger_preparetowait(void)
{
    struct charger *charger = &charger_state;
    int64_t now = curr_time_ms();
    int64_t next_event = INT64_MAX;
    int64_t timeout;

    LOGV("[%" PRId64 "] next screen: %" PRId64 " next key: %" PRId64 " next pwr: %" PRId64 "\n", now,
         charger->next_screen_transition, charger->next_key_check,
         charger->next_pwr_check);

    if (charger->next_screen_transition != -1)
        next_event = charger->next_screen_transition;
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

static int input_callback(int fd, unsigned int epevents, void *data)
{
    struct charger *charger = (struct charger *)data;
    struct input_event ev;
    int ret;

    ret = ev_get_input(fd, epevents, &ev);
    if (ret)
        return -1;
    update_input_state(charger, &ev);
    return 0;
}

static void charger_event_handler(uint32_t /*epevents*/)
{
    int ret;

    ret = ev_wait(-1);
    if (!ret)
        ev_dispatch();
}

animation* init_animation()
{
    bool parse_success;

    std::string content;
    if (base::ReadFileToString(animation_desc_path, &content)) {
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
    LOGV("  animation: %d %d '%s' (%d)\n",
        battery_animation.num_cycles, battery_animation.first_frame_repeats,
        battery_animation.animation_file.c_str(), battery_animation.num_frames);
    LOGV("  fail_file: '%s'\n", battery_animation.fail_file.c_str());
    LOGV("  clock: %d %d %d %d %d %d '%s'\n",
        battery_animation.text_clock.pos_x, battery_animation.text_clock.pos_y,
        battery_animation.text_clock.color_r, battery_animation.text_clock.color_g,
        battery_animation.text_clock.color_b, battery_animation.text_clock.color_a,
        battery_animation.text_clock.font_file.c_str());
    LOGV("  percent: %d %d %d %d %d %d '%s'\n",
        battery_animation.text_percent.pos_x, battery_animation.text_percent.pos_y,
        battery_animation.text_percent.color_r, battery_animation.text_percent.color_g,
        battery_animation.text_percent.color_b, battery_animation.text_percent.color_a,
        battery_animation.text_percent.font_file.c_str());
    for (int i = 0; i < battery_animation.num_frames; i++) {
        LOGV("  frame %.2d: %d %d %d\n", i, battery_animation.frames[i].disp_time,
            battery_animation.frames[i].min_level, battery_animation.frames[i].max_level);
    }

    return &battery_animation;
}

void healthd_mode_charger_init(struct healthd_config* config)
{
    int ret;
    struct charger *charger = &charger_state;
    int i;
    int epollfd;

    dump_last_kmsg();

    LOGW("--------------- STARTING CHARGER MODE ---------------\n");

    ret = ev_init(input_callback, charger);
    if (!ret) {
        epollfd = ev_get_epollfd();
        healthd_register_event(epollfd, charger_event_handler, EVENT_WAKEUP_FD);
    }

    struct animation* anim = init_animation();
    charger->batt_anim = anim;

    ret = res_create_display_surface(anim->fail_file.c_str(), &charger->surf_unknown);
    if (ret < 0) {
        LOGE("Cannot load custom battery_fail image. Reverting to built in.\n");
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
    ret = res_create_multi_display_surface(anim->animation_file.c_str(),
        &scale_count, &scale_fps, &scale_frames);
    if (ret < 0) {
        LOGE("Cannot load battery_scale image\n");
        anim->num_frames = 0;
        anim->num_cycles = 1;
    } else if (scale_count != anim->num_frames) {
        LOGE("battery_scale image has unexpected frame count (%d, expected %d)\n",
             scale_count, anim->num_frames);
        anim->num_frames = 0;
        anim->num_cycles = 1;
    } else {
        for (i = 0; i < anim->num_frames; i++) {
            anim->frames[i].surface = scale_frames[i];
        }
    }
    ev_sync_key_state(set_key_callback, charger);

    charger->next_screen_transition = -1;
    charger->next_key_check = -1;
    charger->next_pwr_check = -1;
    healthd_config = config;
    charger->boot_min_cap = config->boot_min_cap;
}
