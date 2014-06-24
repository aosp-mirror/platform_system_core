/*
 * Copyright (C) 2009 The Android Open Source Project
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

#include "usb_vendors.h"

#include <stdio.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include "windows.h"
#  include "shlobj.h"
#else
#  include <unistd.h>
#  include <sys/stat.h>
#endif

#include "sysdeps.h"
#include "adb.h"

#define ANDROID_PATH            ".android"
#define ANDROID_ADB_INI         "adb_usb.ini"

#define TRACE_TAG               TRACE_USB

/* Keep the list below sorted alphabetically by #define name */
// Acer's USB Vendor ID
#define VENDOR_ID_ACER          0x0502
// Allwinner's USB Vendor ID
#define VENDOR_ID_ALLWINNER     0x1F3A
// Amlogic's USB Vendor ID
#define VENDOR_ID_AMLOGIC       0x1b8e
// AnyDATA's USB Vendor ID
#define VENDOR_ID_ANYDATA       0x16D5
// Archos's USB Vendor ID
#define VENDOR_ID_ARCHOS        0x0E79
// Asus's USB Vendor ID
#define VENDOR_ID_ASUS          0x0b05
// BYD's USB Vendor ID
#define VENDOR_ID_BYD           0x1D91
// Compal's USB Vendor ID
#define VENDOR_ID_COMPAL        0x04B7
// Compalcomm's USB Vendor ID
#define VENDOR_ID_COMPALCOMM    0x1219
// Dell's USB Vendor ID
#define VENDOR_ID_DELL          0x413c
// ECS's USB Vendor ID
#define VENDOR_ID_ECS           0x03fc
// EMERGING_TECH's USB Vendor ID
#define VENDOR_ID_EMERGING_TECH 0x297F
// Emerson's USB Vendor ID
#define VENDOR_ID_EMERSON       0x2207
// Foxconn's USB Vendor ID
#define VENDOR_ID_FOXCONN       0x0489
// Fujitsu's USB Vendor ID
#define VENDOR_ID_FUJITSU       0x04C5
// Funai's USB Vendor ID
#define VENDOR_ID_FUNAI         0x0F1C
// Garmin-Asus's USB Vendor ID
#define VENDOR_ID_GARMIN_ASUS   0x091E
// Gigabyte's USB Vendor ID
#define VENDOR_ID_GIGABYTE      0x0414
// Gigaset's USB Vendor ID
#define VENDOR_ID_GIGASET       0x1E85
// GIONEE's USB Vendor ID
#define VENDOR_ID_GIONEE        0x271D
// Google's USB Vendor ID
#define VENDOR_ID_GOOGLE        0x18d1
// Haier's USB Vendor ID
#define VENDOR_ID_HAIER         0x201E
// Harris's USB Vendor ID
#define VENDOR_ID_HARRIS        0x19A5
// Hisense's USB Vendor ID
#define VENDOR_ID_HISENSE       0x109b
// Honeywell's USB Vendor ID
#define VENDOR_ID_HONEYWELL     0x0c2e
// HP's USB Vendor ID
#define VENDOR_ID_HP            0x03f0
// HTC's USB Vendor ID
#define VENDOR_ID_HTC           0x0bb4
// Huawei's USB Vendor ID
#define VENDOR_ID_HUAWEI        0x12D1
// INQ Mobile's USB Vendor ID
#define VENDOR_ID_INQ_MOBILE    0x2314
// Intel's USB Vendor ID
#define VENDOR_ID_INTEL         0x8087
// Intermec's USB Vendor ID
#define VENDOR_ID_INTERMEC      0x067e
// IRiver's USB Vendor ID
#define VENDOR_ID_IRIVER        0x2420
// K-Touch's USB Vendor ID
#define VENDOR_ID_K_TOUCH       0x24E3
// KT Tech's USB Vendor ID
#define VENDOR_ID_KT_TECH       0x2116
// Kobo's USB Vendor ID
#define VENDOR_ID_KOBO          0x2237
// Kyocera's USB Vendor ID
#define VENDOR_ID_KYOCERA       0x0482
// Lab126's USB Vendor ID
#define VENDOR_ID_LAB126        0x1949
// Lenovo's USB Vendor ID
#define VENDOR_ID_LENOVO        0x17EF
// LenovoMobile's USB Vendor ID
#define VENDOR_ID_LENOVOMOBILE  0x2006
// LG's USB Vendor ID
#define VENDOR_ID_LGE           0x1004
// Lumigon's USB Vendor ID
#define VENDOR_ID_LUMIGON       0x25E3
// Motorola's USB Vendor ID
#define VENDOR_ID_MOTOROLA      0x22b8
// MSI's USB Vendor ID
#define VENDOR_ID_MSI           0x0DB0
// MTK's USB Vendor ID
#define VENDOR_ID_MTK           0x0e8d
// NEC's USB Vendor ID
#define VENDOR_ID_NEC           0x0409
// B&N Nook's USB Vendor ID
#define VENDOR_ID_NOOK          0x2080
// Nvidia's USB Vendor ID
#define VENDOR_ID_NVIDIA        0x0955
// OPPO's USB Vendor ID
#define VENDOR_ID_OPPO          0x22D9
// On-The-Go-Video's USB Vendor ID
#define VENDOR_ID_OTGV          0x2257
// OUYA's USB Vendor ID
#define VENDOR_ID_OUYA          0x2836
// Pantech's USB Vendor ID
#define VENDOR_ID_PANTECH       0x10A9
// Pegatron's USB Vendor ID
#define VENDOR_ID_PEGATRON      0x1D4D
// Philips's USB Vendor ID
#define VENDOR_ID_PHILIPS       0x0471
// Panasonic Mobile Communication's USB Vendor ID
#define VENDOR_ID_PMC           0x04DA
// Positivo's USB Vendor ID
#define VENDOR_ID_POSITIVO      0x1662
// Prestigio's USB Vendor ID
#define VENDOR_ID_PRESTIGIO     0x29e4
// Qisda's USB Vendor ID
#define VENDOR_ID_QISDA         0x1D45
// Qualcomm's USB Vendor ID
#define VENDOR_ID_QUALCOMM      0x05c6
// Quanta's USB Vendor ID
#define VENDOR_ID_QUANTA        0x0408
// Rockchip's USB Vendor ID
#define VENDOR_ID_ROCKCHIP      0x2207
// Samsung's USB Vendor ID
#define VENDOR_ID_SAMSUNG       0x04e8
// Sharp's USB Vendor ID
#define VENDOR_ID_SHARP         0x04dd
// SK Telesys's USB Vendor ID
#define VENDOR_ID_SK_TELESYS    0x1F53
// Smartisan's USB Vendor ID
#define VENDOR_ID_SMARTISAN     0x29a9
// Sony's USB Vendor ID
#define VENDOR_ID_SONY          0x054C
// Sony Ericsson's USB Vendor ID
#define VENDOR_ID_SONY_ERICSSON 0x0FCE
// T & A Mobile Phones' USB Vendor ID
#define VENDOR_ID_T_AND_A       0x1BBB
// TechFaith's USB Vendor ID
#define VENDOR_ID_TECHFAITH     0x1d09
// Teleepoch's USB Vendor ID
#define VENDOR_ID_TELEEPOCH     0x2340
// Texas Instruments's USB Vendor ID
#define VENDOR_ID_TI            0x0451
// Toshiba's USB Vendor ID
#define VENDOR_ID_TOSHIBA       0x0930
// Unowhy's USB Vendor ID
#define VENDOR_ID_UNOWHY        0x2A49
// Vizio's USB Vendor ID
#define VENDOR_ID_VIZIO         0xE040
// Wacom's USB Vendor ID
#define VENDOR_ID_WACOM         0x0531
// Xiaomi's USB Vendor ID
#define VENDOR_ID_XIAOMI        0x2717
// YotaDevices's USB Vendor ID
#define VENDOR_ID_YOTADEVICES   0x2916
// Yulong Coolpad's USB Vendor ID
#define VENDOR_ID_YULONG_COOLPAD 0x1EBF
// ZTE's USB Vendor ID
#define VENDOR_ID_ZTE           0x19D2
/* Keep the list above sorted alphabetically by #define name */

/** built-in vendor list */
/* Keep the list below sorted alphabetically */
int builtInVendorIds[] = {
    VENDOR_ID_ACER,
    VENDOR_ID_ALLWINNER,
    VENDOR_ID_AMLOGIC,
    VENDOR_ID_ANYDATA,
    VENDOR_ID_ARCHOS,
    VENDOR_ID_ASUS,
    VENDOR_ID_BYD,
    VENDOR_ID_COMPAL,
    VENDOR_ID_COMPALCOMM,
    VENDOR_ID_DELL,
    VENDOR_ID_ECS,
    VENDOR_ID_EMERGING_TECH,
    VENDOR_ID_EMERSON,
    VENDOR_ID_FOXCONN,
    VENDOR_ID_FUJITSU,
    VENDOR_ID_FUNAI,
    VENDOR_ID_GARMIN_ASUS,
    VENDOR_ID_GIGABYTE,
    VENDOR_ID_GIGASET,
    VENDOR_ID_GIONEE,
    VENDOR_ID_GOOGLE,
    VENDOR_ID_HAIER,
    VENDOR_ID_HARRIS,
    VENDOR_ID_HISENSE,
    VENDOR_ID_HONEYWELL,
    VENDOR_ID_HP,
    VENDOR_ID_HTC,
    VENDOR_ID_HUAWEI,
    VENDOR_ID_INQ_MOBILE,
    VENDOR_ID_INTEL,
    VENDOR_ID_INTERMEC,
    VENDOR_ID_IRIVER,
    VENDOR_ID_KOBO,
    VENDOR_ID_K_TOUCH,
    VENDOR_ID_KT_TECH,
    VENDOR_ID_KYOCERA,
    VENDOR_ID_LAB126,
    VENDOR_ID_LENOVO,
    VENDOR_ID_LENOVOMOBILE,
    VENDOR_ID_LGE,
    VENDOR_ID_LUMIGON,
    VENDOR_ID_MOTOROLA,
    VENDOR_ID_MSI,
    VENDOR_ID_MTK,
    VENDOR_ID_NEC,
    VENDOR_ID_NOOK,
    VENDOR_ID_NVIDIA,
    VENDOR_ID_OPPO,
    VENDOR_ID_OTGV,
    VENDOR_ID_OUYA,
    VENDOR_ID_PANTECH,
    VENDOR_ID_PEGATRON,
    VENDOR_ID_PHILIPS,
    VENDOR_ID_PMC,
    VENDOR_ID_POSITIVO,
    VENDOR_ID_PRESTIGIO,
    VENDOR_ID_QISDA,
    VENDOR_ID_QUALCOMM,
    VENDOR_ID_QUANTA,
    VENDOR_ID_ROCKCHIP,
    VENDOR_ID_SAMSUNG,
    VENDOR_ID_SHARP,
    VENDOR_ID_SK_TELESYS,
    VENDOR_ID_SMARTISAN,
    VENDOR_ID_SONY,
    VENDOR_ID_SONY_ERICSSON,
    VENDOR_ID_T_AND_A,
    VENDOR_ID_TECHFAITH,
    VENDOR_ID_TELEEPOCH,
    VENDOR_ID_TI,
    VENDOR_ID_TOSHIBA,
    VENDOR_ID_UNOWHY,
    VENDOR_ID_VIZIO,
    VENDOR_ID_WACOM,
    VENDOR_ID_XIAOMI,
    VENDOR_ID_YOTADEVICES,
    VENDOR_ID_YULONG_COOLPAD,
    VENDOR_ID_ZTE,
};
/* Keep the list above sorted alphabetically */

#define BUILT_IN_VENDOR_COUNT    (sizeof(builtInVendorIds)/sizeof(builtInVendorIds[0]))

/* max number of supported vendor ids (built-in + 3rd party). increase as needed */
#define VENDOR_COUNT_MAX         128

int vendorIds[VENDOR_COUNT_MAX];
unsigned vendorIdCount = 0;

int get_adb_usb_ini(char* buff, size_t len);

void usb_vendors_init(void)
{
    if (VENDOR_COUNT_MAX < BUILT_IN_VENDOR_COUNT) {
        fprintf(stderr, "VENDOR_COUNT_MAX not big enough for built-in vendor list.\n");
        exit(2);
    }

    /* add the built-in vendors at the beginning of the array */
    memcpy(vendorIds, builtInVendorIds, sizeof(builtInVendorIds));

    /* default array size is the number of built-in vendors */
    vendorIdCount = BUILT_IN_VENDOR_COUNT;

    if (VENDOR_COUNT_MAX == BUILT_IN_VENDOR_COUNT)
        return;

    char temp[PATH_MAX];
    if (get_adb_usb_ini(temp, sizeof(temp)) == 0) {
        FILE * f = fopen(temp, "rt");

        if (f != NULL) {
            /* The vendor id file is pretty basic. 1 vendor id per line.
               Lines starting with # are comments */
            while (fgets(temp, sizeof(temp), f) != NULL) {
                if (temp[0] == '#')
                    continue;

                long value = strtol(temp, NULL, 0);
                if (errno == EINVAL || errno == ERANGE || value > INT_MAX || value < 0) {
                    fprintf(stderr, "Invalid content in %s. Quitting.\n", ANDROID_ADB_INI);
                    exit(2);
                }

                vendorIds[vendorIdCount++] = (int)value;

                /* make sure we don't go beyond the array */
                if (vendorIdCount == VENDOR_COUNT_MAX) {
                    break;
                }
            }
            fclose(f);
        }
    }
}

/* Utils methods */

/* builds the path to the adb vendor id file. returns 0 if success */
int build_path(char* buff, size_t len, const char* format, const char* home)
{
    if (snprintf(buff, len, format, home, ANDROID_PATH, ANDROID_ADB_INI) >= (signed)len) {
        return 1;
    }

    return 0;
}

/* fills buff with the path to the adb vendor id file. returns 0 if success */
int get_adb_usb_ini(char* buff, size_t len)
{
#ifdef _WIN32
    const char* home = getenv("ANDROID_SDK_HOME");
    if (home != NULL) {
        return build_path(buff, len, "%s\\%s\\%s", home);
    } else {
        char path[MAX_PATH];
        SHGetFolderPath( NULL, CSIDL_PROFILE, NULL, 0, path);
        return build_path(buff, len, "%s\\%s\\%s", path);
    }
#else
    const char* home = getenv("HOME");
    if (home == NULL)
        home = "/tmp";

    return build_path(buff, len, "%s/%s/%s", home);
#endif
}
