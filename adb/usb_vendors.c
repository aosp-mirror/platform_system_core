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

// Google's USB Vendor ID
#define VENDOR_ID_GOOGLE        0x18d1
// Intel's USB Vendor ID
#define VENDOR_ID_INTEL         0x8087
// HTC's USB Vendor ID
#define VENDOR_ID_HTC           0x0bb4
// Samsung's USB Vendor ID
#define VENDOR_ID_SAMSUNG       0x04e8
// Motorola's USB Vendor ID
#define VENDOR_ID_MOTOROLA      0x22b8
// LG's USB Vendor ID
#define VENDOR_ID_LGE           0x1004
// Huawei's USB Vendor ID
#define VENDOR_ID_HUAWEI        0x12D1
// Acer's USB Vendor ID
#define VENDOR_ID_ACER          0x0502
// Sony Ericsson's USB Vendor ID
#define VENDOR_ID_SONY_ERICSSON 0x0FCE
// Foxconn's USB Vendor ID
#define VENDOR_ID_FOXCONN       0x0489
// Dell's USB Vendor ID
#define VENDOR_ID_DELL          0x413c
// Nvidia's USB Vendor ID
#define VENDOR_ID_NVIDIA        0x0955
// Garmin-Asus's USB Vendor ID
#define VENDOR_ID_GARMIN_ASUS   0x091E
// Sharp's USB Vendor ID
#define VENDOR_ID_SHARP         0x04dd
// ZTE's USB Vendor ID
#define VENDOR_ID_ZTE           0x19D2
// Kyocera's USB Vendor ID
#define VENDOR_ID_KYOCERA       0x0482
// Pantech's USB Vendor ID
#define VENDOR_ID_PANTECH       0x10A9
// Qualcomm's USB Vendor ID
#define VENDOR_ID_QUALCOMM      0x05c6
// On-The-Go-Video's USB Vendor ID
#define VENDOR_ID_OTGV          0x2257
// NEC's USB Vendor ID
#define VENDOR_ID_NEC           0x0409
// Panasonic Mobile Communication's USB Vendor ID
#define VENDOR_ID_PMC           0x04DA
// Toshiba's USB Vendor ID
#define VENDOR_ID_TOSHIBA       0x0930
// SK Telesys's USB Vendor ID
#define VENDOR_ID_SK_TELESYS    0x1F53
// KT Tech's USB Vendor ID
#define VENDOR_ID_KT_TECH       0x2116
// Asus's USB Vendor ID
#define VENDOR_ID_ASUS          0x0b05
// Philips's USB Vendor ID
#define VENDOR_ID_PHILIPS       0x0471
// Texas Instruments's USB Vendor ID
#define VENDOR_ID_TI            0x0451
// Funai's USB Vendor ID
#define VENDOR_ID_FUNAI         0x0F1C
// Gigabyte's USB Vendor ID
#define VENDOR_ID_GIGABYTE      0x0414
// IRiver's USB Vendor ID
#define VENDOR_ID_IRIVER        0x2420
// Compal's USB Vendor ID
#define VENDOR_ID_COMPAL        0x1219
// T & A Mobile Phones' USB Vendor ID
#define VENDOR_ID_T_AND_A       0x1BBB
// LenovoMobile's USB Vendor ID
#define VENDOR_ID_LENOVOMOBILE  0x2006
// Lenovo's USB Vendor ID
#define VENDOR_ID_LENOVO        0x17EF
// Vizio's USB Vendor ID
#define VENDOR_ID_VIZIO         0xE040
// K-Touch's USB Vendor ID
#define VENDOR_ID_K_TOUCH       0x24E3
// Pegatron's USB Vendor ID
#define VENDOR_ID_PEGATRON      0x1D4D
// Archos's USB Vendor ID
#define VENDOR_ID_ARCHOS        0x0E79
// Positivo's USB Vendor ID
#define VENDOR_ID_POSITIVO      0x1662
// Fujitsu's USB Vendor ID
#define VENDOR_ID_FUJITSU       0x04C5
// Lumigon's USB Vendor ID
#define VENDOR_ID_LUMIGON       0x25E3
// Quanta's USB Vendor ID
#define VENDOR_ID_QUANTA        0x0408
// INQ Mobile's USB Vendor ID
#define VENDOR_ID_INQ_MOBILE    0x2314
// Sony's USB Vendor ID
#define VENDOR_ID_SONY          0x054C
// Lab126's USB Vendor ID
#define VENDOR_ID_LAB126        0x1949
// Yulong Coolpad's USB Vendor ID
#define VENDOR_ID_YULONG_COOLPAD 0x1EBF
// Kobo's USB Vendor ID
#define VENDOR_ID_KOBO          0x2237
// Teleepoch's USB Vendor ID
#define VENDOR_ID_TELEEPOCH     0x2340
// AnyDATA's USB Vendor ID
#define VENDOR_ID_ANYDATA       0x16D5
// Harris's USB Vendor ID
#define VENDOR_ID_HARRIS        0x19A5
// OPPO's USB Vendor ID
#define VENDOR_ID_OPPO          0x22D9
// Xiaomi's USB Vendor ID
#define VENDOR_ID_XIAOMI        0x2717
// BYD's USB Vendor ID
#define VENDOR_ID_BYD           0x19D1
// OUYA's USB Vendor ID
#define VENDOR_ID_OUYA          0x2836
// Haier's USB Vendor ID
#define VENDOR_ID_HAIER         0x201E
// Hisense's USB Vendor ID
#define VENDOR_ID_HISENSE       0x109b
// MTK's USB Vendor ID
#define VENDOR_ID_MTK           0x0e8d
// B&N Nook's USB Vendor ID
#define VENDOR_ID_NOOK          0x2080
// Qisda's USB Vendor ID
#define VENDOR_ID_QISDA         0x1D45
// ECS's USB Vendor ID
#define VENDOR_ID_ECS           0x03fc


/** built-in vendor list */
int builtInVendorIds[] = {
    VENDOR_ID_GOOGLE,
    VENDOR_ID_INTEL,
    VENDOR_ID_HTC,
    VENDOR_ID_SAMSUNG,
    VENDOR_ID_MOTOROLA,
    VENDOR_ID_LGE,
    VENDOR_ID_HUAWEI,
    VENDOR_ID_ACER,
    VENDOR_ID_SONY_ERICSSON,
    VENDOR_ID_FOXCONN,
    VENDOR_ID_DELL,
    VENDOR_ID_NVIDIA,
    VENDOR_ID_GARMIN_ASUS,
    VENDOR_ID_SHARP,
    VENDOR_ID_ZTE,
    VENDOR_ID_KYOCERA,
    VENDOR_ID_PANTECH,
    VENDOR_ID_QUALCOMM,
    VENDOR_ID_OTGV,
    VENDOR_ID_NEC,
    VENDOR_ID_PMC,
    VENDOR_ID_TOSHIBA,
    VENDOR_ID_SK_TELESYS,
    VENDOR_ID_KT_TECH,
    VENDOR_ID_ASUS,
    VENDOR_ID_PHILIPS,
    VENDOR_ID_TI,
    VENDOR_ID_FUNAI,
    VENDOR_ID_GIGABYTE,
    VENDOR_ID_IRIVER,
    VENDOR_ID_COMPAL,
    VENDOR_ID_T_AND_A,
    VENDOR_ID_LENOVOMOBILE,
    VENDOR_ID_LENOVO,
    VENDOR_ID_VIZIO,
    VENDOR_ID_K_TOUCH,
    VENDOR_ID_PEGATRON,
    VENDOR_ID_ARCHOS,
    VENDOR_ID_POSITIVO,
    VENDOR_ID_FUJITSU,
    VENDOR_ID_LUMIGON,
    VENDOR_ID_QUANTA,
    VENDOR_ID_INQ_MOBILE,
    VENDOR_ID_SONY,
    VENDOR_ID_LAB126,
    VENDOR_ID_YULONG_COOLPAD,
    VENDOR_ID_KOBO,
    VENDOR_ID_TELEEPOCH,
    VENDOR_ID_ANYDATA,
    VENDOR_ID_HARRIS,
    VENDOR_ID_OPPO,
    VENDOR_ID_XIAOMI,
    VENDOR_ID_BYD,
    VENDOR_ID_OUYA,
    VENDOR_ID_HAIER,
    VENDOR_ID_HISENSE,
    VENDOR_ID_MTK,
    VENDOR_ID_NOOK,
    VENDOR_ID_QISDA,
    VENDOR_ID_ECS,
};

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
