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

/** built-in vendor list */
int builtInVendorIds[] = {
    VENDOR_ID_GOOGLE,
    VENDOR_ID_HTC,
    VENDOR_ID_SAMSUNG,
    VENDOR_ID_MOTOROLA,
    VENDOR_ID_LGE,
    VENDOR_ID_HUAWEI,
    VENDOR_ID_ACER,
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
        }
    }
}

/* Utils methods */

/* builds the path to the adb vendor id file. returns 0 if success */
int build_path(char* buff, size_t len, const char* format, const char* home)
{
    if (snprintf(buff, len, format, home, ANDROID_PATH, ANDROID_ADB_INI) >= len) {
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
