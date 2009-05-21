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

#include "sysdeps.h"
#include <stdio.h>
#include "adb.h"

int* vendorIds = NULL;
unsigned vendorIdCount = 0;

void usb_vendors_init(void) {
    /* for now, only put the built-in VENDOR_ID_* */
    vendorIdCount = 2;
    vendorIds = (int*)malloc(vendorIdCount * sizeof(int));
    vendorIds[0] = VENDOR_ID_GOOGLE;
    vendorIds[1] = VENDOR_ID_HTC;
}

void usb_vendors_cleanup(void) {
    if (vendorIds != NULL) {
        free(vendorIds);
        vendorIds = NULL;
        vendorIdCount = 0;
    }
}
