/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include <functional>

#include "transport.h"

struct usb_ifc_info {
        /* from device descriptor */
    unsigned short dev_vendor;
    unsigned short dev_product;

    unsigned char dev_class;
    unsigned char dev_subclass;
    unsigned char dev_protocol;

    unsigned char ifc_class;
    unsigned char ifc_subclass;
    unsigned char ifc_protocol;

    unsigned char has_bulk_in;
    unsigned char has_bulk_out;

    unsigned char writable;

    char serial_number[256];
    char device_path[256];

    char interface[256];
};

class UsbTransport : public Transport {
    // Resets the underlying transport.  Returns 0 on success.
    // This effectively simulates unplugging and replugging
  public:
    virtual int Reset() = 0;
};

typedef std::function<int(usb_ifc_info*)> ifc_match_func;

// 0 is non blocking
UsbTransport* usb_open(ifc_match_func callback, uint32_t timeout_ms = 0);
