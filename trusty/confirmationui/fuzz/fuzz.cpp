/*
 * Copyright (C) 2020 The Android Open Source Project
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

#undef NDEBUG

#include <assert.h>
#include <log/log.h>
#include <stdlib.h>
#include <trusty/coverage/coverage.h>
#include <trusty/fuzz/counters.h>
#include <trusty/fuzz/utils.h>
#include <unistd.h>

using android::trusty::coverage::CoverageRecord;
using android::trusty::fuzz::ExtraCounters;
using android::trusty::fuzz::TrustyApp;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define CONFIRMATIONUI_PORT "com.android.trusty.confirmationui"

/* ConfirmationUI TA's UUID is 7dee2364-c036-425b-b086-df0f6c233c1b */
static struct uuid confirmationui_uuid = {
    0x7dee2364,
    0xc036,
    0x425b,
    {0xb0, 0x86, 0xdf, 0x0f, 0x6c, 0x23, 0x3c, 0x1b},
};

/* The format of the packets is as following:
 * 16 bits (uint16_t, header) + payload bytes
 * The 16 bits header spicify the number of bytes of payload (header excluded).
 */
struct data_packet {
    uint16_t header;
    uint8_t payload[];
};

static CoverageRecord record(TIPC_DEV, &confirmationui_uuid);

extern "C" int LLVMFuzzerInitialize(int* /* argc */, char*** /* argv */) {
    auto ret = record.Open();
    assert(ret.ok());
    return 0;
}

/* Each corpus contains one or more data packets. */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static uint8_t buf[TIPC_MAX_MSG_SIZE];
    size_t data_idx = 0;

    ExtraCounters counters(&record);
    counters.Reset();

    TrustyApp ta(TIPC_DEV, CONFIRMATIONUI_PORT);
    auto ret = ta.Connect();
    if (!ret.ok()) {
        android::trusty::fuzz::Abort();
    }

    while (data_idx < size) {
        struct data_packet* data_packet_ptr = (struct data_packet*)&data[data_idx];
        size_t payload_size = data_packet_ptr->header;
        data_idx += data_packet_ptr->header + sizeof(data_packet_ptr->header);

        /* Write message to confirmationui server */
        ret = ta.Write(data_packet_ptr->payload, payload_size);
        if (!ret.ok()) {
            return -1;
        }

        /* Read message from confirmationui server */
        ret = ta.Read(&buf, sizeof(buf));
        if (!ret.ok()) {
            return -1;
        }
    }

    return 0;
}
