/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <errno.h>
#include <string.h>

#include <log/log.h>
#include <log/logger.h>

#define MAX_EVENT_PAYLOAD 512
#define MAX_SUBTAG_LEN 32

static inline void copy4LE(uint8_t *buf, size_t pos, int val)
{
    buf[pos] = val & 0xFF;
    buf[pos+1] = (val >> 8) & 0xFF;
    buf[pos+2] = (val >> 16) & 0xFF;
    buf[pos+3] = (val >> 24) & 0xFF;
}

int __android_log_error_write(int tag, const char *subTag, int32_t uid, const char *data,
                              uint32_t dataLen)
{
    uint8_t buf[MAX_EVENT_PAYLOAD];
    size_t pos = 0;
    uint32_t subTagLen = 0;
    uint32_t roomLeftForData = 0;

    if ((subTag == NULL) || ((data == NULL) && (dataLen != 0))) return -EINVAL;

    subTagLen = strlen(subTag);

    // Truncate subtags that are too long.
    subTagLen = subTagLen > MAX_SUBTAG_LEN ? MAX_SUBTAG_LEN : subTagLen;

    // Truncate dataLen if it is too long.
    roomLeftForData = MAX_EVENT_PAYLOAD -
            (1 + // EVENT_TYPE_LIST
             1 + // Number of elements in list
             1 + // EVENT_TYPE_STRING
             sizeof(subTagLen) +
             subTagLen +
             1 + // EVENT_TYPE_INT
             sizeof(uid) +
             1 + // EVENT_TYPE_STRING
             sizeof(dataLen));
    dataLen = dataLen > roomLeftForData ? roomLeftForData : dataLen;

    buf[pos++] = EVENT_TYPE_LIST;
    buf[pos++] = 3; // Number of elements in the list (subTag, uid, data)

    // Write sub tag.
    buf[pos++] = EVENT_TYPE_STRING;
    copy4LE(buf, pos, subTagLen);
    pos += 4;
    memcpy(&buf[pos], subTag, subTagLen);
    pos += subTagLen;

    // Write UID.
    buf[pos++] = EVENT_TYPE_INT;
    copy4LE(buf, pos, uid);
    pos += 4;

    // Write data.
    buf[pos++] = EVENT_TYPE_STRING;
    copy4LE(buf, pos, dataLen);
    pos += 4;
    if (dataLen != 0)
    {
        memcpy(&buf[pos], data, dataLen);
        pos += dataLen;
    }

    return __android_log_bwrite(tag, buf, pos);
}
