/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "include/stats_event.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "include/stats_event_list.h"

#define STATS_EVENT_TAG 1937006964
#define LOGGER_ENTRY_MAX_PAYLOAD 4068
// Max payload size is 4 bytes less as 4 bytes are reserved for stats_eventTag.
// See android_util_Stats_Log.cpp
#define MAX_EVENT_PAYLOAD (LOGGER_ENTRY_MAX_PAYLOAD - 4)

/* POSITIONS */
#define POS_NUM_ELEMENTS 1
#define POS_TIMESTAMP (POS_NUM_ELEMENTS + sizeof(uint8_t))
#define POS_ATOM_ID (POS_TIMESTAMP + sizeof(uint8_t) + sizeof(uint64_t))
#define POS_FIRST_FIELD (POS_ATOM_ID + sizeof(uint8_t) + sizeof(uint32_t))

/* LIMITS */
#define MAX_ANNOTATION_COUNT 15
#define MAX_BYTE_VALUE 127  // parsing side requires that lengths fit in 7 bits

// The stats_event struct holds the serialized encoding of an event
// within a buf. Also includes other required fields.
struct stats_event {
    uint8_t buf[MAX_EVENT_PAYLOAD];
    size_t lastFieldPos;  // location of last field within the buf
    size_t size;          // number of valid bytes within buffer
    uint32_t numElements;
    uint32_t atomId;
    uint32_t errors;
    uint32_t tag;
    bool built;
};

static int64_t get_elapsed_realtime_ns() {
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

struct stats_event* stats_event_obtain() {
    struct stats_event* event = malloc(sizeof(struct stats_event));

    memset(event->buf, 0, MAX_EVENT_PAYLOAD);
    event->buf[0] = OBJECT_TYPE;
    event->atomId = 0;
    event->errors = 0;
    event->tag = STATS_EVENT_TAG;
    event->built = false;

    // place the timestamp
    uint64_t timestampNs = get_elapsed_realtime_ns();
    event->buf[POS_TIMESTAMP] = INT64_TYPE;
    memcpy(&event->buf[POS_TIMESTAMP + sizeof(uint8_t)], &timestampNs, sizeof(timestampNs));

    event->numElements = 1;
    event->lastFieldPos = 0;  // 0 since we haven't written a field yet
    event->size = POS_FIRST_FIELD;

    return event;
}

void stats_event_release(struct stats_event* event) {
    free(event);
}

void stats_event_set_atom_id(struct stats_event* event, uint32_t atomId) {
    event->atomId = atomId;
    event->buf[POS_ATOM_ID] = INT32_TYPE;
    memcpy(&event->buf[POS_ATOM_ID + sizeof(uint8_t)], &atomId, sizeof(atomId));
    event->numElements++;
}

// Side-effect: modifies event->errors if the buffer would overflow
static bool overflows(struct stats_event* event, size_t size) {
    if (event->size + size > MAX_EVENT_PAYLOAD) {
        event->errors |= ERROR_OVERFLOW;
        return true;
    }
    return false;
}

// Side-effect: all append functions increment event->size if there is
// sufficient space within the buffer to place the value
static void append_byte(struct stats_event* event, uint8_t value) {
    if (!overflows(event, sizeof(value))) {
        event->buf[event->size] = value;
        event->size += sizeof(value);
    }
}

static void append_bool(struct stats_event* event, bool value) {
    append_byte(event, (uint8_t)value);
}

static void append_int32(struct stats_event* event, int32_t value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->size], &value, sizeof(value));
        event->size += sizeof(value);
    }
}

static void append_int64(struct stats_event* event, int64_t value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->size], &value, sizeof(value));
        event->size += sizeof(value);
    }
}

static void append_float(struct stats_event* event, float value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->size], &value, sizeof(value));
        event->size += sizeof(float);
    }
}

static void append_byte_array(struct stats_event* event, uint8_t* buf, size_t size) {
    if (!overflows(event, size)) {
        memcpy(&event->buf[event->size], buf, size);
        event->size += size;
    }
}

// Side-effect: modifies event->errors if buf is not properly null-terminated
static void append_string(struct stats_event* event, const char* buf) {
    size_t size = strnlen(buf, MAX_EVENT_PAYLOAD);
    if (event->errors) {
        event->errors |= ERROR_STRING_NOT_NULL_TERMINATED;
        return;
    }

    append_int32(event, size);
    append_byte_array(event, (uint8_t*)buf, size);
}

static void start_field(struct stats_event* event, uint8_t typeId) {
    event->lastFieldPos = event->size;
    append_byte(event, typeId);
    event->numElements++;
}

void stats_event_write_int32(struct stats_event* event, int32_t value) {
    if (event->errors) return;

    start_field(event, INT32_TYPE);
    append_int32(event, value);
}

void stats_event_write_int64(struct stats_event* event, int64_t value) {
    if (event->errors) return;

    start_field(event, INT64_TYPE);
    append_int64(event, value);
}

void stats_event_write_float(struct stats_event* event, float value) {
    if (event->errors) return;

    start_field(event, FLOAT_TYPE);
    append_float(event, value);
}

void stats_event_write_bool(struct stats_event* event, bool value) {
    if (event->errors) return;

    start_field(event, BOOL_TYPE);
    append_bool(event, value);
}

void stats_event_write_byte_array(struct stats_event* event, uint8_t* buf, size_t numBytes) {
    if (event->errors) return;

    start_field(event, BYTE_ARRAY_TYPE);
    append_int32(event, numBytes);
    append_byte_array(event, buf, numBytes);
}

// Buf is assumed to be encoded using UTF8
void stats_event_write_string8(struct stats_event* event, const char* buf) {
    if (event->errors) return;

    start_field(event, STRING_TYPE);
    append_string(event, buf);
}

// Tags are assumed to be encoded using UTF8
void stats_event_write_attribution_chain(struct stats_event* event, uint32_t* uids,
                                         const char** tags, uint8_t numNodes) {
    if (numNodes > MAX_BYTE_VALUE) event->errors |= ERROR_ATTRIBUTION_CHAIN_TOO_LONG;
    if (event->errors) return;

    start_field(event, ATTRIBUTION_CHAIN_TYPE);
    append_byte(event, numNodes);

    for (uint8_t i = 0; i < numNodes; i++) {
        append_int32(event, uids[i]);
        append_string(event, tags[i]);
    }
}

void stats_event_write_key_value_pairs(struct stats_event* event, struct key_value_pair* pairs,
                                       uint8_t numPairs) {
    if (numPairs > MAX_BYTE_VALUE) event->errors |= ERROR_TOO_MANY_KEY_VALUE_PAIRS;
    if (event->errors) return;

    start_field(event, KEY_VALUE_PAIRS_TYPE);
    append_byte(event, numPairs);

    for (uint8_t i = 0; i < numPairs; i++) {
        append_int32(event, pairs[i].key);
        append_byte(event, pairs[i].valueType);
        switch (pairs[i].valueType) {
            case INT32_TYPE:
                append_int32(event, pairs[i].int32Value);
                break;
            case INT64_TYPE:
                append_int64(event, pairs[i].int64Value);
                break;
            case FLOAT_TYPE:
                append_float(event, pairs[i].floatValue);
                break;
            case STRING_TYPE:
                append_string(event, pairs[i].stringValue);
                break;
            default:
                event->errors |= ERROR_INVALID_VALUE_TYPE;
                return;
        }
    }
}

// Side-effect: modifies event->errors if field has too many annotations
static void increment_annotation_count(struct stats_event* event) {
    uint8_t fieldType = event->buf[event->lastFieldPos] & 0x0F;
    uint32_t oldAnnotationCount = (event->buf[event->lastFieldPos] & 0xF0) >> 4;
    uint32_t newAnnotationCount = oldAnnotationCount + 1;

    if (newAnnotationCount > MAX_ANNOTATION_COUNT) {
        event->errors |= ERROR_TOO_MANY_ANNOTATIONS;
        return;
    }

    event->buf[event->lastFieldPos] = (((uint8_t)newAnnotationCount << 4) & 0xF0) | fieldType;
}

void stats_event_add_bool_annotation(struct stats_event* event, uint8_t annotationId, bool value) {
    if (event->lastFieldPos == 0) event->errors |= ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD;
    if (annotationId > MAX_BYTE_VALUE) event->errors |= ERROR_ANNOTATION_ID_TOO_LARGE;
    if (event->errors) return;

    append_byte(event, annotationId);
    append_byte(event, BOOL_TYPE);
    append_bool(event, value);
    increment_annotation_count(event);
}

void stats_event_add_int32_annotation(struct stats_event* event, uint8_t annotationId,
                                      int32_t value) {
    if (event->lastFieldPos == 0) event->errors |= ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD;
    if (annotationId > MAX_BYTE_VALUE) event->errors |= ERROR_ANNOTATION_ID_TOO_LARGE;
    if (event->errors) return;

    append_byte(event, annotationId);
    append_byte(event, INT32_TYPE);
    append_int32(event, value);
    increment_annotation_count(event);
}

uint32_t stats_event_get_atom_id(struct stats_event* event) {
    return event->atomId;
}

uint8_t* stats_event_get_buffer(struct stats_event* event, size_t* size) {
    if (size) *size = event->size;
    return event->buf;
}

uint32_t stats_event_get_errors(struct stats_event* event) {
    return event->errors;
}

void stats_event_build(struct stats_event* event) {
    if (event->built) return;

    if (event->atomId == 0) event->errors |= ERROR_NO_ATOM_ID;

    if (event->numElements > MAX_BYTE_VALUE) {
        event->errors |= ERROR_TOO_MANY_FIELDS;
    } else {
        event->buf[POS_NUM_ELEMENTS] = event->numElements;
    }

    // If there are errors, rewrite buffer.
    if (event->errors) {
        event->buf[POS_NUM_ELEMENTS] = 3;
        event->buf[POS_FIRST_FIELD] = ERROR_TYPE;
        memcpy(&event->buf[POS_FIRST_FIELD + sizeof(uint8_t)], &event->errors,
               sizeof(event->errors));
        event->size = POS_FIRST_FIELD + sizeof(uint8_t) + sizeof(uint32_t);
    }

    event->built = true;
}

void stats_event_write(struct stats_event* event) {
    stats_event_build(event);

    // Prepare iovecs for write to statsd.
    struct iovec vecs[2];
    vecs[0].iov_base = &event->tag;
    vecs[0].iov_len = sizeof(event->tag);
    vecs[1].iov_base = &event->buf;
    vecs[1].iov_len = event->size;
    write_to_statsd(vecs, 2);
}
