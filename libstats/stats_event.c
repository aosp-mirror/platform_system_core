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

#define byte unsigned char

#define STATS_EVENT_TAG 1937006964
#define LOGGER_ENTRY_MAX_PAYLOAD 4068
// Max payload size is 4 bytes less as 4 bytes are reserved for stats_eventTag.
// See android_util_Stats_Log.cpp
#define MAX_EVENT_PAYLOAD (LOGGER_ENTRY_MAX_PAYLOAD - 4)

/* POSITIONS */
#define POS_NUM_ELEMENTS 1
#define POS_TIMESTAMP (POS_NUM_ELEMENTS + 1)
#define POS_ATOM_ID (POS_TIMESTAMP + sizeof(byte) + sizeof(uint64_t))
#define POS_FIRST_FIELD (POS_ATOM_ID + sizeof(byte) + sizeof(uint32_t))

/* LIMITS */
#define MAX_ANNOTATION_COUNT 15
#define MAX_BYTE_VALUE 127  // parsing side requires that lengths fit in 7 bits

// The stats_event struct holds the serialized encoding of an event
// within a buf. Also includes other required fields.
struct stats_event {
    byte buf[MAX_EVENT_PAYLOAD];
    size_t bufPos;        // current write position within the buf
    size_t lastFieldPos;  // location of last field within the buf
    byte lastFieldType;   // type of last field
    size_t size;          // number of valid bytes within buffer
    uint32_t numElements;
    uint32_t atomId;
    uint64_t timestampNs;
    uint32_t errors;
    uint32_t tag;
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

    event->bufPos = POS_FIRST_FIELD;
    event->lastFieldPos = 0;
    event->lastFieldType = OBJECT_TYPE;
    event->size = 0;
    event->numElements = 0;
    event->atomId = 0;
    event->timestampNs = get_elapsed_realtime_ns();
    event->errors = 0;
    event->tag = STATS_EVENT_TAG;
    return event;
}

void stats_event_release(struct stats_event* event) {
    free(event);  // free is a no-op if event is NULL
}

// Should only be used for testing
void stats_event_set_timestamp_ns(struct stats_event* event, uint64_t timestampNs) {
    if (event) event->timestampNs = timestampNs;
}

void stats_event_set_atom_id(struct stats_event* event, uint32_t atomId) {
    if (event) event->atomId = atomId;
}

// Side-effect: modifies event->errors if the buffer would overflow
static bool overflows(struct stats_event* event, size_t size) {
    if (event->bufPos + size > MAX_EVENT_PAYLOAD) {
        event->errors |= ERROR_OVERFLOW;
        return true;
    }
    return false;
}

static size_t put_byte(struct stats_event* event, byte value) {
    if (!overflows(event, sizeof(value))) {
        event->buf[event->bufPos] = value;
        return sizeof(byte);
    }
    return 0;
}

static size_t put_bool(struct stats_event* event, bool value) {
    return put_byte(event, (byte)value);
}

static size_t put_int32(struct stats_event* event, int32_t value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->bufPos], &value, sizeof(int32_t));
        return sizeof(int32_t);
    }
    return 0;
}

static size_t put_int64(struct stats_event* event, int64_t value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->bufPos], &value, sizeof(int64_t));
        return sizeof(int64_t);
    }
    return 0;
}

static size_t put_float(struct stats_event* event, float value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->bufPos], &value, sizeof(float));
        return sizeof(float);
    }
    return 0;
}

static size_t put_byte_array(struct stats_event* event, void* buf, size_t size) {
    if (!overflows(event, size)) {
        memcpy(&event->buf[event->bufPos], buf, size);
        return size;
    }
    return 0;
}

static void start_field(struct stats_event* event, byte typeId) {
    event->lastFieldPos = event->bufPos;
    event->lastFieldType = typeId;
    event->bufPos += put_byte(event, typeId);
    event->numElements++;
}

void stats_event_write_int32(struct stats_event* event, int32_t value) {
    if (!event || event->errors) return;

    start_field(event, INT32_TYPE);
    event->bufPos += put_int32(event, value);
}

void stats_event_write_int64(struct stats_event* event, int64_t value) {
    if (!event || event->errors) return;

    start_field(event, INT64_TYPE);
    event->bufPos += put_int64(event, value);
}

void stats_event_write_float(struct stats_event* event, float value) {
    if (!event || event->errors) return;

    start_field(event, FLOAT_TYPE);
    event->bufPos += put_float(event, value);
}

void stats_event_write_bool(struct stats_event* event, bool value) {
    if (!event || event->errors) return;

    start_field(event, BOOL_TYPE);
    event->bufPos += put_bool(event, value);
}

// Buf is assumed to be encoded using UTF8
void stats_event_write_byte_array(struct stats_event* event, uint8_t* buf, uint32_t numBytes) {
    if (!event || !buf || event->errors) return;

    start_field(event, BYTE_ARRAY_TYPE);
    event->bufPos += put_int32(event, numBytes);
    event->bufPos += put_byte_array(event, buf, numBytes);
}

// Buf is assumed to be encoded using UTF8
void stats_event_write_string8(struct stats_event* event, char* buf, uint32_t numBytes) {
    if (!event || !buf || event->errors) return;

    start_field(event, STRING_TYPE);
    event->bufPos += put_int32(event, numBytes);
    event->bufPos += put_byte_array(event, buf, numBytes);
}

// Tags are assumed to be encoded using UTF8
void stats_event_write_attribution_chain(struct stats_event* event, uint32_t* uids, char** tags,
                                         uint32_t* tagLengths, uint32_t numNodes) {
    if (!event || event->errors) return;
    if (numNodes > MAX_BYTE_VALUE) {
        event->errors |= ERROR_ATTRIBUTION_CHAIN_TOO_LONG;
        return;
    }

    start_field(event, ATTRIBUTION_CHAIN_TYPE);
    event->bufPos += put_byte(event, (byte)numNodes);

    for (int i = 0; i < numNodes; i++) {
        event->bufPos += put_int32(event, uids[i]);
        event->bufPos += put_int32(event, tagLengths[i]);
        event->bufPos += put_byte_array(event, tags[i], tagLengths[i]);
    }
}

void stats_event_add_key_value_pairs(struct stats_event* event, struct key_value_pair* pairs,
                                     uint32_t numPairs) {
    if (!event || event->errors) return;
    if (numPairs > MAX_BYTE_VALUE) {
        event->errors |= ERROR_TOO_MANY_KEY_VALUE_PAIRS;
        return;
    }

    start_field(event, KEY_VALUE_PAIRS_TYPE);
    event->bufPos += put_byte(event, (byte)numPairs);

    for (int i = 0; i < numPairs; i++) {
        event->bufPos += put_int32(event, pairs[i].key);
        event->bufPos += put_byte(event, pairs[i].valueType);
        switch (pairs[i].valueType) {
            case INT32_TYPE:
                event->bufPos += put_int32(event, pairs[i].int32Value);
                break;
            case INT64_TYPE:
                event->bufPos += put_int64(event, pairs[i].int64Value);
                break;
            case FLOAT_TYPE:
                event->bufPos += put_float(event, pairs[i].floatValue);
                break;
            case STRING_TYPE:
                event->bufPos += put_int32(event, pairs[i].stringBytes);
                event->bufPos += put_byte_array(event, pairs[i].stringValue, pairs[i].stringBytes);
                break;
            default:
                event->errors |= ERROR_INVALID_VALUE_TYPE;
                return;
        }
    }
}

// Side-effect: modifies event->errors if annotation does not follow field
static bool does_annotation_follow_field(struct stats_event* event) {
    if (event->lastFieldPos == 0) {
        event->errors |= ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD;
        return false;
    }
    return true;
}

// Side-effect: modifies event->errors if annotation id is too large
static bool is_valid_annotation_id(struct stats_event* event, uint32_t annotationId) {
    if (annotationId > MAX_BYTE_VALUE) {
        event->errors |= ERROR_ANNOTATION_ID_TOO_LARGE;
        return false;
    }
    return true;
}

// Side-effect: modifies event->errors if field has too many annotations
static void increment_annotation_count(struct stats_event* event) {
    byte fieldType = event->buf[event->lastFieldPos] & 0x0F;
    uint32_t oldAnnotationCount = event->buf[event->lastFieldPos] & 0xF0;
    uint32_t newAnnotationCount = oldAnnotationCount + 1;

    if (newAnnotationCount > MAX_ANNOTATION_COUNT) {
        event->errors |= ERROR_TOO_MANY_ANNOTATIONS;
        return;
    }

    event->buf[event->lastFieldPos] = (((byte)newAnnotationCount << 4) & 0xF0) | fieldType;
}

void stats_event_add_bool_annotation(struct stats_event* event, uint32_t annotationId, bool value) {
    if (!event || event->errors) return;
    if (!does_annotation_follow_field(event)) return;
    if (!is_valid_annotation_id(event, annotationId)) return;

    event->bufPos += put_byte(event, (byte)annotationId);
    event->bufPos += put_byte(event, BOOL_TYPE);
    event->bufPos += put_bool(event, value);
    increment_annotation_count(event);
}

void stats_event_add_int32_annotation(struct stats_event* event, uint32_t annotationId,
                                      int32_t value) {
    if (!event || event->errors) return;
    if (!does_annotation_follow_field(event)) return;
    if (!is_valid_annotation_id(event, annotationId)) return;

    event->bufPos += put_byte(event, (byte)annotationId);
    event->bufPos += put_byte(event, INT32_TYPE);
    event->bufPos += put_int32(event, value);
    increment_annotation_count(event);
}

uint32_t stats_event_get_errors(struct stats_event* event) {
    return event->errors;
}

static void build(struct stats_event* event) {
    // store size before we modify bufPos
    event->size = event->bufPos;

    if (event->timestampNs == 0) {
        event->errors |= ERROR_NO_TIMESTAMP;
    } else {
        // Don't use the write functions since they short-circuit if there was
        // an error previously. We, regardless, want to know the timestamp and
        // atomId.
        event->bufPos = POS_TIMESTAMP;
        event->bufPos += put_byte(event, INT64_TYPE);
        event->bufPos += put_int64(event, event->timestampNs);
        event->numElements++;
    }

    if (event->atomId == 0) {
        event->errors |= ERROR_NO_ATOM_ID;
    } else {
        event->bufPos = POS_ATOM_ID;
        event->bufPos += put_byte(event, INT32_TYPE);
        event->bufPos += put_int64(event, event->atomId);
        event->numElements++;
    }

    if (event->numElements > MAX_BYTE_VALUE) {
        event->errors |= ERROR_TOO_MANY_FIELDS;
    } else {
        event->bufPos = POS_NUM_ELEMENTS;
        put_byte(event, (byte)event->numElements);
    }

    // If there are errors, rewrite buffer
    if (event->errors) {
        event->bufPos = POS_NUM_ELEMENTS;
        put_byte(event, (byte)3);

        event->bufPos = POS_FIRST_FIELD;
        event->bufPos += put_byte(event, ERROR_TYPE);
        event->bufPos += put_int32(event, event->errors);
        event->size = event->bufPos;
    }
}

void stats_event_write(struct stats_event* event) {
    if (!event) return;

    build(event);

    // prepare iovecs for write to statsd
    struct iovec vecs[2];
    vecs[0].iov_base = &event->tag;
    vecs[0].iov_len = sizeof(event->tag);
    vecs[1].iov_base = &event->buf;
    vecs[1].iov_len = event->size;
    write_to_statsd(vecs, 2);
}
