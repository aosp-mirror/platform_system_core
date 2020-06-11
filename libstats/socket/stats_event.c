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
#include "stats_buffer_writer.h"

#define LOGGER_ENTRY_MAX_PAYLOAD 4068
// Max payload size is 4 bytes less as 4 bytes are reserved for stats_eventTag.
// See android_util_Stats_Log.cpp
#define MAX_PUSH_EVENT_PAYLOAD (LOGGER_ENTRY_MAX_PAYLOAD - 4)

#define MAX_PULL_EVENT_PAYLOAD (50 * 1024)  // 50 KB

/* POSITIONS */
#define POS_NUM_ELEMENTS 1
#define POS_TIMESTAMP (POS_NUM_ELEMENTS + sizeof(uint8_t))
#define POS_ATOM_ID (POS_TIMESTAMP + sizeof(uint8_t) + sizeof(uint64_t))

/* LIMITS */
#define MAX_ANNOTATION_COUNT 15
#define MAX_BYTE_VALUE 127  // parsing side requires that lengths fit in 7 bits

/* ERRORS */
#define ERROR_NO_TIMESTAMP 0x1
#define ERROR_NO_ATOM_ID 0x2
#define ERROR_OVERFLOW 0x4
#define ERROR_ATTRIBUTION_CHAIN_TOO_LONG 0x8
#define ERROR_TOO_MANY_KEY_VALUE_PAIRS 0x10
#define ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD 0x20
#define ERROR_INVALID_ANNOTATION_ID 0x40
#define ERROR_ANNOTATION_ID_TOO_LARGE 0x80
#define ERROR_TOO_MANY_ANNOTATIONS 0x100
#define ERROR_TOO_MANY_FIELDS 0x200
#define ERROR_INVALID_VALUE_TYPE 0x400
#define ERROR_STRING_NOT_NULL_TERMINATED 0x800
#define ERROR_ATOM_ID_INVALID_POSITION 0x2000

/* TYPE IDS */
#define INT32_TYPE 0x00
#define INT64_TYPE 0x01
#define STRING_TYPE 0x02
#define LIST_TYPE 0x03
#define FLOAT_TYPE 0x04
#define BOOL_TYPE 0x05
#define BYTE_ARRAY_TYPE 0x06
#define OBJECT_TYPE 0x07
#define KEY_VALUE_PAIRS_TYPE 0x08
#define ATTRIBUTION_CHAIN_TYPE 0x09
#define ERROR_TYPE 0x0F

// The AStatsEvent struct holds the serialized encoding of an event
// within a buf. Also includes other required fields.
struct AStatsEvent {
    uint8_t* buf;
    // Location of last field within the buf. Here, field denotes either a
    // metadata field (e.g. timestamp) or an atom field.
    size_t lastFieldPos;
    // Number of valid bytes within the buffer.
    size_t numBytesWritten;
    uint32_t numElements;
    uint32_t atomId;
    uint32_t errors;
    bool built;
    size_t bufSize;
};

static int64_t get_elapsed_realtime_ns() {
    struct timespec t;
    t.tv_sec = t.tv_nsec = 0;
    clock_gettime(CLOCK_BOOTTIME, &t);
    return (int64_t)t.tv_sec * 1000000000LL + t.tv_nsec;
}

AStatsEvent* AStatsEvent_obtain() {
    AStatsEvent* event = malloc(sizeof(AStatsEvent));
    event->lastFieldPos = 0;
    event->numBytesWritten = 2;  // reserve first 2 bytes for root event type and number of elements
    event->numElements = 0;
    event->atomId = 0;
    event->errors = 0;
    event->built = false;
    event->bufSize = MAX_PUSH_EVENT_PAYLOAD;
    event->buf = (uint8_t*)calloc(event->bufSize, 1);

    event->buf[0] = OBJECT_TYPE;
    AStatsEvent_writeInt64(event, get_elapsed_realtime_ns());  // write the timestamp

    return event;
}

void AStatsEvent_release(AStatsEvent* event) {
    free(event->buf);
    free(event);
}

void AStatsEvent_setAtomId(AStatsEvent* event, uint32_t atomId) {
    if (event->atomId != 0) return;
    if (event->numElements != 1) {
        event->errors |= ERROR_ATOM_ID_INVALID_POSITION;
        return;
    }

    event->atomId = atomId;
    AStatsEvent_writeInt32(event, atomId);
}

// Overwrites the timestamp populated in AStatsEvent_obtain with a custom
// timestamp. Should only be called from test code.
void AStatsEvent_overwriteTimestamp(AStatsEvent* event, uint64_t timestampNs) {
    memcpy(&event->buf[POS_TIMESTAMP + sizeof(uint8_t)], &timestampNs, sizeof(timestampNs));
    // Do not increment numElements because we already accounted for the timestamp
    // within AStatsEvent_obtain.
}

// Side-effect: modifies event->errors if the buffer would overflow
static bool overflows(AStatsEvent* event, size_t size) {
    const size_t totalBytesNeeded = event->numBytesWritten + size;
    if (totalBytesNeeded > MAX_PULL_EVENT_PAYLOAD) {
        event->errors |= ERROR_OVERFLOW;
        return true;
    }

    // Expand buffer if needed.
    if (event->bufSize < MAX_PULL_EVENT_PAYLOAD && totalBytesNeeded > event->bufSize) {
        do {
            event->bufSize *= 2;
        } while (event->bufSize <= totalBytesNeeded);

        if (event->bufSize > MAX_PULL_EVENT_PAYLOAD) {
            event->bufSize = MAX_PULL_EVENT_PAYLOAD;
        }

        event->buf = (uint8_t*)realloc(event->buf, event->bufSize);
    }
    return false;
}

// Side-effect: all append functions increment event->numBytesWritten if there is
// sufficient space within the buffer to place the value
static void append_byte(AStatsEvent* event, uint8_t value) {
    if (!overflows(event, sizeof(value))) {
        event->buf[event->numBytesWritten] = value;
        event->numBytesWritten += sizeof(value);
    }
}

static void append_bool(AStatsEvent* event, bool value) {
    append_byte(event, (uint8_t)value);
}

static void append_int32(AStatsEvent* event, int32_t value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->numBytesWritten], &value, sizeof(value));
        event->numBytesWritten += sizeof(value);
    }
}

static void append_int64(AStatsEvent* event, int64_t value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->numBytesWritten], &value, sizeof(value));
        event->numBytesWritten += sizeof(value);
    }
}

static void append_float(AStatsEvent* event, float value) {
    if (!overflows(event, sizeof(value))) {
        memcpy(&event->buf[event->numBytesWritten], &value, sizeof(value));
        event->numBytesWritten += sizeof(float);
    }
}

static void append_byte_array(AStatsEvent* event, const uint8_t* buf, size_t size) {
    if (!overflows(event, size)) {
        memcpy(&event->buf[event->numBytesWritten], buf, size);
        event->numBytesWritten += size;
    }
}

// Side-effect: modifies event->errors if buf is not properly null-terminated
static void append_string(AStatsEvent* event, const char* buf) {
    size_t size = strnlen(buf, MAX_PULL_EVENT_PAYLOAD);
    if (size == MAX_PULL_EVENT_PAYLOAD) {
        event->errors |= ERROR_STRING_NOT_NULL_TERMINATED;
        return;
    }

    append_int32(event, size);
    append_byte_array(event, (uint8_t*)buf, size);
}

static void start_field(AStatsEvent* event, uint8_t typeId) {
    event->lastFieldPos = event->numBytesWritten;
    append_byte(event, typeId);
    event->numElements++;
}

void AStatsEvent_writeInt32(AStatsEvent* event, int32_t value) {
    start_field(event, INT32_TYPE);
    append_int32(event, value);
}

void AStatsEvent_writeInt64(AStatsEvent* event, int64_t value) {
    start_field(event, INT64_TYPE);
    append_int64(event, value);
}

void AStatsEvent_writeFloat(AStatsEvent* event, float value) {
    start_field(event, FLOAT_TYPE);
    append_float(event, value);
}

void AStatsEvent_writeBool(AStatsEvent* event, bool value) {
    start_field(event, BOOL_TYPE);
    append_bool(event, value);
}

void AStatsEvent_writeByteArray(AStatsEvent* event, const uint8_t* buf, size_t numBytes) {
    start_field(event, BYTE_ARRAY_TYPE);
    append_int32(event, numBytes);
    append_byte_array(event, buf, numBytes);
}

// Value is assumed to be encoded using UTF8
void AStatsEvent_writeString(AStatsEvent* event, const char* value) {
    start_field(event, STRING_TYPE);
    append_string(event, value);
}

// Tags are assumed to be encoded using UTF8
void AStatsEvent_writeAttributionChain(AStatsEvent* event, const uint32_t* uids,
                                       const char* const* tags, uint8_t numNodes) {
    if (numNodes > MAX_BYTE_VALUE) {
        event->errors |= ERROR_ATTRIBUTION_CHAIN_TOO_LONG;
        return;
    }

    start_field(event, ATTRIBUTION_CHAIN_TYPE);
    append_byte(event, numNodes);

    for (uint8_t i = 0; i < numNodes; i++) {
        append_int32(event, uids[i]);
        append_string(event, tags[i]);
    }
}

// Side-effect: modifies event->errors if field has too many annotations
static void increment_annotation_count(AStatsEvent* event) {
    uint8_t fieldType = event->buf[event->lastFieldPos] & 0x0F;
    uint32_t oldAnnotationCount = (event->buf[event->lastFieldPos] & 0xF0) >> 4;
    uint32_t newAnnotationCount = oldAnnotationCount + 1;

    if (newAnnotationCount > MAX_ANNOTATION_COUNT) {
        event->errors |= ERROR_TOO_MANY_ANNOTATIONS;
        return;
    }

    event->buf[event->lastFieldPos] = (((uint8_t)newAnnotationCount << 4) & 0xF0) | fieldType;
}

void AStatsEvent_addBoolAnnotation(AStatsEvent* event, uint8_t annotationId, bool value) {
    if (event->numElements < 2) {
        event->errors |= ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD;
        return;
    } else if (annotationId > MAX_BYTE_VALUE) {
        event->errors |= ERROR_ANNOTATION_ID_TOO_LARGE;
        return;
    }

    append_byte(event, annotationId);
    append_byte(event, BOOL_TYPE);
    append_bool(event, value);
    increment_annotation_count(event);
}

void AStatsEvent_addInt32Annotation(AStatsEvent* event, uint8_t annotationId, int32_t value) {
    if (event->numElements < 2) {
        event->errors |= ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD;
        return;
    } else if (annotationId > MAX_BYTE_VALUE) {
        event->errors |= ERROR_ANNOTATION_ID_TOO_LARGE;
        return;
    }

    append_byte(event, annotationId);
    append_byte(event, INT32_TYPE);
    append_int32(event, value);
    increment_annotation_count(event);
}

uint32_t AStatsEvent_getAtomId(AStatsEvent* event) {
    return event->atomId;
}

uint8_t* AStatsEvent_getBuffer(AStatsEvent* event, size_t* size) {
    if (size) *size = event->numBytesWritten;
    return event->buf;
}

uint32_t AStatsEvent_getErrors(AStatsEvent* event) {
    return event->errors;
}

static void build_internal(AStatsEvent* event, const bool push) {
    if (event->numElements > MAX_BYTE_VALUE) event->errors |= ERROR_TOO_MANY_FIELDS;
    if (0 == event->atomId) event->errors |= ERROR_NO_ATOM_ID;
    if (push && event->numBytesWritten > MAX_PUSH_EVENT_PAYLOAD) event->errors |= ERROR_OVERFLOW;

    // If there are errors, rewrite buffer.
    if (event->errors) {
        // Discard everything after the atom id (including atom-level
        // annotations). This leaves only two elements (timestamp and atom id).
        event->numElements = 2;
        // Reset number of atom-level annotations to 0.
        event->buf[POS_ATOM_ID] = INT32_TYPE;
        // Now, write errors to the buffer immediately after the atom id.
        event->numBytesWritten = POS_ATOM_ID + sizeof(uint8_t) + sizeof(uint32_t);
        start_field(event, ERROR_TYPE);
        append_int32(event, event->errors);
    }

    event->buf[POS_NUM_ELEMENTS] = event->numElements;
}

void AStatsEvent_build(AStatsEvent* event) {
    if (event->built) return;

    build_internal(event, false /* push */);

    event->built = true;
}

int AStatsEvent_write(AStatsEvent* event) {
    build_internal(event, true /* push */);
    return write_buffer_to_statsd(event->buf, event->numBytesWritten, event->atomId);
}
