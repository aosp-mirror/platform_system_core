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

#ifndef ANDROID_STATS_LOG_STATS_EVENT_H
#define ANDROID_STATS_LOG_STATS_EVENT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Functionality to build and store the buffer sent over the statsd socket.
 * This code defines and encapsulates the socket protocol.
 *
 * Usage:
 *      struct stats_event* event = stats_event_obtain();
 *
 *      stats_event_set_atom_id(event, atomId);
 *      stats_event_write_int32(event, 24);
 *      stats_event_add_bool_annotation(event, 1, true); // annotations apply to the previous field
 *      stats_event_add_int32_annotation(event, 2, 128);
 *      stats_event_write_float(event, 2.0);
 *
 *      stats_event_build(event);
 *      stats_event_write(event);
 *      stats_event_release(event);
 *
 * Notes:
 *    (a) write_<type>() and add_<type>_annotation() should be called in the order that fields
 *        and annotations are defined in the atom.
 *    (b) set_atom_id() can be called anytime before stats_event_write().
 *    (c) add_<type>_annotation() calls apply to the previous field.
 *    (d) If errors occur, stats_event_write() will write a bitmask of the errors to the socket.
 *    (e) All strings should be encoded using UTF8.
 */

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

#ifdef __cplusplus
extern "C" {
#endif  // __CPLUSPLUS

struct stats_event;

/* SYSTEM API */
struct stats_event* stats_event_obtain();
// The build function can be called multiple times without error. If the event
// has been built before, this function is a no-op.
void stats_event_build(struct stats_event* event);
void stats_event_write(struct stats_event* event);
void stats_event_release(struct stats_event* event);

void stats_event_set_atom_id(struct stats_event* event, uint32_t atomId);

void stats_event_write_int32(struct stats_event* event, int32_t value);
void stats_event_write_int64(struct stats_event* event, int64_t value);
void stats_event_write_float(struct stats_event* event, float value);
void stats_event_write_bool(struct stats_event* event, bool value);

void stats_event_write_byte_array(struct stats_event* event, uint8_t* buf, size_t numBytes);

// Buf must be null-terminated.
void stats_event_write_string8(struct stats_event* event, const char* buf);

// Tags must be null-terminated.
void stats_event_write_attribution_chain(struct stats_event* event, uint32_t* uids,
                                         const char** tags, uint8_t numNodes);

/* key_value_pair struct can be constructed as follows:
 *    struct key_value_pair pair = {.key = key, .valueType = STRING_TYPE,
 *                                  .stringValue = buf};
 */
struct key_value_pair {
    int32_t key;
    uint8_t valueType;  // expected to be INT32_TYPE, INT64_TYPE, FLOAT_TYPE, or STRING_TYPE
    union {
        int32_t int32Value;
        int64_t int64Value;
        float floatValue;
        const char* stringValue;  // must be null terminated
    };
};

void stats_event_write_key_value_pairs(struct stats_event* event, struct key_value_pair* pairs,
                                       uint8_t numPairs);

void stats_event_add_bool_annotation(struct stats_event* event, uint8_t annotationId, bool value);
void stats_event_add_int32_annotation(struct stats_event* event, uint8_t annotationId,
                                      int32_t value);

uint32_t stats_event_get_atom_id(struct stats_event* event);
uint8_t* stats_event_get_buffer(struct stats_event* event, size_t* size);
uint32_t stats_event_get_errors(struct stats_event* event);

#ifdef __cplusplus
}
#endif  // __CPLUSPLUS

#endif  // ANDROID_STATS_LOG_STATS_EVENT_H
