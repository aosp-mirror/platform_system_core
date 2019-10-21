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
 *      stats_event_set_timestamp_ns(event, timestampNs);
 *      stats_event_set_atom_id(event, atomId);
 *      stats_event_write_int32(event, 24);
 *      stats_event_add_bool_annotation(event, 1, true); // annotations apply to the previous field
 *      stats_event_add_int32_annotation(event, 2, 128);
 *      stats_event_write_float(event, 2.0);
 *
 *      stats_event_write(event);
 *      stats_event_release(event);
 *
 * Notes:
 *    (a) write_<type>() and add_<type>_annotation() should be called in the order that fields
 *        and annotations are defined in the atom.
 *    (b) set_timestamp_ns() and set_atom_id() can be called anytime before stats_event_write().
 *    (c) add_<type>_annotation() calls apply to the previous field.
 *    (d) If errors occur, stats_event_write() will write a bitmask of the errors to the socket.
 *    (e) Strings should be encoded using UTF8 and written using stats_event_write_string8().
 */

struct stats_event;

/* ERRORS */
#define ERROR_NO_TIMESTAMP 0x1
#define ERROR_NO_ATOM_ID 0x2
#define ERROR_OVERFLOW 0x4
#define ERROR_ATTRIBUTION_CHAIN_TOO_LONG 0x8
#define ERROR_ANNOTATION_DOES_NOT_FOLLOW_FIELD 0x10
#define ERROR_INVALID_ANNOTATION_ID 0x20
#define ERROR_ANNOTATION_ID_TOO_LARGE 0x40
#define ERROR_TOO_MANY_ANNOTATIONS 0x80
#define ERROR_TOO_MANY_FIELDS 0x100

/* System API */
struct stats_event* stats_event_obtain();
void stats_event_write(struct stats_event* event);
void stats_event_release(struct stats_event* event);

void stats_event_set_atom_id(struct stats_event* event, const uint32_t atomId);
void stats_event_set_timestamp_ns(struct stats_event* event, const uint64_t timestampNs);

void stats_event_write_int32(struct stats_event* event, int32_t value);
void stats_event_write_int64(struct stats_event* event, int64_t value);
void stats_event_write_float(struct stats_event* event, float value);
void stats_event_write_bool(struct stats_event* event, bool value);
void stats_event_write_byte_array(struct stats_event* event, uint8_t* buf, uint32_t numBytes);
void stats_event_write_string8(struct stats_event* event, char* buf, uint32_t numBytes);
void stats_event_write_attribution_chain(struct stats_event* event, uint32_t* uids, char** tags,
                                         uint32_t* tagLengths, uint32_t numNodes);

void stats_event_add_bool_annotation(struct stats_event* event, uint32_t annotationId, bool value);
void stats_event_add_int32_annotation(struct stats_event* event, uint32_t annotationId,
                                      int32_t value);

uint32_t stats_event_get_errors(struct stats_event* event);

#endif  // ANDROID_STATS_LOG_STATS_EVENT_H
