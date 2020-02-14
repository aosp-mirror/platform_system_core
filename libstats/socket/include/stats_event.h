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
 *      AStatsEvent* event = AStatsEvent_obtain();
 *
 *      AStatsEvent_setAtomId(event, atomId);
 *      AStatsEvent_writeInt32(event, 24);
 *      AStatsEvent_addBoolAnnotation(event, 1, true); // annotations apply to the previous field
 *      AStatsEvent_addInt32Annotation(event, 2, 128);
 *      AStatsEvent_writeFloat(event, 2.0);
 *
 *      AStatsEvent_build(event);
 *      AStatsEvent_write(event);
 *      AStatsEvent_release(event);
 *
 * Notes:
 *    (a) write_<type>() and add_<type>_annotation() should be called in the order that fields
 *        and annotations are defined in the atom.
 *    (b) set_atom_id() can be called anytime before stats_event_write().
 *    (c) add_<type>_annotation() calls apply to the previous field.
 *    (d) If errors occur, stats_event_write() will write a bitmask of the errors to the socket.
 *    (e) All strings should be encoded using UTF8.
 */

#ifdef __cplusplus
extern "C" {
#endif  // __CPLUSPLUS

/**
 * Opaque struct use to represent a StatsEvent. It builds and stores the data that is sent to
 * statsd.
 */
struct AStatsEvent;
typedef struct AStatsEvent AStatsEvent;

/**
 * Returns a new AStatsEvent. If you call this function, you must call AStatsEvent_release to free
 * the allocated memory.
 */
AStatsEvent* AStatsEvent_obtain();

/**
 * Builds and finalizes the StatsEvent.
 *
 * After this function, the StatsEvent must not be modified in any way other than calling release or
 * write. Build must be always be called before AStatsEvent_write.
 *
 * Build can be called multiple times without error.
 * If the event has been built before, this function is a no-op.
 */
void AStatsEvent_build(AStatsEvent* event);

/**
 * Writes the StatsEvent to the stats log.
 *
 * After calling this, AStatsEvent_release must be called,
 * and is the only function that can be safely called.
 */
int AStatsEvent_write(AStatsEvent* event);

/**
 * Frees the memory held by this StatsEvent
 *
 * After calling this, the StatsEvent must not be used or modified in any way.
 */
void AStatsEvent_release(AStatsEvent* event);

/**
 * Sets the atom id for this StatsEvent.
 **/
void AStatsEvent_setAtomId(AStatsEvent* event, uint32_t atomId);

/**
 * Writes an int32_t field to this StatsEvent.
 **/
void AStatsEvent_writeInt32(AStatsEvent* event, int32_t value);

/**
 * Writes an int64_t field to this StatsEvent.
 **/
void AStatsEvent_writeInt64(AStatsEvent* event, int64_t value);

/**
 * Writes a float field to this StatsEvent.
 **/
void AStatsEvent_writeFloat(AStatsEvent* event, float value);

/**
 * Write a bool field to this StatsEvent.
 **/
void AStatsEvent_writeBool(AStatsEvent* event, bool value);

/**
 * Write a byte array field to this StatsEvent.
 **/
void AStatsEvent_writeByteArray(AStatsEvent* event, const uint8_t* buf, size_t numBytes);

/**
 * Write a string field to this StatsEvent.
 *
 * The string must be null-terminated.
 **/
void AStatsEvent_writeString(AStatsEvent* event, const char* value);

/**
 * Write an attribution chain field to this StatsEvent.
 *
 * The sizes of uids and tags must be equal. The AttributionNode at position i is
 * made up of uids[i] and tags[i].
 *
 * \param uids array of uids in the attribution chain.
 * \param tags array of tags in the attribution chain. Each tag must be null-terminated.
 * \param numNodes the number of AttributionNodes in the attribution chain. This is the length of
 *                 the uids and the tags.
 **/
void AStatsEvent_writeAttributionChain(AStatsEvent* event, const uint32_t* uids,
                                       const char* const* tags, uint8_t numNodes);

/**
 * Write a bool annotation for the previous field written.
 **/
void AStatsEvent_addBoolAnnotation(AStatsEvent* event, uint8_t annotationId, bool value);

/**
 * Write an integer annotation for the previous field written.
 **/
void AStatsEvent_addInt32Annotation(AStatsEvent* event, uint8_t annotationId, int32_t value);

// Internal/test APIs. Should not be exposed outside of the APEX.
void AStatsEvent_overwriteTimestamp(AStatsEvent* event, uint64_t timestampNs);
uint32_t AStatsEvent_getAtomId(AStatsEvent* event);
// Size is an output parameter.
uint8_t* AStatsEvent_getBuffer(AStatsEvent* event, size_t* size);
uint32_t AStatsEvent_getErrors(AStatsEvent* event);

// exposed for benchmarking only
void AStatsEvent_truncateBuffer(struct AStatsEvent* event, bool truncate);

#ifdef __cplusplus
}
#endif  // __CPLUSPLUS

#endif  // ANDROID_STATS_LOG_STATS_EVENT_H
