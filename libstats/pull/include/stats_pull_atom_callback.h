/*
 * Copyright (C) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <stats_event.h>

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque struct representing the metadata for registering an AStatsManager_PullAtomCallback.
 */
struct AStatsManager_PullAtomMetadata;
typedef struct AStatsManager_PullAtomMetadata AStatsManager_PullAtomMetadata;

/**
 * Allocate and initialize new PullAtomMetadata.
 *
 * Must call AStatsManager_PullAtomMetadata_release to free the memory.
 */
AStatsManager_PullAtomMetadata* AStatsManager_PullAtomMetadata_obtain();

/**
 * Frees the memory held by this PullAtomMetadata
 *
 * After calling this, the PullAtomMetadata must not be used or modified in any way.
 */
void AStatsManager_PullAtomMetadata_release(AStatsManager_PullAtomMetadata* metadata);

/**
 * Set the cool down time of the pull in milliseconds. If two successive pulls are issued
 * within the cool down, a cached version of the first will be used for the second. The minimum
 * allowed cool down is one second.
 */
void AStatsManager_PullAtomMetadata_setCoolDownMillis(AStatsManager_PullAtomMetadata* metadata,
                                                      int64_t cool_down_millis);

/**
 * Get the cool down time of the pull in milliseconds.
 */
int64_t AStatsManager_PullAtomMetadata_getCoolDownMillis(AStatsManager_PullAtomMetadata* metadata);

/**
 * Set the maximum time the pull can take in milliseconds.
 * The maximum allowed timeout is 10 seconds.
 */
void AStatsManager_PullAtomMetadata_setTimeoutMillis(AStatsManager_PullAtomMetadata* metadata,
                                                     int64_t timeout_millis);

/**
 * Get the maximum time the pull can take in milliseconds.
 */
int64_t AStatsManager_PullAtomMetadata_getTimeoutMillis(AStatsManager_PullAtomMetadata* metadata);

/**
 * Set the additive fields of this pulled atom.
 *
 * This is only applicable for atoms which have a uid field. When tasks are run in
 * isolated processes, the data will be attributed to the host uid. Additive fields
 * will be combined when the non-additive fields are the same.
 */
void AStatsManager_PullAtomMetadata_setAdditiveFields(AStatsManager_PullAtomMetadata* metadata,
                                                      int32_t* additive_fields, int32_t num_fields);

/**
 * Get the number of additive fields for this pulled atom. This is intended to be called before
 * AStatsManager_PullAtomMetadata_getAdditiveFields to determine the size of the array.
 */
int32_t AStatsManager_PullAtomMetadata_getNumAdditiveFields(
        AStatsManager_PullAtomMetadata* metadata);

/**
 * Get the additive fields of this pulled atom.
 *
 * \param fields an output parameter containing the additive fields for this PullAtomMetadata.
 *               Fields is an array and it is assumed that it is at least as large as the number of
 *               additive fields, which can be obtained by calling
 *               AStatsManager_PullAtomMetadata_getNumAdditiveFields.
 */
void AStatsManager_PullAtomMetadata_getAdditiveFields(AStatsManager_PullAtomMetadata* metadata,
                                                      int32_t* fields);

/**
 * Return codes for the result of a pull.
 */
typedef int32_t AStatsManager_PullAtomCallbackReturn;
enum {
    // Value indicating that this pull was successful and that the result should be used.
    AStatsManager_PULL_SUCCESS = 0,
    // Value indicating that this pull was unsuccessful and that the result should not be used.
    AStatsManager_PULL_SKIP = 1,
};

/**
 * Opaque struct representing a list of AStatsEvent objects.
 */
struct AStatsEventList;
typedef struct AStatsEventList AStatsEventList;

/**
 * Appends and returns an AStatsEvent to the end of the AStatsEventList.
 *
 * If an AStatsEvent is obtained in this manner, the memory is internally managed and
 * AStatsEvent_release does not need to be called. The lifetime of the AStatsEvent is that of the
 * AStatsEventList.
 *
 * The AStatsEvent does still need to be built by calling AStatsEvent_build.
 */
AStatsEvent* AStatsEventList_addStatsEvent(AStatsEventList* pull_data);

/**
 * Callback interface for pulling atoms requested by the stats service.
 *
 * \param atom_tag the tag of the atom to pull.
 * \param data an output parameter in which the caller should fill the results of the pull. This
 *             param cannot be NULL and it's lifetime is as long as the execution of the callback.
 *             It must not be accessed or modified after returning from the callback.
 * \param cookie the opaque pointer passed in AStatsManager_registerPullAtomCallback.
 * \return AStatsManager_PULL_SUCCESS if the pull was successful, or AStatsManager_PULL_SKIP if not.
 */
typedef AStatsManager_PullAtomCallbackReturn (*AStatsManager_PullAtomCallback)(
        int32_t atom_tag, AStatsEventList* data, void* cookie);
/**
 * Sets a callback for an atom when that atom is to be pulled. The stats service will
 * invoke the callback when the stats service determines that this atom needs to be
 * pulled.
 *
 * Requires the REGISTER_STATS_PULL_ATOM permission.
 *
 * \param atom_tag          The tag of the atom for this pull atom callback.
 * \param metadata          Optional metadata specifying the timeout, cool down time, and
 *                          additive fields for mapping isolated to host uids.
 *                          This param is nullable, in which case defaults will be used.
 * \param callback          The callback to be invoked when the stats service pulls the atom.
 * \param cookie            A pointer that will be passed back to the callback.
 *                          It has no meaning to statsd.
 */
void AStatsManager_setPullAtomCallback(int32_t atom_tag, AStatsManager_PullAtomMetadata* metadata,
                                       AStatsManager_PullAtomCallback callback, void* cookie);

/**
 * Clears a callback for an atom when that atom is to be pulled. Note that any ongoing
 * pulls will still occur.
 *
 * Requires the REGISTER_STATS_PULL_ATOM permission.
 *
 * \param atomTag           The tag of the atom of which to unregister
 */
void AStatsManager_clearPullAtomCallback(int32_t atom_tag);

#ifdef __cplusplus
}
#endif
