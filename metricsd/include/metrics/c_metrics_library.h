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

#ifndef METRICS_C_METRICS_LIBRARY_H_
#define METRICS_C_METRICS_LIBRARY_H_

#if defined(__cplusplus)
extern "C" {
#endif
typedef struct CMetricsLibraryOpaque* CMetricsLibrary;

// C wrapper for MetricsLibrary::MetricsLibrary.
CMetricsLibrary CMetricsLibraryNew(void);

// C wrapper for MetricsLibrary::~MetricsLibrary.
void CMetricsLibraryDelete(CMetricsLibrary handle);

// C wrapper for MetricsLibrary::Init.
void CMetricsLibraryInit(CMetricsLibrary handle);

// C wrapper for MetricsLibrary::SendToUMA.
int CMetricsLibrarySendToUMA(CMetricsLibrary handle,
                             const char* name, int sample,
                             int min, int max, int nbuckets);

// C wrapper for MetricsLibrary::SendEnumToUMA.
int CMetricsLibrarySendEnumToUMA(CMetricsLibrary handle,
                                 const char* name, int sample, int max);

// C wrapper for MetricsLibrary::SendSparseToUMA.
int CMetricsLibrarySendSparseToUMA(CMetricsLibrary handle,
                                   const char* name, int sample);

// C wrapper for MetricsLibrary::SendCrashToUMA.
int CMetricsLibrarySendCrashToUMA(CMetricsLibrary handle,
                                  const char* crash_kind);

// C wrapper for MetricsLibrary::AreMetricsEnabled.
int CMetricsLibraryAreMetricsEnabled(CMetricsLibrary handle);

#if defined(__cplusplus)
}
#endif
#endif  // METRICS_C_METRICS_LIBRARY_H_
