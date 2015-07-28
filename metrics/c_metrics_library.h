// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

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

// C wrapper for MetricsLibrary::SendUserActionToUMA.
int CMetricsLibrarySendUserActionToUMA(CMetricsLibrary handle,
                                       const char* action);

// C wrapper for MetricsLibrary::SendCrashToUMA.
int CMetricsLibrarySendCrashToUMA(CMetricsLibrary handle,
                                  const char* crash_kind);

// C wrapper for MetricsLibrary::AreMetricsEnabled.
int CMetricsLibraryAreMetricsEnabled(CMetricsLibrary handle);

#if defined(__cplusplus)
}
#endif
#endif  // METRICS_C_METRICS_LIBRARY_H_
