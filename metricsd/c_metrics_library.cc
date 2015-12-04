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

//
// C wrapper to libmetrics
//

#include "metrics/c_metrics_library.h"

#include <string>

#include "metrics/metrics_library.h"

extern "C" CMetricsLibrary CMetricsLibraryNew(void) {
  MetricsLibrary* lib = new MetricsLibrary;
  return reinterpret_cast<CMetricsLibrary>(lib);
}

extern "C" void CMetricsLibraryDelete(CMetricsLibrary handle) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  delete lib;
}

extern "C" void CMetricsLibraryInit(CMetricsLibrary handle) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  if (lib != NULL)
    lib->Init();
}

extern "C" int CMetricsLibrarySendToUMA(CMetricsLibrary handle,
                                        const char* name, int sample,
                                        int min, int max, int nbuckets) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  if (lib == NULL)
    return 0;
  return lib->SendToUMA(std::string(name), sample, min, max, nbuckets);
}

extern "C" int CMetricsLibrarySendEnumToUMA(CMetricsLibrary handle,
                                            const char* name, int sample,
                                            int max) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  if (lib == NULL)
    return 0;
  return lib->SendEnumToUMA(std::string(name), sample, max);
}

extern "C" int CMetricsLibrarySendSparseToUMA(CMetricsLibrary handle,
                                              const char* name, int sample) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  if (lib == NULL)
    return 0;
  return lib->SendSparseToUMA(std::string(name), sample);
}

extern "C" int CMetricsLibrarySendCrashToUMA(CMetricsLibrary handle,
                                            const char* crash_kind) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  if (lib == NULL)
    return 0;
  return lib->SendCrashToUMA(crash_kind);
}

extern "C" int CMetricsLibraryAreMetricsEnabled(CMetricsLibrary handle) {
  MetricsLibrary* lib = reinterpret_cast<MetricsLibrary*>(handle);
  if (lib == NULL)
    return 0;
  return lib->AreMetricsEnabled();
}
