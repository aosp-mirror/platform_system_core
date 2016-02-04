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

#ifndef METRICS_UPLOADER_METRISCD_SERVICE_RUNNER_H_
#define METRICS_UPLOADER_METRISCD_SERVICE_RUNNER_H_

#include <memory>
#include <thread>

#include <base/message_loop/message_loop.h>
#include <brillo/message_loops/message_loop.h>

#include "uploader/crash_counters.h"

class MetricsdServiceRunner {
 public:
  MetricsdServiceRunner(std::shared_ptr<CrashCounters> counters);

  // Start the Metricsd Binder service in a new thread.
  void Start();

  // Stop the Metricsd service and wait for its thread to exit.
  void Stop();

 private:
  // Creates and run the main loop for metricsd's Binder service.
  void Run();

  std::unique_ptr<base::MessageLoopForIO> message_loop_for_io_;
  std::unique_ptr<brillo::MessageLoop> message_loop_;

  std::unique_ptr<std::thread> thread_;
  std::shared_ptr<CrashCounters> counters_;
};

#endif  // METRICS_UPLOADER_METRISCD_SERVICE_RUNNER_H_
