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

#include "uploader/metricsd_service_runner.h"

#include <thread>

#include <binder/IServiceManager.h>
#include <brillo/binder_watcher.h>
#include <brillo/message_loops/base_message_loop.h>
#include <utils/Errors.h>

#include "uploader/bn_metricsd_impl.h"

MetricsdServiceRunner::MetricsdServiceRunner(
    std::shared_ptr<CrashCounters> counters)
    : counters_(counters) {}

void MetricsdServiceRunner::Start() {
  thread_.reset(new std::thread(&MetricsdServiceRunner::Run, this));
}

void MetricsdServiceRunner::Run() {
  android::sp<BnMetricsdImpl> metrics_service(new BnMetricsdImpl(counters_));

  android::status_t status = android::defaultServiceManager()->addService(
      metrics_service->getInterfaceDescriptor(), metrics_service);
  CHECK(status == android::OK) << "Metricsd service registration failed";

  message_loop_for_io_.reset(new base::MessageLoopForIO);
  message_loop_.reset(new brillo::BaseMessageLoop(message_loop_for_io_.get()));

  brillo::BinderWatcher watcher(message_loop_.get());
  CHECK(watcher.Init()) << "failed to initialize the binder file descriptor "
                        << "watcher";

  message_loop_->Run();

  // Delete the message loop here as it needs to be deconstructed in the thread
  // it is attached to.
  message_loop_.reset();
  message_loop_for_io_.reset();
}

void MetricsdServiceRunner::Stop() {
  message_loop_for_io_->PostTask(FROM_HERE,
                                 message_loop_for_io_->QuitWhenIdleClosure());

  thread_->join();
}
