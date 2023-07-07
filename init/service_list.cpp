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

#include "service_list.h"

#include <android-base/logging.h>

namespace android {
namespace init {

ServiceList::ServiceList() {}

ServiceList& ServiceList::GetInstance() {
    static ServiceList* instance = new ServiceList;
    return *instance;
}

size_t ServiceList::CheckAllCommands() {
    size_t failures = 0;
    for (const auto& service : services_) {
        failures += service->CheckAllCommands();
    }
    return failures;
}

void ServiceList::AddService(std::unique_ptr<Service> service) {
    services_.emplace_back(std::move(service));
}

// Shutdown services in the opposite order that they were started.
const std::vector<Service*> ServiceList::services_in_shutdown_order() const {
    std::vector<Service*> shutdown_services;
    for (const auto& service : services_) {
        if (service->start_order() > 0) shutdown_services.emplace_back(service.get());
    }
    std::sort(shutdown_services.begin(), shutdown_services.end(),
              [](const auto& a, const auto& b) { return a->start_order() > b->start_order(); });
    return shutdown_services;
}

void ServiceList::RemoveService(const Service& svc) {
    auto svc_it = std::find_if(
            services_.begin(), services_.end(),
            [&svc](const std::unique_ptr<Service>& s) { return svc.name() == s->name(); });
    if (svc_it == services_.end()) {
        return;
    }

    services_.erase(svc_it);
}

void ServiceList::DumpState() const {
    for (const auto& s : services_) {
        s->DumpState();
    }
}

void ServiceList::MarkPostData() {
    post_data_ = true;
}

bool ServiceList::IsPostData() {
    return post_data_;
}

void ServiceList::MarkServicesUpdate() {
    services_update_finished_ = true;

    // start the delayed services
    for (const auto& name : delayed_service_names_) {
        Service* service = FindService(name);
        if (service == nullptr) {
            LOG(ERROR) << "delayed service '" << name << "' could not be found.";
            continue;
        }
        if (auto result = service->Start(); !result.ok()) {
            LOG(ERROR) << result.error().message();
        }
    }
    delayed_service_names_.clear();
}

void ServiceList::DelayService(const Service& service) {
    if (services_update_finished_) {
        LOG(ERROR) << "Cannot delay the start of service '" << service.name()
                   << "' because all services are already updated. Ignoring.";
        return;
    }
    delayed_service_names_.emplace_back(service.name());
}

}  // namespace init
}  // namespace android
