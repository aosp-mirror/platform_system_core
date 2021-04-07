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

#pragma once

#include <memory>
#include <vector>

#include "service.h"

namespace android {
namespace init {

class ServiceList {
  public:
    static ServiceList& GetInstance();

    // Exposed for testing
    ServiceList();
    size_t CheckAllCommands();

    void AddService(std::unique_ptr<Service> service);
    void RemoveService(const Service& svc);
    template <class UnaryPredicate>
    void RemoveServiceIf(UnaryPredicate predicate) {
        services_.erase(std::remove_if(services_.begin(), services_.end(), predicate),
                        services_.end());
    }

    template <typename T, typename F = decltype(&Service::name)>
    Service* FindService(T value, F function = &Service::name) const {
        auto svc = std::find_if(services_.begin(), services_.end(),
                                [&function, &value](const std::unique_ptr<Service>& s) {
                                    return std::invoke(function, s) == value;
                                });
        if (svc != services_.end()) {
            return svc->get();
        }
        return nullptr;
    }

    Service* FindInterface(const std::string& interface_name) {
        for (const auto& svc : services_) {
            if (svc->interfaces().count(interface_name) > 0) {
                return svc.get();
            }
        }

        return nullptr;
    }

    void DumpState() const;

    auto begin() const { return services_.begin(); }
    auto end() const { return services_.end(); }
    const std::vector<Service*> services_in_shutdown_order() const;

    void MarkPostData();
    bool IsPostData();
    void MarkServicesUpdate();
    bool IsServicesUpdated() const { return services_update_finished_; }
    void DelayService(const Service& service);

    void ResetState() {
        post_data_ = false;
        services_update_finished_ = false;
    }

  private:
    std::vector<std::unique_ptr<Service>> services_;

    bool post_data_ = false;
    bool services_update_finished_ = false;
    std::vector<std::string> delayed_service_names_;
};

}  // namespace init
}  // namespace android
