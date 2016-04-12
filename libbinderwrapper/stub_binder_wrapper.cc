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

#include <binderwrapper/stub_binder_wrapper.h>

#include <base/logging.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>

namespace android {

StubBinderWrapper::StubBinderWrapper()
    : calling_uid_(-1),
      calling_pid_(-1) {}

StubBinderWrapper::~StubBinderWrapper() = default;

void StubBinderWrapper::SetBinderForService(const std::string& service_name,
                                            const sp<IBinder>& binder) {
  services_to_return_[service_name] = binder;
}

sp<IBinder> StubBinderWrapper::GetRegisteredService(
    const std::string& service_name) const {
  const auto it = registered_services_.find(service_name);
  return it != registered_services_.end() ? it->second : sp<IBinder>();
}

void StubBinderWrapper::NotifyAboutBinderDeath(const sp<IBinder>& binder) {
  const auto it = death_callbacks_.find(binder);
  if (it != death_callbacks_.end())
    it->second.Run();
}

sp<IBinder> StubBinderWrapper::GetService(const std::string& service_name) {
  const auto it = services_to_return_.find(service_name);
  return it != services_to_return_.end() ? it->second : sp<IBinder>();
}

bool StubBinderWrapper::RegisterService(const std::string& service_name,
                                        const sp<IBinder>& binder) {
  registered_services_[service_name] = binder;
  return true;
}

sp<BBinder> StubBinderWrapper::CreateLocalBinder() {
  sp<BBinder> binder(new BBinder());
  local_binders_.push_back(binder);
  return binder;
}

bool StubBinderWrapper::RegisterForDeathNotifications(
    const sp<IBinder>& binder,
    const ::base::Closure& callback) {
  death_callbacks_[binder] = callback;
  return true;
}

bool StubBinderWrapper::UnregisterForDeathNotifications(
    const sp<IBinder>& binder) {
  death_callbacks_.erase(binder);
  return true;
}

uid_t StubBinderWrapper::GetCallingUid() {
  return calling_uid_;
}

pid_t StubBinderWrapper::GetCallingPid() {
  return calling_pid_;
}

}  // namespace android
