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

#include "real_binder_wrapper.h"

#include <android-base/logging.h>

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

namespace android {

// Class that handles binder death notifications. libbinder wants the recipient
// to be wrapped in sp<>, so registering RealBinderWrapper as a recipient would
// be awkward.
class RealBinderWrapper::DeathRecipient : public IBinder::DeathRecipient {
 public:
   explicit DeathRecipient(const std::function<void()>& callback)
       : callback_(std::move(callback)) {}
   ~DeathRecipient() = default;

   // IBinder::DeathRecipient:
   void binderDied(const wp<IBinder>& who) override { callback_(); }

 private:
  // Callback to run in response to binder death.
   std::function<void()> callback_;

   DISALLOW_COPY_AND_ASSIGN(DeathRecipient);
};

RealBinderWrapper::RealBinderWrapper() = default;

RealBinderWrapper::~RealBinderWrapper() = default;

sp<IBinder> RealBinderWrapper::GetService(const std::string& service_name) {
  sp<IServiceManager> service_manager = defaultServiceManager();
  if (!service_manager.get()) {
    LOG(ERROR) << "Unable to get service manager";
    return sp<IBinder>();
  }
  sp<IBinder> binder =
      service_manager->checkService(String16(service_name.c_str()));
  if (!binder.get())
    LOG(ERROR) << "Unable to get \"" << service_name << "\" service";
  return binder;
}

bool RealBinderWrapper::RegisterService(const std::string& service_name,
                                        const sp<IBinder>& binder) {
  sp<IServiceManager> service_manager = defaultServiceManager();
  if (!service_manager.get()) {
    LOG(ERROR) << "Unable to get service manager";
    return false;
  }
  status_t status = defaultServiceManager()->addService(
      String16(service_name.c_str()), binder);
  if (status != OK) {
    LOG(ERROR) << "Failed to register \"" << service_name << "\" with service "
               << "manager";
    return false;
  }
  return true;
}

sp<BBinder> RealBinderWrapper::CreateLocalBinder() {
  return sp<BBinder>(new BBinder());
}

bool RealBinderWrapper::RegisterForDeathNotifications(const sp<IBinder>& binder,
                                                      const std::function<void()>& callback) {
  sp<DeathRecipient> recipient(new DeathRecipient(callback));
  if (binder->linkToDeath(recipient) != OK) {
    LOG(ERROR) << "Failed to register for death notifications on "
               << binder.get();
    return false;
  }
  death_recipients_[binder] = recipient;
  return true;
}

bool RealBinderWrapper::UnregisterForDeathNotifications(
    const sp<IBinder>& binder) {
  auto it = death_recipients_.find(binder);
  if (it == death_recipients_.end()) {
    LOG(ERROR) << "Not registered for death notifications on " << binder.get();
    return false;
  }
  if (binder->unlinkToDeath(it->second) != OK) {
    LOG(ERROR) << "Failed to unregister for death notifications on "
               << binder.get();
    return false;
  }
  death_recipients_.erase(it);
  return true;
}

uid_t RealBinderWrapper::GetCallingUid() {
  return IPCThreadState::self()->getCallingUid();
}

pid_t RealBinderWrapper::GetCallingPid() {
  return IPCThreadState::self()->getCallingPid();
}

}  // namespace android
