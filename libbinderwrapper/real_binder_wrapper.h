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

#ifndef SYSTEM_CORE_LIBBINDERWRAPPER_REAL_BINDER_WRAPPER_H_
#define SYSTEM_CORE_LIBBINDERWRAPPER_REAL_BINDER_WRAPPER_H_

#include <map>

#include <base/macros.h>
#include <binderwrapper/binder_wrapper.h>

namespace android {

class IBinder;

// Real implementation of BinderWrapper.
class RealBinderWrapper : public BinderWrapper {
 public:
  RealBinderWrapper();
  ~RealBinderWrapper() override;

  // BinderWrapper:
  sp<IBinder> GetService(const std::string& service_name) override;
  bool RegisterService(const std::string& service_name,
                       const sp<IBinder>& binder) override;
  sp<BBinder> CreateLocalBinder() override;
  bool RegisterForDeathNotifications(const sp<IBinder>& binder,
                                     const ::base::Closure& callback) override;
  bool UnregisterForDeathNotifications(const sp<IBinder>& binder) override;
  uid_t GetCallingUid() override;
  pid_t GetCallingPid() override;

 private:
  class DeathRecipient;

  // Map from binder handle to object that should be notified of the binder's
  // death.
  std::map<sp<IBinder>, sp<DeathRecipient>> death_recipients_;

  DISALLOW_COPY_AND_ASSIGN(RealBinderWrapper);
};

}  // namespace android

#endif  // SYSTEM_CORE_LIBBINDER_WRAPPER_REAL_BINDER_WRAPPER_H_
