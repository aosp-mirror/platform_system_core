/*
 * Copyright 2021, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <aidl/android/hardware/security/secureclock/BnSecureClock.h>
#include <aidl/android/hardware/security/secureclock/TimeStampToken.h>
#include <aidl/android/hardware/security/secureclock/Timestamp.h>

#include <trusty_keymaster/TrustyKeymaster.h>

namespace aidl::android::hardware::security::secureclock::trusty {

class TrustySecureClock : public BnSecureClock {
  public:
    explicit TrustySecureClock(std::shared_ptr<::keymaster::TrustyKeymaster> impl)
        : impl_(std::move(impl)) {}
    ~TrustySecureClock() = default;
    ::ndk::ScopedAStatus generateTimeStamp(int64_t challenge, TimeStampToken* token) override;

  private:
    std::shared_ptr<::keymaster::TrustyKeymaster> impl_;
};

}  // namespace aidl::android::hardware::security::secureclock::trusty
