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

#include <aidl/android/hardware/security/sharedsecret/BnSharedSecret.h>
#include <aidl/android/hardware/security/sharedsecret/SharedSecretParameters.h>

#include <trusty_keymaster/TrustyKeymaster.h>

namespace aidl::android::hardware::security::sharedsecret::trusty {

class TrustySharedSecret : public BnSharedSecret {
  public:
    explicit TrustySharedSecret(std::shared_ptr<::keymaster::TrustyKeymaster> impl)
        : impl_(std::move(impl)) {}
    ~TrustySharedSecret() = default;

    ::ndk::ScopedAStatus getSharedSecretParameters(SharedSecretParameters* params) override;
    ::ndk::ScopedAStatus computeSharedSecret(const std::vector<SharedSecretParameters>& params,
                                             std::vector<uint8_t>* sharingCheck) override;

  private:
    std::shared_ptr<::keymaster::TrustyKeymaster> impl_;
};
}  // namespace aidl::android::hardware::security::sharedsecret::trusty
