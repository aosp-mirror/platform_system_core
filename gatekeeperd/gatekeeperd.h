/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <aidl/android/hardware/gatekeeper/IGatekeeper.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <android/service/gatekeeper/BnGateKeeperService.h>
#include <gatekeeper/GateKeeperResponse.h>

using ::android::hardware::gatekeeper::V1_0::IGatekeeper;
using AidlIGatekeeper = ::aidl::android::hardware::gatekeeper::IGatekeeper;
using ::android::binder::Status;
using ::android::service::gatekeeper::BnGateKeeperService;
using GKResponse = ::android::service::gatekeeper::GateKeeperResponse;

namespace android {

class GateKeeperProxy : public BnGateKeeperService {
  public:
    GateKeeperProxy();

    virtual ~GateKeeperProxy() {}

    void store_sid(uint32_t userId, uint64_t sid);

    void clear_state_if_needed();

    bool mark_cold_boot();

    void maybe_store_sid(uint32_t userId, uint64_t sid);

    uint64_t read_sid(uint32_t userId);

    void clear_sid(uint32_t userId);

    // This should only be called on userIds being passed to the GateKeeper HAL. It ensures that
    // secure storage shared across a GSI image and a host image will not overlap.
    Status adjust_userId(uint32_t userId, uint32_t* hw_userId);

#define GK_ERROR *gkResponse = GKResponse::error(), Status::ok()

    Status enroll(int32_t userId, const std::optional<std::vector<uint8_t>>& currentPasswordHandle,
                  const std::optional<std::vector<uint8_t>>& currentPassword,
                  const std::vector<uint8_t>& desiredPassword, GKResponse* gkResponse) override;

    Status verify(int32_t userId, const ::std::vector<uint8_t>& enrolledPasswordHandle,
                  const ::std::vector<uint8_t>& providedPassword, GKResponse* gkResponse) override;

    Status verifyChallenge(int32_t userId, int64_t challenge,
                           const std::vector<uint8_t>& enrolledPasswordHandle,
                           const std::vector<uint8_t>& providedPassword,
                           GKResponse* gkResponse) override;

    Status getSecureUserId(int32_t userId, int64_t* sid) override;

    Status clearSecureUserId(int32_t userId) override;

    Status reportDeviceSetupComplete() override;

    status_t dump(int fd, const Vector<String16>&) override;

  private:
    // AIDL gatekeeper service.
    std::shared_ptr<AidlIGatekeeper> aidl_hw_device;
    // HIDL gatekeeper service.
    sp<IGatekeeper> hw_device;

    bool clear_state_if_needed_done;
    bool is_running_gsi;
};
}  // namespace android
