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

#define LOG_TAG "gatekeeperd"

#include <android/service/gatekeeper/BnGateKeeperService.h>
#include <gatekeeper/GateKeeperResponse.h>

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <memory>

#include <KeyMintUtils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android/binder_ibinder.h>
#include <android/binder_manager.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <gatekeeper/password_handle.h>  // for password_handle_t
#include <hardware/hw_auth_token.h>
#include <libgsi/libgsi.h>
#include <log/log.h>
#include <utils/String16.h>

#include <aidl/android/hardware/gatekeeper/IGatekeeper.h>
#include <aidl/android/hardware/security/keymint/HardwareAuthToken.h>
#include <aidl/android/security/authorization/IKeystoreAuthorization.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <hidl/HidlSupport.h>

using android::sp;
using android::hardware::Return;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using android::hardware::gatekeeper::V1_0::IGatekeeper;

using AidlGatekeeperEnrollResp = aidl::android::hardware::gatekeeper::GatekeeperEnrollResponse;
using AidlGatekeeperVerifyResp = aidl::android::hardware::gatekeeper::GatekeeperVerifyResponse;
using AidlIGatekeeper = aidl::android::hardware::gatekeeper::IGatekeeper;

using ::android::binder::Status;
using ::android::service::gatekeeper::BnGateKeeperService;
using GKResponse = ::android::service::gatekeeper::GateKeeperResponse;
using GKResponseCode = ::android::service::gatekeeper::ResponseCode;
using ::aidl::android::hardware::security::keymint::HardwareAuthenticatorType;
using ::aidl::android::hardware::security::keymint::HardwareAuthToken;
using ::aidl::android::hardware::security::keymint::km_utils::authToken2AidlVec;
using ::aidl::android::security::authorization::IKeystoreAuthorization;

namespace android {

static const String16 KEYGUARD_PERMISSION("android.permission.ACCESS_KEYGUARD_SECURE_STORAGE");
static const String16 DUMP_PERMISSION("android.permission.DUMP");
constexpr const char gatekeeperServiceName[] = "android.hardware.gatekeeper.IGatekeeper/default";

class GateKeeperProxy : public BnGateKeeperService {
  public:
    GateKeeperProxy() {
        clear_state_if_needed_done = false;
        hw_device = IGatekeeper::getService();
        ::ndk::SpAIBinder ks2Binder(AServiceManager_getService(gatekeeperServiceName));
        aidl_hw_device = AidlIGatekeeper::fromBinder(ks2Binder);
        is_running_gsi = android::base::GetBoolProperty(android::gsi::kGsiBootedProp, false);

        if (!aidl_hw_device && !hw_device) {
            LOG(ERROR) << "Could not find Gatekeeper device, which makes me very sad.";
        }
    }

    virtual ~GateKeeperProxy() {}

    void store_sid(uint32_t userId, uint64_t sid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", userId);
        int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            ALOGE("could not open file: %s: %s", filename, strerror(errno));
            return;
        }
        write(fd, &sid, sizeof(sid));
        close(fd);
    }

    void clear_state_if_needed() {
        if (clear_state_if_needed_done) {
            return;
        }

        if (mark_cold_boot() && !is_running_gsi) {
            ALOGI("cold boot: clearing state");
            if (aidl_hw_device) {
                aidl_hw_device->deleteAllUsers();
            } else if (hw_device) {
                hw_device->deleteAllUsers([](const GatekeeperResponse&) {});
            }
        }

        clear_state_if_needed_done = true;
    }

    bool mark_cold_boot() {
        const char* filename = ".coldboot";
        if (access(filename, F_OK) == -1) {
            int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
            if (fd < 0) {
                ALOGE("could not open file: %s : %s", filename, strerror(errno));
                return false;
            }
            close(fd);
            return true;
        }
        return false;
    }

    void maybe_store_sid(uint32_t userId, uint64_t sid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", userId);
        if (access(filename, F_OK) == -1) {
            store_sid(userId, sid);
        }
    }

    uint64_t read_sid(uint32_t userId) {
        char filename[21];
        uint64_t sid;
        snprintf(filename, sizeof(filename), "%u", userId);
        int fd = open(filename, O_RDONLY);
        if (fd < 0) return 0;
        read(fd, &sid, sizeof(sid));
        close(fd);
        return sid;
    }

    void clear_sid(uint32_t userId) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", userId);
        if (remove(filename) < 0) {
            ALOGE("%s: could not remove file [%s], attempting 0 write", __func__, strerror(errno));
            store_sid(userId, 0);
        }
    }

    // This should only be called on userIds being passed to the GateKeeper HAL. It ensures that
    // secure storage shared across a GSI image and a host image will not overlap.
    uint32_t adjust_userId(uint32_t userId) {
        static constexpr uint32_t kGsiOffset = 1000000;
        CHECK(userId < kGsiOffset);
        CHECK((aidl_hw_device != nullptr) || (hw_device != nullptr));
        if (is_running_gsi) {
            return userId + kGsiOffset;
        }
        return userId;
    }

#define GK_ERROR *gkResponse = GKResponse::error(), Status::ok()

    Status enroll(int32_t userId, const std::optional<std::vector<uint8_t>>& currentPasswordHandle,
                  const std::optional<std::vector<uint8_t>>& currentPassword,
                  const std::vector<uint8_t>& desiredPassword, GKResponse* gkResponse) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return GK_ERROR;
        }

        // Make sure to clear any state from before factory reset as soon as a credential is
        // enrolled (which may happen during device setup).
        clear_state_if_needed();

        // need a desired password to enroll
        if (desiredPassword.size() == 0) return GK_ERROR;

        if (!aidl_hw_device && !hw_device) {
            LOG(ERROR) << "has no HAL to talk to";
            return GK_ERROR;
        }

        android::hardware::hidl_vec<uint8_t> curPwdHandle;
        android::hardware::hidl_vec<uint8_t> curPwd;

        if (currentPasswordHandle && currentPassword) {
            if (hw_device) {
                // Hidl Implementations expects passwordHandle to be in
                // gatekeeper::password_handle_t format.
                if (currentPasswordHandle->size() != sizeof(gatekeeper::password_handle_t)) {
                    LOG(INFO) << "Password handle has wrong length";
                    return GK_ERROR;
                }
            }
            curPwdHandle.setToExternal(const_cast<uint8_t*>(currentPasswordHandle->data()),
                                       currentPasswordHandle->size());
            curPwd.setToExternal(const_cast<uint8_t*>(currentPassword->data()),
                                 currentPassword->size());
        }

        android::hardware::hidl_vec<uint8_t> newPwd;
        newPwd.setToExternal(const_cast<uint8_t*>(desiredPassword.data()), desiredPassword.size());

        uint32_t hw_userId = adjust_userId(userId);
        uint64_t secureUserId = 0;
        if (aidl_hw_device) {
            // AIDL gatekeeper service
            AidlGatekeeperEnrollResp rsp;
            auto result = aidl_hw_device->enroll(hw_userId, curPwdHandle, curPwd, newPwd, &rsp);
            if (!result.isOk()) {
                LOG(ERROR) << "enroll transaction failed";
                return GK_ERROR;
            }
            if (rsp.statusCode >= AidlIGatekeeper::STATUS_OK) {
                *gkResponse = GKResponse::ok({rsp.data.begin(), rsp.data.end()});
                secureUserId = static_cast<uint64_t>(rsp.secureUserId);
            } else if (rsp.statusCode == AidlIGatekeeper::ERROR_RETRY_TIMEOUT &&
                       rsp.timeoutMs > 0) {
                *gkResponse = GKResponse::retry(rsp.timeoutMs);
            } else {
                *gkResponse = GKResponse::error();
            }
        } else if (hw_device) {
            // HIDL gatekeeper service
            Return<void> hwRes = hw_device->enroll(
                hw_userId, curPwdHandle, curPwd, newPwd,
                [&gkResponse](const GatekeeperResponse& rsp) {
                    if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                        *gkResponse = GKResponse::ok({rsp.data.begin(), rsp.data.end()});
                    } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT &&
                               rsp.timeout > 0) {
                        *gkResponse = GKResponse::retry(rsp.timeout);
                    } else {
                        *gkResponse = GKResponse::error();
                    }
                });
            if (!hwRes.isOk()) {
                LOG(ERROR) << "enroll transaction failed";
                return GK_ERROR;
            }
            if (gkResponse->response_code() == GKResponseCode::OK) {
                if (gkResponse->payload().size() != sizeof(gatekeeper::password_handle_t)) {
                    LOG(ERROR) << "HAL returned password handle of invalid length "
                               << gkResponse->payload().size();
                    return GK_ERROR;
                }

                const gatekeeper::password_handle_t* handle =
                    reinterpret_cast<const gatekeeper::password_handle_t*>(
                        gkResponse->payload().data());
                secureUserId = handle->user_id;
            }
        }

        if (gkResponse->response_code() == GKResponseCode::OK && !gkResponse->should_reenroll()) {
            store_sid(userId, secureUserId);

            GKResponse verifyResponse;
            // immediately verify this password so we don't ask the user to enter it again
            // if they just created it.
            auto status = verify(userId, gkResponse->payload(), desiredPassword, &verifyResponse);
            if (!status.isOk() || verifyResponse.response_code() != GKResponseCode::OK) {
                LOG(ERROR) << "Failed to verify password after enrolling";
            }
        }

        return Status::ok();
    }

    Status verify(int32_t userId, const ::std::vector<uint8_t>& enrolledPasswordHandle,
                  const ::std::vector<uint8_t>& providedPassword, GKResponse* gkResponse) override {
        return verifyChallenge(userId, 0 /* challenge */, enrolledPasswordHandle, providedPassword,
                               gkResponse);
    }

    Status verifyChallenge(int32_t userId, int64_t challenge,
                           const std::vector<uint8_t>& enrolledPasswordHandle,
                           const std::vector<uint8_t>& providedPassword,
                           GKResponse* gkResponse) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return GK_ERROR;
        }

        // can't verify if we're missing either param
        if (enrolledPasswordHandle.size() == 0 || providedPassword.size() == 0) return GK_ERROR;

        if (!aidl_hw_device && !hw_device) {
            LOG(ERROR) << "has no HAL to talk to";
            return GK_ERROR;
        }

        if (hw_device) {
            // Hidl Implementations expects passwordHandle to be in gatekeeper::password_handle_t
            if (enrolledPasswordHandle.size() != sizeof(gatekeeper::password_handle_t)) {
                LOG(INFO) << "Password handle has wrong length";
                return GK_ERROR;
            }
        }

        uint32_t hw_userId = adjust_userId(userId);
        android::hardware::hidl_vec<uint8_t> curPwdHandle;
        curPwdHandle.setToExternal(const_cast<uint8_t*>(enrolledPasswordHandle.data()),
                                   enrolledPasswordHandle.size());
        android::hardware::hidl_vec<uint8_t> enteredPwd;
        enteredPwd.setToExternal(const_cast<uint8_t*>(providedPassword.data()),
                                 providedPassword.size());

        uint64_t secureUserId = 0;
        if (aidl_hw_device) {
            // AIDL gatekeeper service
            AidlGatekeeperVerifyResp rsp;
            auto result =
                aidl_hw_device->verify(hw_userId, challenge, curPwdHandle, enteredPwd, &rsp);
            if (!result.isOk()) {
                LOG(ERROR) << "verify transaction failed";
                return GK_ERROR;
            }
            if (rsp.statusCode >= AidlIGatekeeper::STATUS_OK) {
                secureUserId = rsp.hardwareAuthToken.userId;
                // Serialize HardwareAuthToken to a vector as hw_auth_token_t.
                *gkResponse = GKResponse::ok(authToken2AidlVec(rsp.hardwareAuthToken),
                                             rsp.statusCode ==
                                                 AidlIGatekeeper::STATUS_REENROLL /* reenroll */);
            } else if (rsp.statusCode == AidlIGatekeeper::ERROR_RETRY_TIMEOUT) {
                *gkResponse = GKResponse::retry(rsp.timeoutMs);
            } else {
                *gkResponse = GKResponse::error();
            }
        } else if (hw_device) {
            // HIDL gatekeeper service
            Return<void> hwRes = hw_device->verify(
                hw_userId, challenge, curPwdHandle, enteredPwd,
                [&gkResponse](const GatekeeperResponse& rsp) {
                    if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                        *gkResponse = GKResponse::ok(
                            {rsp.data.begin(), rsp.data.end()},
                            rsp.code == GatekeeperStatusCode::STATUS_REENROLL /* reenroll */);
                    } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT) {
                        *gkResponse = GKResponse::retry(rsp.timeout);
                    } else {
                        *gkResponse = GKResponse::error();
                    }
                });

            if (!hwRes.isOk()) {
                LOG(ERROR) << "verify transaction failed";
                return GK_ERROR;
            }
            const gatekeeper::password_handle_t* handle =
                reinterpret_cast<const gatekeeper::password_handle_t*>(
                    enrolledPasswordHandle.data());
            secureUserId = handle->user_id;
        }

        if (gkResponse->response_code() == GKResponseCode::OK) {
            if (gkResponse->payload().size() != 0) {
                // try to connect to IKeystoreAuthorization AIDL service first.
                AIBinder* authzAIBinder =
                        AServiceManager_getService("android.security.authorization");
                ::ndk::SpAIBinder authzBinder(authzAIBinder);
                auto authzService = IKeystoreAuthorization::fromBinder(authzBinder);
                if (authzService) {
                    if (gkResponse->payload().size() != sizeof(hw_auth_token_t)) {
                        LOG(ERROR) << "Incorrect size of AuthToken payload.";
                        return GK_ERROR;
                    }

                    const hw_auth_token_t* hwAuthToken =
                            reinterpret_cast<const hw_auth_token_t*>(gkResponse->payload().data());
                    HardwareAuthToken authToken;

                    authToken.timestamp.milliSeconds = betoh64(hwAuthToken->timestamp);
                    authToken.challenge = hwAuthToken->challenge;
                    authToken.userId = hwAuthToken->user_id;
                    authToken.authenticatorId = hwAuthToken->authenticator_id;
                    authToken.authenticatorType = static_cast<HardwareAuthenticatorType>(
                            betoh32(hwAuthToken->authenticator_type));
                    authToken.mac.assign(&hwAuthToken->hmac[0], &hwAuthToken->hmac[32]);
                    auto result = authzService->addAuthToken(authToken);
                    if (!result.isOk()) {
                        LOG(ERROR) << "Failure in sending AuthToken to AuthorizationService.";
                        return GK_ERROR;
                    }
                } else {
                    LOG(ERROR) << "Cannot deliver auth token. Unable to communicate with "
                                  "Keystore.";
                    return GK_ERROR;
                }
            }

            maybe_store_sid(userId, secureUserId);
        }

        return Status::ok();
    }

    Status getSecureUserId(int32_t userId, int64_t* sid) override {
        *sid = read_sid(userId);
        return Status::ok();
    }

    Status clearSecureUserId(int32_t userId) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            ALOGE("%s: permission denied for [%d:%d]", __func__, calling_pid, calling_uid);
            return Status::ok();
        }
        clear_sid(userId);

        uint32_t hw_userId = adjust_userId(userId);
        if (aidl_hw_device) {
            aidl_hw_device->deleteUser(hw_userId);
        } else if (hw_device) {
            hw_device->deleteUser(hw_userId, [](const GatekeeperResponse&) {});
        }
        return Status::ok();
    }

    Status reportDeviceSetupComplete() override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            ALOGE("%s: permission denied for [%d:%d]", __func__, calling_pid, calling_uid);
            return Status::ok();
        }

        clear_state_if_needed();
        return Status::ok();
    }

    status_t dump(int fd, const Vector<String16>&) override {
        IPCThreadState* ipc = IPCThreadState::self();
        const int pid = ipc->getCallingPid();
        const int uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(DUMP_PERMISSION, pid, uid)) {
            return PERMISSION_DENIED;
        }

        if (aidl_hw_device == nullptr && hw_device == nullptr) {
            const char* result = "Device not available";
            write(fd, result, strlen(result) + 1);
        } else {
            const char* result = "OK";
            write(fd, result, strlen(result) + 1);
        }

        return OK;
    }

  private:
    // AIDL gatekeeper service.
    std::shared_ptr<AidlIGatekeeper> aidl_hw_device;
    // HIDL gatekeeper service.
    sp<IGatekeeper> hw_device;

    bool clear_state_if_needed_done;
    bool is_running_gsi;
};
}  // namespace android

int main(int argc, char* argv[]) {
    ALOGI("Starting gatekeeperd...");
    if (argc < 2) {
        ALOGE("A directory must be specified!");
        return 1;
    }
    if (chdir(argv[1]) == -1) {
        ALOGE("chdir: %s: %s", argv[1], strerror(errno));
        return 1;
    }

    android::sp<android::IServiceManager> sm = android::defaultServiceManager();
    android::sp<android::GateKeeperProxy> proxy = new android::GateKeeperProxy();
    android::status_t ret =
        sm->addService(android::String16("android.service.gatekeeper.IGateKeeperService"), proxy);
    if (ret != android::OK) {
        ALOGE("Couldn't register binder service!");
        return -1;
    }

    /*
     * We're the only thread in existence, so we're just going to process
     * Binder transaction as a single-threaded program.
     */
    android::IPCThreadState::self()->joinThreadPool();
    return 0;
}
