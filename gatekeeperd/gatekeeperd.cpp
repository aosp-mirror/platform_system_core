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

#include "IGateKeeperService.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <memory>

#include <android/security/IKeystoreService.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <gatekeeper/password_handle.h> // for password_handle_t
#include <hardware/gatekeeper.h>
#include <hardware/hw_auth_token.h>
#include <keystore/keystore.h> // For error code
#include <keystore/keystore_return_types.h>
#include <log/log.h>
#include <utils/Log.h>
#include <utils/String16.h>

#include "SoftGateKeeperDevice.h"

#include <hidl/HidlSupport.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

using android::sp;
using android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;
using android::hardware::Return;

namespace android {

static const String16 KEYGUARD_PERMISSION("android.permission.ACCESS_KEYGUARD_SECURE_STORAGE");
static const String16 DUMP_PERMISSION("android.permission.DUMP");

class GateKeeperProxy : public BnGateKeeperService {
public:
    GateKeeperProxy() {
        clear_state_if_needed_done = false;
        hw_device = IGatekeeper::getService();

        if (hw_device == nullptr) {
            ALOGW("falling back to software GateKeeper");
            soft_device.reset(new SoftGateKeeperDevice());
        }
    }

    virtual ~GateKeeperProxy() {
    }

    void store_sid(uint32_t uid, uint64_t sid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", uid);
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

        if (mark_cold_boot()) {
            ALOGI("cold boot: clearing state");
            if (hw_device != nullptr) {
                hw_device->deleteAllUsers([](const GatekeeperResponse &){});
            }
        }

        clear_state_if_needed_done = true;
    }

    bool mark_cold_boot() {
        const char *filename = ".coldboot";
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

    void maybe_store_sid(uint32_t uid, uint64_t sid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", uid);
        if (access(filename, F_OK) == -1) {
            store_sid(uid, sid);
        }
    }

    uint64_t read_sid(uint32_t uid) {
        char filename[21];
        uint64_t sid;
        snprintf(filename, sizeof(filename), "%u", uid);
        int fd = open(filename, O_RDONLY);
        if (fd < 0) return 0;
        read(fd, &sid, sizeof(sid));
        close(fd);
        return sid;
    }

    void clear_sid(uint32_t uid) {
        char filename[21];
        snprintf(filename, sizeof(filename), "%u", uid);
        if (remove(filename) < 0) {
            ALOGE("%s: could not remove file [%s], attempting 0 write", __func__, strerror(errno));
            store_sid(uid, 0);
        }
    }

    virtual int enroll(uint32_t uid,
            const uint8_t *current_password_handle, uint32_t current_password_handle_length,
            const uint8_t *current_password, uint32_t current_password_length,
            const uint8_t *desired_password, uint32_t desired_password_length,
            uint8_t **enrolled_password_handle, uint32_t *enrolled_password_handle_length) {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return PERMISSION_DENIED;
        }

        // Make sure to clear any state from before factory reset as soon as a credential is
        // enrolled (which may happen during device setup).
        clear_state_if_needed();

        // need a desired password to enroll
        if (desired_password_length == 0) return -EINVAL;

        int ret;
        if (hw_device != nullptr) {
            const gatekeeper::password_handle_t *handle =
                    reinterpret_cast<const gatekeeper::password_handle_t *>(current_password_handle);

            if (handle != NULL && handle->version != 0 && !handle->hardware_backed) {
                // handle is being re-enrolled from a software version. HAL probably won't accept
                // the handle as valid, so we nullify it and enroll from scratch
                current_password_handle = NULL;
                current_password_handle_length = 0;
                current_password = NULL;
                current_password_length = 0;
            }

            android::hardware::hidl_vec<uint8_t> curPwdHandle;
            curPwdHandle.setToExternal(const_cast<uint8_t*>(current_password_handle),
                                       current_password_handle_length);
            android::hardware::hidl_vec<uint8_t> curPwd;
            curPwd.setToExternal(const_cast<uint8_t*>(current_password),
                                 current_password_length);
            android::hardware::hidl_vec<uint8_t> newPwd;
            newPwd.setToExternal(const_cast<uint8_t*>(desired_password),
                                 desired_password_length);

            Return<void> hwRes = hw_device->enroll(uid, curPwdHandle, curPwd, newPwd,
                              [&ret, enrolled_password_handle, enrolled_password_handle_length]
                                   (const GatekeeperResponse &rsp) {
                ret = static_cast<int>(rsp.code); // propagate errors
                if (rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                    if (enrolled_password_handle != nullptr &&
                        enrolled_password_handle_length != nullptr) {
                        *enrolled_password_handle = new uint8_t[rsp.data.size()];
                        *enrolled_password_handle_length = rsp.data.size();
                        memcpy(*enrolled_password_handle, rsp.data.data(),
                               *enrolled_password_handle_length);
                    }
                    ret = 0; // all success states are reported as 0
                } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT && rsp.timeout > 0) {
                    ret = rsp.timeout;
                }
            });
            if (!hwRes.isOk()) {
                ALOGE("enroll transaction failed\n");
                ret = -1;
            }
        } else {
            ret = soft_device->enroll(uid,
                    current_password_handle, current_password_handle_length,
                    current_password, current_password_length,
                    desired_password, desired_password_length,
                    enrolled_password_handle, enrolled_password_handle_length);
        }

        if (ret == GATEKEEPER_RESPONSE_OK && (*enrolled_password_handle == nullptr ||
            *enrolled_password_handle_length != sizeof(password_handle_t))) {
            ret = GATEKEEPER_RESPONSE_ERROR;
            ALOGE("HAL: password_handle=%p size_of_handle=%" PRIu32 "\n",
                  *enrolled_password_handle, *enrolled_password_handle_length);
        }

        if (ret == GATEKEEPER_RESPONSE_OK) {
            gatekeeper::password_handle_t *handle =
                    reinterpret_cast<gatekeeper::password_handle_t *>(*enrolled_password_handle);
            store_sid(uid, handle->user_id);
            bool rr;

            // immediately verify this password so we don't ask the user to enter it again
            // if they just created it.
            verify(uid, *enrolled_password_handle, sizeof(password_handle_t), desired_password,
                    desired_password_length, &rr);
        }

        return ret;
    }

    virtual int verify(uint32_t uid,
            const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length, bool *request_reenroll) {
        uint8_t *auth_token;
        uint32_t auth_token_length;
        return verifyChallenge(uid, 0, enrolled_password_handle, enrolled_password_handle_length,
                provided_password, provided_password_length,
                &auth_token, &auth_token_length, request_reenroll);
    }

    virtual int verifyChallenge(uint32_t uid, uint64_t challenge,
            const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length,
            uint8_t **auth_token, uint32_t *auth_token_length, bool *request_reenroll) {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return PERMISSION_DENIED;
        }

        // can't verify if we're missing either param
        if ((enrolled_password_handle_length | provided_password_length) == 0)
            return -EINVAL;

        int ret;
        if (hw_device != nullptr) {
            const gatekeeper::password_handle_t *handle =
                    reinterpret_cast<const gatekeeper::password_handle_t *>(enrolled_password_handle);
            // handle version 0 does not have hardware backed flag, and thus cannot be upgraded to
            // a HAL if there was none before
            if (handle->version == 0 || handle->hardware_backed) {
                android::hardware::hidl_vec<uint8_t> curPwdHandle;
                curPwdHandle.setToExternal(const_cast<uint8_t*>(enrolled_password_handle),
                                           enrolled_password_handle_length);
                android::hardware::hidl_vec<uint8_t> enteredPwd;
                enteredPwd.setToExternal(const_cast<uint8_t*>(provided_password),
                                         provided_password_length);
                Return<void> hwRes = hw_device->verify(uid, challenge, curPwdHandle, enteredPwd,
                                        [&ret, request_reenroll, auth_token, auth_token_length]
                                             (const GatekeeperResponse &rsp) {
                    ret = static_cast<int>(rsp.code); // propagate errors
                    if (auth_token != nullptr && auth_token_length != nullptr &&
                        rsp.code >= GatekeeperStatusCode::STATUS_OK) {
                        *auth_token = new uint8_t[rsp.data.size()];
                        *auth_token_length = rsp.data.size();
                        memcpy(*auth_token, rsp.data.data(), *auth_token_length);
                        if (request_reenroll != nullptr) {
                            *request_reenroll = (rsp.code == GatekeeperStatusCode::STATUS_REENROLL);
                        }
                        ret = 0; // all success states are reported as 0
                    } else if (rsp.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT &&
                               rsp.timeout > 0) {
                        ret = rsp.timeout;
                    }
                });
                if (!hwRes.isOk()) {
                    ALOGE("verify transaction failed\n");
                    ret = -1;
                }
            } else {
                // upgrade scenario, a HAL has been added to this device where there was none before
                SoftGateKeeperDevice soft_dev;
                ret = soft_dev.verify(uid, challenge,
                    enrolled_password_handle, enrolled_password_handle_length,
                    provided_password, provided_password_length, auth_token, auth_token_length,
                    request_reenroll);

                if (ret == 0) {
                    // success! re-enroll with HAL
                    *request_reenroll = true;
                }
            }
        } else {
            ret = soft_device->verify(uid, challenge,
                enrolled_password_handle, enrolled_password_handle_length,
                provided_password, provided_password_length, auth_token, auth_token_length,
                request_reenroll);
        }

        if (ret == 0 && *auth_token != NULL && *auth_token_length > 0) {
            // TODO: cache service?
            sp<IServiceManager> sm = defaultServiceManager();
            sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
            sp<security::IKeystoreService> service =
                interface_cast<security::IKeystoreService>(binder);
            if (service != NULL) {
                std::vector<uint8_t> auth_token_vector(*auth_token,
                                                       (*auth_token) + *auth_token_length);
                int result = 0;
                auto binder_result = service->addAuthToken(auth_token_vector, uid, &result);
                if (!binder_result.isOk() || !keystore::KeyStoreServiceReturnCode(result).isOk()) {
                    ALOGE("Failure sending auth token to KeyStore: %" PRId32, result);
                }
            } else {
                ALOGE("Unable to communicate with KeyStore");
            }
        }

        if (ret == 0) {
            maybe_store_sid(uid, reinterpret_cast<const gatekeeper::password_handle_t *>(
                        enrolled_password_handle)->user_id);
        }

        return ret;
    }

    virtual uint64_t getSecureUserId(uint32_t uid) { return read_sid(uid); }

    virtual void clearSecureUserId(uint32_t uid) {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            ALOGE("%s: permission denied for [%d:%d]", __func__, calling_pid, calling_uid);
            return;
        }
        clear_sid(uid);

        if (hw_device != nullptr) {
            hw_device->deleteUser(uid, [] (const GatekeeperResponse &){});
        }
    }

    virtual void reportDeviceSetupComplete() {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            ALOGE("%s: permission denied for [%d:%d]", __func__, calling_pid, calling_uid);
            return;
        }

        clear_state_if_needed();
    }

    virtual status_t dump(int fd, const Vector<String16> &) {
        IPCThreadState* ipc = IPCThreadState::self();
        const int pid = ipc->getCallingPid();
        const int uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(DUMP_PERMISSION, pid, uid)) {
            return PERMISSION_DENIED;
        }

        if (hw_device == NULL) {
            const char *result = "Device not available";
            write(fd, result, strlen(result) + 1);
        } else {
            const char *result = "OK";
            write(fd, result, strlen(result) + 1);
        }

        return NO_ERROR;
    }

private:
    sp<IGatekeeper> hw_device;
    std::unique_ptr<SoftGateKeeperDevice> soft_device;

    bool clear_state_if_needed_done;
};
}// namespace android

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
    android::status_t ret = sm->addService(
            android::String16("android.service.gatekeeper.IGateKeeperService"), proxy);
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
