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
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>

#include <cutils/log.h>
#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/PermissionCache.h>
#include <utils/String16.h>

#include <keystore/IKeystoreService.h>
#include <keystore/keystore.h> // For error code
#include <gatekeeper/password_handle.h> // for password_handle_t
#include <hardware/gatekeeper.h>
#include <hardware/hw_auth_token.h>

namespace android {

static const String16 KEYGUARD_PERMISSION("android.permission.ACCESS_KEYGUARD_SECURE_STORAGE");
static const String16 DUMP_PERMISSION("android.permission.DUMP");

class GateKeeperProxy : public BnGateKeeperService {
public:
    GateKeeperProxy() {
        int ret = hw_get_module_by_class(GATEKEEPER_HARDWARE_MODULE_ID, NULL, &module);
        if (ret < 0)
            LOG_ALWAYS_FATAL_IF(ret < 0, "Unable to find GateKeeper HAL");
        ret = gatekeeper_open(module, &device);
        if (ret < 0)
            LOG_ALWAYS_FATAL_IF(ret < 0, "Unable to open GateKeeper HAL");
    }

    virtual ~GateKeeperProxy() {
        gatekeeper_close(device);
    }

    void store_sid(uint32_t uid, uint64_t sid) {
        char filename[21];
        sprintf(filename, "%u", uid);
        int fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            ALOGW("could not open file: %s: %s", filename, strerror(errno));
            return;
        }
        write(fd, &sid, sizeof(sid));
        close(fd);
    }

    void maybe_store_sid(uint32_t uid, uint64_t sid) {
        char filename[21];
        sprintf(filename, "%u", uid);
        if (access(filename, F_OK) == -1) {
            store_sid(uid, sid);
        }
    }

    uint64_t read_sid(uint32_t uid) {
        char filename[21];
        uint64_t sid;
        sprintf(filename, "%u", uid);
        int fd = open(filename, O_RDONLY);
        if (fd < 0) return 0;
        read(fd, &sid, sizeof(sid));
        return sid;
    }

    virtual status_t enroll(uint32_t uid,
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

        // need a desired password to enroll
        if (desired_password_length == 0) return -EINVAL;
        int ret = device->enroll(device, uid,
                current_password_handle, current_password_handle_length,
                current_password, current_password_length,
                desired_password, desired_password_length,
                enrolled_password_handle, enrolled_password_handle_length);
        if (ret >= 0) {
            gatekeeper::password_handle_t *handle =
                    reinterpret_cast<gatekeeper::password_handle_t *>(*enrolled_password_handle);
            store_sid(uid, handle->user_id);
            return NO_ERROR;
        }
        return UNKNOWN_ERROR;
    }

    virtual status_t verify(uint32_t uid,
            const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length) {
        uint8_t *auth_token;
        uint32_t auth_token_length;
        return verifyChallenge(uid, 0, enrolled_password_handle, enrolled_password_handle_length,
                provided_password, provided_password_length,
                &auth_token, &auth_token_length);
    }

    virtual status_t verifyChallenge(uint32_t uid, uint64_t challenge,
            const uint8_t *enrolled_password_handle, uint32_t enrolled_password_handle_length,
            const uint8_t *provided_password, uint32_t provided_password_length,
            uint8_t **auth_token, uint32_t *auth_token_length) {
        IPCThreadState* ipc = IPCThreadState::self();
        const int calling_pid = ipc->getCallingPid();
        const int calling_uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(KEYGUARD_PERMISSION, calling_pid, calling_uid)) {
            return PERMISSION_DENIED;
        }

        // can't verify if we're missing either param
        if ((enrolled_password_handle_length | provided_password_length) == 0)
            return -EINVAL;

        int ret = device->verify(device, uid, challenge,
                enrolled_password_handle, enrolled_password_handle_length,
                provided_password, provided_password_length, auth_token, auth_token_length);

        if (ret >= 0 && *auth_token != NULL && *auth_token_length > 0) {
            // TODO: cache service?
            sp<IServiceManager> sm = defaultServiceManager();
            sp<IBinder> binder = sm->getService(String16("android.security.keystore"));
            sp<IKeystoreService> service = interface_cast<IKeystoreService>(binder);
            if (service != NULL) {
                status_t ret = service->addAuthToken(*auth_token, *auth_token_length);
                if (ret != ResponseCode::NO_ERROR) {
                    ALOGE("Falure sending auth token to KeyStore: %d", ret);
                }
            } else {
                ALOGE("Unable to communicate with KeyStore");
            }
        }

        if (ret >= 0) {
            maybe_store_sid(uid, reinterpret_cast<const gatekeeper::password_handle_t *>(
                        enrolled_password_handle)->user_id);
            return NO_ERROR;
        }

        return UNKNOWN_ERROR;
    }

    virtual uint64_t getSecureUserId(uint32_t uid) {
        return read_sid(uid);
    }

    virtual status_t dump(int fd, const Vector<String16> &) {
        IPCThreadState* ipc = IPCThreadState::self();
        const int pid = ipc->getCallingPid();
        const int uid = ipc->getCallingUid();
        if (!PermissionCache::checkPermission(DUMP_PERMISSION, pid, uid)) {
            return PERMISSION_DENIED;
        }

        if (device == NULL) {
            const char *result = "Device not available";
            write(fd, result, strlen(result) + 1);
        } else {
            const char *result = "OK";
            write(fd, result, strlen(result) + 1);
        }

        return NO_ERROR;
    }

private:
    gatekeeper_device_t *device;
    const hw_module_t *module;
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
