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

#define LOG_TAG "fingerprintd"

#include <android/hardware/biometrics/fingerprint/2.1/types.h>
#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>
#include <android/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprintClientCallback.h>
#include <binder/IServiceManager.h>
#include <keystore/IKeystoreService.h>
#include <keystore/keystore.h> // for error codes
#include <utils/Log.h>

#include "FingerprintDaemonProxy.h"

namespace android {

using hardware::hidl_string;
using hardware::Return;
using hardware::biometrics::fingerprint::V2_1::FingerprintMsg;
using hardware::biometrics::fingerprint::V2_1::RequestStatus;
using hardware::biometrics::fingerprint::V2_1::FingerprintError;
using hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprintClientCallback;
using Type = hardware::biometrics::fingerprint::V2_1::FingerprintMsgType;
using IBiometricsFingerprint = hardware::biometrics::fingerprint::V2_1::IBiometricsFingerprint;

FingerprintDaemonProxy* FingerprintDaemonProxy::sInstance = nullptr;
static sp<IBiometricsFingerprint> gBFP = nullptr;
static sp<IBiometricsFingerprintClientCallback> gClientCallback = nullptr;

template <typename E>
constexpr typename std::underlying_type<E>::type to_native(E e) {
    return static_cast<typename std::underlying_type<E>::type>(e);
}

const ssize_t hw_auth_token_size = 69;

namespace hardware {

class BiometricsFingerprintClientCallback : public IBiometricsFingerprintClientCallback {
  public:
    BiometricsFingerprintClientCallback() {};
    virtual ~BiometricsFingerprintClientCallback() = default;
    Return<void> notify(const FingerprintMsg& msg) {
        FingerprintDaemonProxy::hal_notify_callback(msg);
        return Void();
    }
};

IBiometricsFingerprintClientCallback* HIDL_FETCH_IBiometricsFingerprintClientCallback(const char* /* name */) {
    return new BiometricsFingerprintClientCallback();
}

} // namespace hardware

FingerprintDaemonProxy::FingerprintDaemonProxy() : mCallback(nullptr) {

}

FingerprintDaemonProxy::~FingerprintDaemonProxy() {
    closeHal();
}

void FingerprintDaemonProxy::hal_notify_callback(const hardware::biometrics::fingerprint::V2_1::FingerprintMsg &msg) {
    FingerprintDaemonProxy* instance = FingerprintDaemonProxy::getInstance();
    const sp<IFingerprintDaemonCallback> callback = instance->mCallback;
    if (callback == nullptr) {
        ALOGE("Invalid callback object");
        return;
    }
    switch (msg.type) {
        case Type::ERROR:
            ALOGD("onError(%d)", msg.data.error);
            callback->onError(0, to_native(msg.data.error));
            break;
        case Type::ACQUIRED:
            ALOGD("onAcquired(%d)", msg.data.acquired.acquiredInfo);
            callback->onAcquired(0, to_native(msg.data.acquired.acquiredInfo));
            break;
        case Type::AUTHENTICATED:
            ALOGD("onAuthenticated(fid=%d, gid=%d)",
                    msg.data.authenticated.finger.fid,
                    msg.data.authenticated.finger.gid);
            if (msg.data.authenticated.finger.fid != 0) {
                const uint8_t* hat = reinterpret_cast<const uint8_t *>(&msg.data.authenticated.hat);
                instance->notifyKeystore(hat, sizeof(msg.data.authenticated.hat));
            }
            callback->onAuthenticated(0,
                    msg.data.authenticated.finger.fid,
                    msg.data.authenticated.finger.gid);
            break;
        case Type::TEMPLATE_ENROLLING:
            ALOGD("onEnrollResult(fid=%d, gid=%d, rem=%d)",
                    msg.data.enroll.finger.fid,
                    msg.data.enroll.finger.gid,
                    msg.data.enroll.samplesRemaining);
            callback->onEnrollResult(0,
                    msg.data.enroll.finger.fid,
                    msg.data.enroll.finger.gid,
                    msg.data.enroll.samplesRemaining);
            break;
        case Type::TEMPLATE_REMOVED:
            ALOGD("onRemove(fid=%d, gid=%d)",
                    msg.data.removed.finger.fid,
                    msg.data.removed.finger.gid);
            callback->onRemoved(0,
                    msg.data.removed.finger.fid,
                    msg.data.removed.finger.gid);
            break;
        case Type::TEMPLATE_ENUMERATING:
            ALOGD("onEnumerate(fid=%d, gid=%d, rem=%d)",
                    msg.data.enumerated.finger.fid,
                    msg.data.enumerated.finger.gid,
                    msg.data.enumerated.remainingTemplates);
            callback->onEnumerate(0,
                    msg.data.enumerated.finger.fid,
                    msg.data.enumerated.finger.gid,
                    msg.data.enumerated.remainingTemplates);
            break;
        default:
            ALOGE("invalid msg type: %d", msg.type);
            return;
    }
}

void FingerprintDaemonProxy::notifyKeystore(const uint8_t *auth_token, const size_t auth_token_length) {
    if (auth_token != nullptr && auth_token_length > 0) {
        // TODO: cache service?
        sp < IServiceManager > sm = defaultServiceManager();
        sp < IBinder > binder = sm->getService(String16("android.security.keystore"));
        sp < IKeystoreService > service = interface_cast < IKeystoreService > (binder);
        if (service != nullptr) {
            status_t ret = service->addAuthToken(auth_token, auth_token_length);
            if (ret != ResponseCode::NO_ERROR) {
                ALOGE("Falure sending auth token to KeyStore: %d", ret);
            }
        } else {
            ALOGE("Unable to communicate with KeyStore");
        }
    }
}

void FingerprintDaemonProxy::init(const sp<IFingerprintDaemonCallback>& callback) {
    if (mCallback != nullptr && IInterface::asBinder(callback) != IInterface::asBinder(mCallback)) {
        IInterface::asBinder(mCallback)->unlinkToDeath(this);
    }
    IInterface::asBinder(callback)->linkToDeath(this);
    mCallback = callback;
}

int32_t FingerprintDaemonProxy::enroll(const uint8_t* token, ssize_t tokenSize, int32_t groupId,
        int32_t timeout) {
    ALOG(LOG_VERBOSE, LOG_TAG, "enroll(gid=%d, timeout=%d)\n", groupId, timeout);
    if (tokenSize != hw_auth_token_size) {
        ALOG(LOG_VERBOSE, LOG_TAG, "enroll() : invalid token size %zd, expected %zd\n", tokenSize, hw_auth_token_size);
        return -1;
    }

    hardware::hidl_array<uint8_t, hw_auth_token_size> hat(token);
    Return<RequestStatus> ret = gBFP->enroll(hat, groupId, timeout);
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

uint64_t FingerprintDaemonProxy::preEnroll() {
    return gBFP->preEnroll();
}

int32_t FingerprintDaemonProxy::postEnroll() {
    Return<RequestStatus> ret = gBFP->postEnroll();
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

int32_t FingerprintDaemonProxy::stopEnrollment() {
    ALOG(LOG_VERBOSE, LOG_TAG, "stopEnrollment()\n");
    Return<RequestStatus> ret = gBFP->cancel();
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

int32_t FingerprintDaemonProxy::authenticate(uint64_t sessionId, uint32_t groupId) {
    ALOG(LOG_VERBOSE, LOG_TAG, "authenticate(sid=%" PRId64 ", gid=%d)\n", sessionId, groupId);
    Return<RequestStatus> ret = gBFP->authenticate(sessionId, groupId);
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

int32_t FingerprintDaemonProxy::stopAuthentication() {
    ALOG(LOG_VERBOSE, LOG_TAG, "stopAuthentication()\n");
    Return<RequestStatus> ret = gBFP->cancel();
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

int32_t FingerprintDaemonProxy::remove(int32_t fingerId, int32_t groupId) {
    ALOG(LOG_VERBOSE, LOG_TAG, "remove(fid=%d, gid=%d)\n", fingerId, groupId);
    Return<RequestStatus> ret = gBFP->remove(groupId, fingerId);
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

int32_t FingerprintDaemonProxy::enumerate() {
    ALOG(LOG_VERBOSE, LOG_TAG, "enumerate()\n");
    Return<RequestStatus> ret = gBFP->enumerate();
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

uint64_t FingerprintDaemonProxy::getAuthenticatorId() {
    return gBFP->getAuthenticatorId();
}

int32_t FingerprintDaemonProxy::setActiveGroup(int32_t groupId, const uint8_t* path,
        ssize_t pathlen) {
    if (pathlen >= PATH_MAX || pathlen <= 0) {
        ALOGE("Bad path length: %zd", pathlen);
        return -1;
    }
    hidl_string pathname;
    pathname.setToExternal(reinterpret_cast<const char*>(path), pathlen);
    ALOG(LOG_VERBOSE, LOG_TAG, "setActiveGroup(%d, %s, %zu)", groupId, pathname.c_str(), pathlen);
    Return<RequestStatus> ret = gBFP->setActiveGroup(groupId, pathname);
    if (!ret.getStatus().isOk()) {
        ALOGE("Unknown transport error");
        return -1;
    }

    RequestStatus status = ret;
    return to_native(status);
}

int64_t FingerprintDaemonProxy::openHal() {
    if (gBFP == nullptr) {
        // TODO(b/31632518)
        gBFP = IBiometricsFingerprint::getService("fingerprint");
        if(gBFP == nullptr) {
            ALOGE("Can't get service fingerprint");
            return 0;
        }
    }
    gClientCallback = hardware::HIDL_FETCH_IBiometricsFingerprintClientCallback(nullptr);
    gBFP->setNotify(gClientCallback);
    return reinterpret_cast<int64_t>(gBFP.get());
}

int32_t FingerprintDaemonProxy::closeHal() {
    // Obsolete, return 0 for compatibility reasons.
    return 0;
}

void FingerprintDaemonProxy::binderDied(const wp<IBinder>& who) {
    ALOGD("binder died");
    int err;
    if (0 != (err = closeHal())) {
        ALOGE("Can't close fingerprint device, error: %d", err);
    }
    if (IInterface::asBinder(mCallback) == who) {
        mCallback = nullptr;
    }
}

} // namespace android
