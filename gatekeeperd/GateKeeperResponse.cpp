/*
**
** Copyright 2019, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#define LOG_TAG "gatekeeperd"

#include <gatekeeper/GateKeeperResponse.h>

#include <binder/Parcel.h>

#include <android-base/logging.h>

namespace android {
namespace service {
namespace gatekeeper {

status_t GateKeeperResponse::readFromParcel(const Parcel* in) {
    if (in == nullptr) {
        LOG(ERROR) << "readFromParcel got null in parameter";
        return BAD_VALUE;
    }
    timeout_ = 0;
    should_reenroll_ = false;
    payload_ = {};
    response_code_ = ResponseCode(in->readInt32());
    if (response_code_ == ResponseCode::OK) {
        should_reenroll_ = in->readInt32();
        ssize_t length = in->readInt32();
        if (length > 0) {
            length = in->readInt32();
            const uint8_t* buf = reinterpret_cast<const uint8_t*>(in->readInplace(length));
            if (buf == nullptr) {
                LOG(ERROR) << "readInplace returned null buffer for length " << length;
                return BAD_VALUE;
            }
            payload_.resize(length);
            std::copy(buf, buf + length, payload_.data());
        }
    } else if (response_code_ == ResponseCode::RETRY) {
        timeout_ = in->readInt32();
    }
    return NO_ERROR;
}
status_t GateKeeperResponse::writeToParcel(Parcel* out) const {
    if (out == nullptr) {
        LOG(ERROR) << "writeToParcel got null out parameter";
        return BAD_VALUE;
    }
    out->writeInt32(int32_t(response_code_));
    if (response_code_ == ResponseCode::OK) {
        out->writeInt32(should_reenroll_);
        out->writeInt32(payload_.size());
        if (payload_.size() != 0) {
            out->writeInt32(payload_.size());
            uint8_t* buf = reinterpret_cast<uint8_t*>(out->writeInplace(payload_.size()));
            if (buf == nullptr) {
                LOG(ERROR) << "writeInplace returned null buffer for length " << payload_.size();
                return BAD_VALUE;
            }
            std::copy(payload_.begin(), payload_.end(), buf);
        }
    } else if (response_code_ == ResponseCode::RETRY) {
        out->writeInt32(timeout_);
    }
    return NO_ERROR;
}

}  // namespace gatekeeper
}  // namespace service
}  // namespace android
