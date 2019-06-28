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

#ifndef GATEKEEPERD_INCLUDE_GATEKEEPER_GATEKEEPERRESPONSE_H_
#define GATEKEEPERD_INCLUDE_GATEKEEPER_GATEKEEPERRESPONSE_H_

#include <binder/Parcelable.h>

namespace android {
namespace service {
namespace gatekeeper {

enum class ResponseCode : int32_t {
    ERROR = -1,
    OK = 0,
    RETRY = 1,
};

class GateKeeperResponse : public ::android::Parcelable {
    GateKeeperResponse(ResponseCode response_code, int32_t timeout = 0,
                       std::vector<uint8_t> payload = {}, bool should_reenroll = false)
        : response_code_(response_code),
          timeout_(timeout),
          payload_(std::move(payload)),
          should_reenroll_(should_reenroll) {}

  public:
    GateKeeperResponse() = default;
    GateKeeperResponse(GateKeeperResponse&&) = default;
    GateKeeperResponse(const GateKeeperResponse&) = default;
    GateKeeperResponse& operator=(GateKeeperResponse&&) = default;

    static GateKeeperResponse error() { return GateKeeperResponse(ResponseCode::ERROR); }
    static GateKeeperResponse retry(int32_t timeout) {
        return GateKeeperResponse(ResponseCode::RETRY, timeout);
    }
    static GateKeeperResponse ok(std::vector<uint8_t> payload, bool reenroll = false) {
        return GateKeeperResponse(ResponseCode::OK, 0, std::move(payload), reenroll);
    }

    status_t readFromParcel(const Parcel* in) override;
    status_t writeToParcel(Parcel* out) const override;

    const std::vector<uint8_t>& payload() const { return payload_; }

    void payload(std::vector<uint8_t> payload) { payload_ = payload; }

    ResponseCode response_code() const { return response_code_; }

    void response_code(ResponseCode response_code) { response_code_ = response_code; }

    bool should_reenroll() const { return should_reenroll_; }

    void should_reenroll(bool should_reenroll) { should_reenroll_ = should_reenroll; }

    int32_t timeout() const { return timeout_; }

    void timeout(int32_t timeout) { timeout_ = timeout; }

  private:
    ResponseCode response_code_;
    int32_t timeout_;
    std::vector<uint8_t> payload_;
    bool should_reenroll_;
};

}  // namespace gatekeeper
}  // namespace service
}  // namespace android

#endif  // GATEKEEPERD_INCLUDE_GATEKEEPER_GATEKEEPERRESPONSE_H_
