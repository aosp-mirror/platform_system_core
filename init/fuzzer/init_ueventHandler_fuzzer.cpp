/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <devices.h>
#include <firmware_handler.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <modalias_handler.h>
#include <sys/stat.h>
#include <util.h>
#include <fstream>

using namespace android;
using namespace android::init;
constexpr int32_t kMaxBytes = 100;
constexpr int32_t kMaxSize = 1000;
constexpr int32_t kMinSize = 1;

/*'HandleUevent' prefixes the path with '/sys' and hence this is required to point
 * to'/data/local/tmp' dir.*/
const std::string kPath = "/../data/local/tmp/";
const std::string kPathPrefix = "/..";

void MakeFile(FuzzedDataProvider* fdp, std::string s) {
    std::ofstream out;
    out.open(s, std::ios::binary | std::ofstream::trunc);
    for (int32_t idx = 0; idx < fdp->ConsumeIntegralInRange(kMinSize, kMaxSize); ++idx) {
        out << fdp->ConsumeRandomLengthString(kMaxBytes) << "\n";
    }
    out.close();
}

void CreateDir(std::string Directory, FuzzedDataProvider* fdp) {
    std::string tmp = Directory.substr(kPathPrefix.length());
    mkdir_recursive(android::base::Dirname(tmp.c_str()),
                    S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    MakeFile(fdp, tmp + "/data");
    MakeFile(fdp, tmp + "/loading");
}

std::string SelectRandomString(FuzzedDataProvider* fdp, std::string s) {
    if (fdp->ConsumeBool()) {
        if (fdp->ConsumeBool()) {
            return fdp->ConsumeRandomLengthString(kMaxBytes);
        } else {
            return s;
        }
    }
    return "";
}

Uevent CreateUevent(FuzzedDataProvider* fdp) {
    Uevent uevent;
    uevent.action = SelectRandomString(fdp, "add");
    uevent.subsystem = SelectRandomString(fdp, "firmware");
    uevent.path = SelectRandomString(fdp, kPath + fdp->ConsumeRandomLengthString(kMaxBytes));
    uevent.firmware = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxBytes) : "";
    uevent.partition_name = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxBytes) : "";
    uevent.device_name = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxBytes) : "";
    uevent.modalias = fdp->ConsumeBool() ? fdp->ConsumeRandomLengthString(kMaxBytes) : "";
    uevent.partition_num = fdp->ConsumeIntegral<int32_t>();
    uevent.major = fdp->ConsumeIntegral<int32_t>();
    uevent.minor = fdp->ConsumeIntegral<int32_t>();
    return uevent;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    while (fdp.remaining_bytes()) {
        auto invoke_uevent_handler_fuzzer = fdp.PickValueInArray<const std::function<void()>>({
                [&]() {
                    std::vector<std::string> modalias_vector;
                    for (size_t idx = 0;
                         idx < fdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idx) {
                        modalias_vector.push_back(fdp.ConsumeRandomLengthString(kMaxBytes));
                    }
                    ModaliasHandler modalias_handler = ModaliasHandler(modalias_vector);
                    modalias_handler.HandleUevent(CreateUevent(&fdp));
                },
                [&]() {
                    std::vector<ExternalFirmwareHandler> external_handlers;
                    std::vector<std::string> firmware_directories;
                    for (size_t idx = 0;
                         idx < fdp.ConsumeIntegralInRange<size_t>(kMinSize, kMaxSize); ++idx) {
                        std::string devPath = fdp.ConsumeRandomLengthString(kMaxBytes);
                        uid_t uid = fdp.ConsumeIntegral<uid_t>();
                        gid_t gid = fdp.ConsumeIntegral<gid_t>();
                        std::string handlerPath = fdp.ConsumeRandomLengthString(kMaxBytes);
                        ExternalFirmwareHandler externalFirmwareHandler =
                                ExternalFirmwareHandler(devPath, uid, gid, handlerPath);
                        external_handlers.push_back(externalFirmwareHandler);
                        firmware_directories.push_back(fdp.ConsumeRandomLengthString(kMaxBytes));
                    }
                    FirmwareHandler firmware_handler =
                            FirmwareHandler(firmware_directories, external_handlers);
                    Uevent uevent = CreateUevent(&fdp);
                    if (fdp.ConsumeBool() && uevent.path.size() != 0 &&
                        uevent.path.find(kPath) == 0) {
                        CreateDir(uevent.path, &fdp);
                        firmware_handler.HandleUevent(uevent);
                        std::string s = uevent.path.substr(kPathPrefix.length());
                        remove(s.c_str());
                    } else {
                        firmware_handler.HandleUevent(uevent);
                    }
                },
        });
        invoke_uevent_handler_fuzzer();
    }
    return 0;
}
