/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adb_wifi.h"

#include <fstream>
#include <random>
#include <thread>

#include <adb/crypto/key.h>
#include <adb/crypto/x509_generator.h>
#include <android-base/file.h>
#include <android-base/parsenetaddress.h>
#include "client/pairing/pairing_client.h"

#include "adb_auth.h"
#include "adb_known_hosts.pb.h"
#include "adb_utils.h"
#include "client/adb_client.h"
#include "sysdeps.h"

using adbwifi::pairing::PairingClient;
using namespace adb::crypto;

struct PairingResultWaiter {
    std::mutex mutex_;
    std::condition_variable cv_;
    std::optional<bool> is_valid_;
    PeerInfo peer_info_;

    static void OnResult(const PeerInfo* peer_info, void* opaque) {
        CHECK(opaque);
        auto* p = reinterpret_cast<PairingResultWaiter*>(opaque);
        {
            std::lock_guard<std::mutex> lock(p->mutex_);
            if (peer_info) {
                memcpy(&(p->peer_info_), peer_info, sizeof(PeerInfo));
            }
            p->is_valid_ = (peer_info != nullptr);
        }
        p->cv_.notify_one();
    }
};  // PairingResultWaiter

void adb_wifi_init() {}

static std::vector<uint8_t> stringToUint8(const std::string& str) {
    auto* p8 = reinterpret_cast<const uint8_t*>(str.data());
    return std::vector<uint8_t>(p8, p8 + str.length());
}

// Tries to replace the |old_file| with |new_file|.
// On success, then |old_file| has been removed and replaced with the
// contents of |new_file|, |new_file| will be removed, and only |old_file| will
// remain.
// On failure, both files will be unchanged.
// |new_file| must exist, but |old_file| does not need to exist.
bool SafeReplaceFile(std::string_view old_file, std::string_view new_file) {
    std::string to_be_deleted(old_file);
    to_be_deleted += ".tbd";

    bool old_renamed = true;
    if (adb_rename(old_file.data(), to_be_deleted.c_str()) != 0) {
        // Don't exit here. This is not necessarily an error, because |old_file|
        // may not exist.
        PLOG(INFO) << "Failed to rename " << old_file;
        old_renamed = false;
    }

    if (adb_rename(new_file.data(), old_file.data()) != 0) {
        PLOG(ERROR) << "Unable to rename file (" << new_file << " => " << old_file << ")";
        if (old_renamed) {
            // Rename the .tbd file back to it's original name
            adb_rename(to_be_deleted.c_str(), old_file.data());
        }
        return false;
    }

    adb_unlink(to_be_deleted.c_str());
    return true;
}

static std::string get_user_known_hosts_path() {
    return adb_get_android_dir_path() + OS_PATH_SEPARATOR + "adb_known_hosts.pb";
}

bool load_known_hosts_from_file(const std::string& path, adb::proto::AdbKnownHosts& known_hosts) {
    // Check for file existence.
    struct stat buf;
    if (stat(path.c_str(), &buf) == -1) {
        LOG(INFO) << "Known hosts file [" << path << "] does not exist...";
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        PLOG(ERROR) << "Unable to open [" << path << "].";
        return false;
    }

    if (!known_hosts.ParseFromIstream(&file)) {
        PLOG(ERROR) << "Failed to parse [" << path << "]. Deleting it as it may be corrupted.";
        adb_unlink(path.c_str());
        return false;
    }

    return true;
}

static bool write_known_host_to_file(std::string& known_host) {
    std::string path = get_user_known_hosts_path();
    if (path.empty()) {
        PLOG(ERROR) << "Error getting user known hosts filename";
        return false;
    }

    adb::proto::AdbKnownHosts known_hosts;
    load_known_hosts_from_file(path, known_hosts);
    auto* host_info = known_hosts.add_host_infos();
    host_info->set_guid(known_host);

    std::unique_ptr<TemporaryFile> temp_file(new TemporaryFile(adb_get_android_dir_path()));
    if (temp_file->fd == -1) {
        PLOG(ERROR) << "Failed to open [" << temp_file->path << "] for writing";
        return false;
    }

    if (!known_hosts.SerializeToFileDescriptor(temp_file->fd)) {
        LOG(ERROR) << "Unable to write out adb_knowns_hosts";
        return false;
    }
    temp_file->DoNotRemove();
    std::string temp_file_name(temp_file->path);
    temp_file.reset();

    // Replace the existing adb_known_hosts with the new one
    if (!SafeReplaceFile(path, temp_file_name.c_str())) {
        LOG(ERROR) << "Failed to replace old adb_known_hosts";
        adb_unlink(temp_file_name.c_str());
        return false;
    }
    chmod(path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP);

    return true;
}

bool adb_wifi_is_known_host(const std::string& host) {
    std::string path = get_user_known_hosts_path();
    if (path.empty()) {
        PLOG(ERROR) << "Error getting user known hosts filename";
        return false;
    }

    adb::proto::AdbKnownHosts known_hosts;
    if (!load_known_hosts_from_file(path, known_hosts)) {
        return false;
    }

    for (const auto& host_info : known_hosts.host_infos()) {
        if (host == host_info.guid()) {
            return true;
        }
    }
    return false;
}

void adb_wifi_pair_device(const std::string& host, const std::string& password,
                          std::string& response) {
    // Check the address for a valid address and port.
    std::string parsed_host;
    std::string err;
    int port = -1;
    if (!android::base::ParseNetAddress(host, &parsed_host, &port, nullptr, &err)) {
        response = "Failed to parse address for pairing: " + err;
        return;
    }
    if (port <= 0 || port > 65535) {
        response = "Invalid port while parsing address [" + host + "]";
        return;
    }

    auto priv_key = adb_auth_get_user_privkey();
    auto x509_cert = GenerateX509Certificate(priv_key.get());
    if (!x509_cert) {
        LOG(ERROR) << "Unable to create X509 certificate for pairing";
        return;
    }
    auto cert_str = X509ToPEMString(x509_cert.get());
    auto priv_str = Key::ToPEMString(priv_key.get());

    // Send our public key on pairing success
    PeerInfo system_info = {};
    system_info.type = ADB_RSA_PUB_KEY;
    std::string public_key = adb_auth_get_userkey();
    CHECK_LE(public_key.size(), sizeof(system_info.data) - 1);  // -1 for null byte
    memcpy(system_info.data, public_key.data(), public_key.size());

    auto pswd8 = stringToUint8(password);
    auto cert8 = stringToUint8(cert_str);
    auto priv8 = stringToUint8(priv_str);

    auto client = PairingClient::Create(pswd8, system_info, cert8, priv8);
    if (client == nullptr) {
        response = "Failed: unable to create pairing client.";
        return;
    }

    PairingResultWaiter waiter;
    std::unique_lock<std::mutex> lock(waiter.mutex_);
    if (!client->Start(host, waiter.OnResult, &waiter)) {
        response = "Failed: Unable to start pairing client.";
        return;
    }
    waiter.cv_.wait(lock, [&]() { return waiter.is_valid_.has_value(); });
    if (!*(waiter.is_valid_)) {
        response = "Failed: Wrong password or connection was dropped.";
        return;
    }

    if (waiter.peer_info_.type != ADB_DEVICE_GUID) {
        response = "Failed: Successfully paired but server returned unknown response=";
        response += waiter.peer_info_.type;
        return;
    }

    std::string device_guid = reinterpret_cast<const char*>(waiter.peer_info_.data);
    response = "Successfully paired to " + host + " [guid=" + device_guid + "]";

    // Write to adb_known_hosts
    write_known_host_to_file(device_guid);
    // Try to auto-connect.
    adb_secure_connect_by_service_name(device_guid.c_str());
}
