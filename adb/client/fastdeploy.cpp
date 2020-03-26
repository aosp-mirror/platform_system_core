/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "fastdeploy.h"

#include <string.h>
#include <algorithm>
#include <array>
#include <memory>

#include "android-base/file.h"
#include "android-base/strings.h"
#include "androidfw/ResourceTypes.h"
#include "androidfw/ZipFileRO.h"
#include "client/file_sync_client.h"
#include "commandline.h"
#include "deployagent.inc"        // Generated include via build rule.
#include "deployagentscript.inc"  // Generated include via build rule.
#include "fastdeploy/deploypatchgenerator/deploy_patch_generator.h"
#include "fastdeploy/deploypatchgenerator/patch_utils.h"
#include "fastdeploy/proto/ApkEntry.pb.h"
#include "fastdeploycallbacks.h"
#include "sysdeps.h"

#include "adb_utils.h"

static constexpr long kRequiredAgentVersion = 0x00000003;

static constexpr int kPackageMissing = 3;
static constexpr int kInvalidAgentVersion = 4;

static constexpr const char* kDeviceAgentFile = "/data/local/tmp/deployagent.jar";
static constexpr const char* kDeviceAgentScript = "/data/local/tmp/deployagent";

static constexpr bool g_verbose_timings = false;
static FastDeploy_AgentUpdateStrategy g_agent_update_strategy =
        FastDeploy_AgentUpdateDifferentVersion;

using APKMetaData = com::android::fastdeploy::APKMetaData;

namespace {

struct TimeReporter {
    TimeReporter(const char* label) : label_(label) {}
    ~TimeReporter() {
        if (g_verbose_timings) {
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start_);
            fprintf(stderr, "%s finished in %lldms\n", label_,
                    static_cast<long long>(duration.count()));
        }
    }

  private:
    const char* label_;
    std::chrono::steady_clock::time_point start_ = std::chrono::steady_clock::now();
};
#define REPORT_FUNC_TIME() TimeReporter reporter(__func__)

struct FileDeleter {
    FileDeleter(const char* path) : path_(path) {}
    ~FileDeleter() { adb_unlink(path_); }

  private:
    const char* const path_;
};

}  // namespace

int get_device_api_level() {
    static const int api_level = [] {
        REPORT_FUNC_TIME();
        std::vector<char> sdk_version_output_buffer;
        std::vector<char> sdk_version_error_buffer;
        int api_level = -1;

        int status_code =
                capture_shell_command("getprop ro.build.version.sdk", &sdk_version_output_buffer,
                                      &sdk_version_error_buffer);
        if (status_code == 0 && sdk_version_output_buffer.size() > 0) {
            api_level = strtol((char*)sdk_version_output_buffer.data(), nullptr, 10);
        }

        return api_level;
    }();
    return api_level;
}

void fastdeploy_set_agent_update_strategy(FastDeploy_AgentUpdateStrategy agent_update_strategy) {
    g_agent_update_strategy = agent_update_strategy;
}

static void push_to_device(const void* data, size_t byte_count, const char* dst, bool sync) {
    std::vector<const char*> srcs;
    TemporaryFile tf;
    android::base::WriteFully(tf.fd, data, byte_count);
    srcs.push_back(tf.path);
    // On Windows, the file needs to be flushed before pushing to device,
    // but can't be removed until after the push.
    unix_close(tf.release());

    if (!do_sync_push(srcs, dst, sync, true)) {
        error_exit("Failed to push fastdeploy agent to device.");
    }
}

static bool deploy_agent(bool check_time_stamps) {
    REPORT_FUNC_TIME();

    push_to_device(kDeployAgent, sizeof(kDeployAgent), kDeviceAgentFile, check_time_stamps);
    push_to_device(kDeployAgentScript, sizeof(kDeployAgentScript), kDeviceAgentScript,
                   check_time_stamps);

    // on windows the shell script might have lost execute permission
    // so need to set this explicitly
    const char* kChmodCommandPattern = "chmod 777 %s";
    std::string chmod_command =
            android::base::StringPrintf(kChmodCommandPattern, kDeviceAgentScript);
    int ret = send_shell_command(chmod_command);
    if (ret != 0) {
        error_exit("Error executing %s returncode: %d", chmod_command.c_str(), ret);
    }

    return true;
}

static std::string get_string_from_utf16(const char16_t* input, int input_len) {
    ssize_t utf8_length = utf16_to_utf8_length(input, input_len);
    if (utf8_length <= 0) {
        return {};
    }
    std::string utf8;
    utf8.resize(utf8_length);
    utf16_to_utf8(input, input_len, &*utf8.begin(), utf8_length + 1);
    return utf8;
}

static std::string get_package_name_from_apk(const char* apk_path) {
#undef open
    std::unique_ptr<android::ZipFileRO> zip_file((android::ZipFileRO::open)(apk_path));
#define open ___xxx_unix_open
    if (zip_file == nullptr) {
        perror_exit("Could not open %s", apk_path);
    }
    android::ZipEntryRO entry = zip_file->findEntryByName("AndroidManifest.xml");
    if (entry == nullptr) {
        error_exit("Could not find AndroidManifest.xml inside %s", apk_path);
    }
    uint32_t manifest_len = 0;
    if (!zip_file->getEntryInfo(entry, NULL, &manifest_len, NULL, NULL, NULL, NULL)) {
        error_exit("Could not read AndroidManifest.xml inside %s", apk_path);
    }
    std::vector<char> manifest_data(manifest_len);
    if (!zip_file->uncompressEntry(entry, manifest_data.data(), manifest_len)) {
        error_exit("Could not uncompress AndroidManifest.xml inside %s", apk_path);
    }
    android::ResXMLTree tree;
    android::status_t setto_status = tree.setTo(manifest_data.data(), manifest_len, true);
    if (setto_status != android::OK) {
        error_exit("Could not parse AndroidManifest.xml inside %s", apk_path);
    }
    android::ResXMLParser::event_code_t code;
    while ((code = tree.next()) != android::ResXMLParser::BAD_DOCUMENT &&
           code != android::ResXMLParser::END_DOCUMENT) {
        switch (code) {
            case android::ResXMLParser::START_TAG: {
                size_t element_name_length;
                const char16_t* element_name = tree.getElementName(&element_name_length);
                if (element_name == nullptr) {
                    continue;
                }
                std::u16string element_name_string(element_name, element_name_length);
                if (element_name_string == u"manifest") {
                    for (size_t i = 0; i < tree.getAttributeCount(); i++) {
                        size_t attribute_name_length;
                        const char16_t* attribute_name_text =
                                tree.getAttributeName(i, &attribute_name_length);
                        if (attribute_name_text == nullptr) {
                            continue;
                        }
                        std::u16string attribute_name_string(attribute_name_text,
                                                             attribute_name_length);
                        if (attribute_name_string == u"package") {
                            size_t attribute_value_length;
                            const char16_t* attribute_value_text =
                                    tree.getAttributeStringValue(i, &attribute_value_length);
                            if (attribute_value_text == nullptr) {
                                continue;
                            }
                            return get_string_from_utf16(attribute_value_text,
                                                         attribute_value_length);
                        }
                    }
                }
                break;
            }
            default:
                break;
        }
    }
    error_exit("Could not find package name tag in AndroidManifest.xml inside %s", apk_path);
}

static long parse_agent_version(const std::vector<char>& version_buffer) {
    long version = -1;
    if (!version_buffer.empty()) {
        version = strtol((char*)version_buffer.data(), NULL, 16);
    }
    return version;
}

static void update_agent_if_necessary() {
    switch (g_agent_update_strategy) {
        case FastDeploy_AgentUpdateAlways:
            deploy_agent(/*check_time_stamps=*/false);
            break;
        case FastDeploy_AgentUpdateNewerTimeStamp:
            deploy_agent(/*check_time_stamps=*/true);
            break;
        default:
            break;
    }
}

std::optional<APKMetaData> extract_metadata(const char* apk_path) {
    // Update agent if there is a command line argument forcing to do so.
    update_agent_if_necessary();

    REPORT_FUNC_TIME();

    std::string package_name = get_package_name_from_apk(apk_path);

    // Dump apk command checks the required vs current agent version and if they match then returns
    // the APK dump for package. Doing this in a single call saves round-trip and agent launch time.
    constexpr const char* kAgentDumpCommandPattern = "/data/local/tmp/deployagent dump %ld %s";
    std::string dump_command = android::base::StringPrintf(
            kAgentDumpCommandPattern, kRequiredAgentVersion, package_name.c_str());

    std::vector<char> dump_out_buffer;
    std::vector<char> dump_error_buffer;
    int returnCode =
            capture_shell_command(dump_command.c_str(), &dump_out_buffer, &dump_error_buffer);
    if (returnCode >= kInvalidAgentVersion) {
        // Agent has wrong version or missing.
        long agent_version = parse_agent_version(dump_out_buffer);
        if (agent_version < 0) {
            printf("Could not detect agent on device, deploying\n");
        } else {
            printf("Device agent version is (%ld), (%ld) is required, re-deploying\n",
                   agent_version, kRequiredAgentVersion);
        }
        deploy_agent(/*check_time_stamps=*/false);

        // Retry with new agent.
        dump_out_buffer.clear();
        dump_error_buffer.clear();
        returnCode =
                capture_shell_command(dump_command.c_str(), &dump_out_buffer, &dump_error_buffer);
    }
    if (returnCode != 0) {
        if (returnCode == kInvalidAgentVersion) {
            long agent_version = parse_agent_version(dump_out_buffer);
            error_exit(
                    "After update agent version remains incorrect! Expected %ld but version is %ld",
                    kRequiredAgentVersion, agent_version);
        }
        if (returnCode == kPackageMissing) {
            fprintf(stderr, "Package %s not found, falling back to install\n",
                    package_name.c_str());
            return {};
        }
        fprintf(stderr, "Executing %s returned %d\n", dump_command.c_str(), returnCode);
        fprintf(stderr, "%*s\n", int(dump_error_buffer.size()), dump_error_buffer.data());
        error_exit("Aborting");
    }

    com::android::fastdeploy::APKDump dump;
    if (!dump.ParseFromArray(dump_out_buffer.data(), dump_out_buffer.size())) {
        fprintf(stderr, "Can't parse output of %s\n", dump_command.c_str());
        error_exit("Aborting");
    }

    return PatchUtils::GetDeviceAPKMetaData(dump);
}

unique_fd install_patch(int argc, const char** argv) {
    REPORT_FUNC_TIME();
    constexpr char kAgentApplyServicePattern[] = "shell:/data/local/tmp/deployagent apply - -pm %s";

    std::vector<unsigned char> apply_output_buffer;
    std::vector<unsigned char> apply_error_buffer;
    std::string argsString;

    bool rSwitchPresent = false;
    for (int i = 0; i < argc; i++) {
        argsString.append(argv[i]);
        argsString.append(" ");
        if (!strcmp(argv[i], "-r")) {
            rSwitchPresent = true;
        }
    }
    if (!rSwitchPresent) {
        argsString.append("-r");
    }

    std::string error;
    std::string apply_patch_service_string =
            android::base::StringPrintf(kAgentApplyServicePattern, argsString.c_str());
    unique_fd fd{adb_connect(apply_patch_service_string, &error)};
    if (fd < 0) {
        error_exit("Executing %s returned %s", apply_patch_service_string.c_str(), error.c_str());
    }
    return fd;
}

unique_fd apply_patch_on_device(const char* output_path) {
    REPORT_FUNC_TIME();
    constexpr char kAgentApplyServicePattern[] = "shell:/data/local/tmp/deployagent apply - -o %s";

    std::string error;
    std::string apply_patch_service_string =
            android::base::StringPrintf(kAgentApplyServicePattern, output_path);
    unique_fd fd{adb_connect(apply_patch_service_string, &error)};
    if (fd < 0) {
        error_exit("Executing %s returned %s", apply_patch_service_string.c_str(), error.c_str());
    }
    return fd;
}

static void create_patch(const char* apk_path, APKMetaData metadata, borrowed_fd patch_fd) {
    REPORT_FUNC_TIME();
    DeployPatchGenerator generator(/*is_verbose=*/false);
    bool success = generator.CreatePatch(apk_path, std::move(metadata), patch_fd);
    if (!success) {
        error_exit("Failed to create patch for %s", apk_path);
    }
}

int stream_patch(const char* apk_path, APKMetaData metadata, unique_fd patch_fd) {
    create_patch(apk_path, std::move(metadata), patch_fd);

    REPORT_FUNC_TIME();
    return read_and_dump(patch_fd.get());
}
