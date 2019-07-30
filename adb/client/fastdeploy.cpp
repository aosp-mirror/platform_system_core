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
#include "fastdeploycallbacks.h"
#include "sysdeps.h"

#include "adb_utils.h"

static constexpr long kRequiredAgentVersion = 0x00000002;

static constexpr const char* kDeviceAgentPath = "/data/local/tmp/";
static constexpr const char* kDeviceAgentFile = "/data/local/tmp/deployagent.jar";
static constexpr const char* kDeviceAgentScript = "/data/local/tmp/deployagent";

static bool g_use_localagent = false;

long get_agent_version() {
    std::vector<char> versionOutputBuffer;
    std::vector<char> versionErrorBuffer;

    int statusCode = capture_shell_command("/data/local/tmp/deployagent version",
                                           &versionOutputBuffer, &versionErrorBuffer);
    long version = -1;

    if (statusCode == 0 && versionOutputBuffer.size() > 0) {
        version = strtol((char*)versionOutputBuffer.data(), NULL, 16);
    }

    return version;
}

int get_device_api_level() {
    std::vector<char> sdkVersionOutputBuffer;
    std::vector<char> sdkVersionErrorBuffer;
    int api_level = -1;

    int statusCode = capture_shell_command("getprop ro.build.version.sdk", &sdkVersionOutputBuffer,
                                           &sdkVersionErrorBuffer);
    if (statusCode == 0 && sdkVersionOutputBuffer.size() > 0) {
        api_level = strtol((char*)sdkVersionOutputBuffer.data(), NULL, 10);
    }

    return api_level;
}

void fastdeploy_set_local_agent(bool use_localagent) {
    g_use_localagent = use_localagent;
}

static bool deploy_agent(bool checkTimeStamps) {
    std::vector<const char*> srcs;
    // TODO: Deploy agent from bin2c directly instead of writing to disk first.
    TemporaryFile tempAgent;
    android::base::WriteFully(tempAgent.fd, kDeployAgent, sizeof(kDeployAgent));
    srcs.push_back(tempAgent.path);
    if (!do_sync_push(srcs, kDeviceAgentFile, checkTimeStamps)) {
        error_exit("Failed to push fastdeploy agent to device.");
    }
    srcs.clear();
    // TODO: Deploy agent from bin2c directly instead of writing to disk first.
    TemporaryFile tempAgentScript;
    android::base::WriteFully(tempAgentScript.fd, kDeployAgentScript, sizeof(kDeployAgentScript));
    srcs.push_back(tempAgentScript.path);
    if (!do_sync_push(srcs, kDeviceAgentScript, checkTimeStamps)) {
        error_exit("Failed to push fastdeploy agent script to device.");
    }
    srcs.clear();
    // on windows the shell script might have lost execute permission
    // so need to set this explicitly
    const char* kChmodCommandPattern = "chmod 777 %s";
    std::string chmodCommand =
            android::base::StringPrintf(kChmodCommandPattern, kDeviceAgentScript);
    int ret = send_shell_command(chmodCommand);
    if (ret != 0) {
        error_exit("Error executing %s returncode: %d", chmodCommand.c_str(), ret);
    }

    return true;
}

void update_agent(FastDeploy_AgentUpdateStrategy agentUpdateStrategy) {
    long agent_version = get_agent_version();
    switch (agentUpdateStrategy) {
        case FastDeploy_AgentUpdateAlways:
            deploy_agent(false);
            break;
        case FastDeploy_AgentUpdateNewerTimeStamp:
            deploy_agent(true);
            break;
        case FastDeploy_AgentUpdateDifferentVersion:
            if (agent_version != kRequiredAgentVersion) {
                if (agent_version < 0) {
                    printf("Could not detect agent on device, deploying\n");
                } else {
                    printf("Device agent version is (%ld), (%ld) is required, re-deploying\n",
                           agent_version, kRequiredAgentVersion);
                }
                deploy_agent(false);
            }
            break;
    }

    agent_version = get_agent_version();
    if (agent_version != kRequiredAgentVersion) {
        error_exit("After update agent version remains incorrect! Expected %ld but version is %ld",
                   kRequiredAgentVersion, agent_version);
    }
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

static std::string get_packagename_from_apk(const char* apkPath) {
#undef open
    std::unique_ptr<android::ZipFileRO> zipFile(android::ZipFileRO::open(apkPath));
#define open ___xxx_unix_open
    if (zipFile == nullptr) {
        perror_exit("Could not open %s", apkPath);
    }
    android::ZipEntryRO entry = zipFile->findEntryByName("AndroidManifest.xml");
    if (entry == nullptr) {
        error_exit("Could not find AndroidManifest.xml inside %s", apkPath);
    }
    uint32_t manifest_len = 0;
    if (!zipFile->getEntryInfo(entry, NULL, &manifest_len, NULL, NULL, NULL, NULL)) {
        error_exit("Could not read AndroidManifest.xml inside %s", apkPath);
    }
    std::vector<char> manifest_data(manifest_len);
    if (!zipFile->uncompressEntry(entry, manifest_data.data(), manifest_len)) {
        error_exit("Could not uncompress AndroidManifest.xml inside %s", apkPath);
    }
    android::ResXMLTree tree;
    android::status_t setto_status = tree.setTo(manifest_data.data(), manifest_len, true);
    if (setto_status != android::OK) {
        error_exit("Could not parse AndroidManifest.xml inside %s", apkPath);
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
    error_exit("Could not find package name tag in AndroidManifest.xml inside %s", apkPath);
}

void extract_metadata(const char* apkPath, FILE* outputFp) {
    std::string packageName = get_packagename_from_apk(apkPath);
    const char* kAgentExtractCommandPattern = "/data/local/tmp/deployagent extract %s";
    std::string extractCommand =
            android::base::StringPrintf(kAgentExtractCommandPattern, packageName.c_str());

    std::vector<char> extractErrorBuffer;
    DeployAgentFileCallback cb(outputFp, &extractErrorBuffer);
    int returnCode = send_shell_command(extractCommand, false, &cb);
    if (returnCode != 0) {
        fprintf(stderr, "Executing %s returned %d\n", extractCommand.c_str(), returnCode);
        fprintf(stderr, "%*s\n", int(extractErrorBuffer.size()), extractErrorBuffer.data());
        error_exit("Aborting");
    }
}

void create_patch(const char* apkPath, const char* metadataPath, const char* patchPath) {
    DeployPatchGenerator generator(false);
    unique_fd patchFd(adb_open(patchPath, O_WRONLY | O_CREAT | O_CLOEXEC));
    if (patchFd < 0) {
        perror_exit("adb: failed to create %s", patchPath);
    }
    bool success = generator.CreatePatch(apkPath, metadataPath, patchFd);
    if (!success) {
        error_exit("Failed to create patch for %s", apkPath);
    }
}

std::string get_patch_path(const char* apkPath) {
    std::string packageName = get_packagename_from_apk(apkPath);
    std::string patchDevicePath =
            android::base::StringPrintf("%s%s.patch", kDeviceAgentPath, packageName.c_str());
    return patchDevicePath;
}

void apply_patch_on_device(const char* apkPath, const char* patchPath, const char* outputPath) {
    const std::string kAgentApplyCommandPattern = "/data/local/tmp/deployagent apply %s %s -o %s";
    std::string packageName = get_packagename_from_apk(apkPath);
    std::string patchDevicePath = get_patch_path(apkPath);

    std::vector<const char*> srcs = {patchPath};
    bool push_ok = do_sync_push(srcs, patchDevicePath.c_str(), false);
    if (!push_ok) {
        error_exit("Error pushing %s to %s returned", patchPath, patchDevicePath.c_str());
    }

    std::string applyPatchCommand =
            android::base::StringPrintf(kAgentApplyCommandPattern.c_str(), packageName.c_str(),
                                        patchDevicePath.c_str(), outputPath);

    int returnCode = send_shell_command(applyPatchCommand);
    if (returnCode != 0) {
        error_exit("Executing %s returned %d", applyPatchCommand.c_str(), returnCode);
    }
}

void install_patch(const char* apkPath, const char* patchPath, int argc, const char** argv) {
    const std::string kAgentApplyCommandPattern = "/data/local/tmp/deployagent apply %s %s -pm %s";
    std::string packageName = get_packagename_from_apk(apkPath);

    std::string patchDevicePath =
            android::base::StringPrintf("%s%s.patch", kDeviceAgentPath, packageName.c_str());

    std::vector<const char*> srcs{patchPath};
    bool push_ok = do_sync_push(srcs, patchDevicePath.c_str(), false);
    if (!push_ok) {
        error_exit("Error pushing %s to %s returned", patchPath, patchDevicePath.c_str());
    }

    std::vector<unsigned char> applyOutputBuffer;
    std::vector<unsigned char> applyErrorBuffer;
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

    std::string applyPatchCommand =
            android::base::StringPrintf(kAgentApplyCommandPattern.c_str(), packageName.c_str(),
                                        patchDevicePath.c_str(), argsString.c_str());
    int returnCode = send_shell_command(applyPatchCommand);
    if (returnCode != 0) {
        error_exit("Executing %s returned %d", applyPatchCommand.c_str(), returnCode);
    }
}

bool find_package(const char* apkPath) {
    const std::string findCommand =
            "/data/local/tmp/deployagent find " + get_packagename_from_apk(apkPath);
    return !send_shell_command(findCommand);
}
