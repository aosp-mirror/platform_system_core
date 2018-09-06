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

#include <libgen.h>
#include <algorithm>
#include <array>

#include "android-base/file.h"
#include "android-base/strings.h"
#include "client/file_sync_client.h"
#include "commandline.h"
#include "fastdeploy.h"
#include "fastdeploycallbacks.h"
#include "utils/String16.h"

static constexpr long kRequiredAgentVersion = 0x00000001;

static constexpr const char* kDeviceAgentPath = "/data/local/tmp/";

static bool use_localagent = false;

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

void fastdeploy_set_local_agent(bool set_use_localagent) {
    use_localagent = set_use_localagent;
}

// local_path - must start with a '/' and be relative to $ANDROID_PRODUCT_OUT
static bool get_agent_component_host_path(const char* local_path, const char* sdk_path,
                                          std::string* output_path) {
    std::string adb_dir = android::base::GetExecutableDirectory();
    if (adb_dir.empty()) {
        return false;
    }

    if (use_localagent) {
        const char* product_out = getenv("ANDROID_PRODUCT_OUT");
        if (product_out == nullptr) {
            return false;
        }
        *output_path = android::base::StringPrintf("%s%s", product_out, local_path);
        return true;
    } else {
        *output_path = adb_dir + sdk_path;
        return true;
    }
    return false;
}

static bool deploy_agent(bool checkTimeStamps) {
    std::vector<const char*> srcs;
    std::string agent_jar_path;
    if (get_agent_component_host_path("/system/framework/deployagent.jar", "/deployagent.jar",
                                      &agent_jar_path)) {
        srcs.push_back(agent_jar_path.c_str());
    } else {
        return false;
    }

    std::string agent_sh_path;
    if (get_agent_component_host_path("/system/bin/deployagent", "/deployagent", &agent_sh_path)) {
        srcs.push_back(agent_sh_path.c_str());
    } else {
        return false;
    }

    if (do_sync_push(srcs, kDeviceAgentPath, checkTimeStamps)) {
        // on windows the shell script might have lost execute permission
        // so need to set this explicitly
        const char* kChmodCommandPattern = "chmod 777 %sdeployagent";
        std::string chmodCommand =
                android::base::StringPrintf(kChmodCommandPattern, kDeviceAgentPath);
        int ret = send_shell_command(chmodCommand);
        return (ret == 0);
    } else {
        return false;
    }
}

bool update_agent(FastDeploy_AgentUpdateStrategy agentUpdateStrategy) {
    long agent_version = get_agent_version();
    switch (agentUpdateStrategy) {
        case FastDeploy_AgentUpdateAlways:
            if (deploy_agent(false) == false) {
                return false;
            }
            break;
        case FastDeploy_AgentUpdateNewerTimeStamp:
            if (deploy_agent(true) == false) {
                return false;
            }
            break;
        case FastDeploy_AgentUpdateDifferentVersion:
            if (agent_version != kRequiredAgentVersion) {
                if (agent_version < 0) {
                    printf("Could not detect agent on device, deploying\n");
                } else {
                    printf("Device agent version is (%ld), (%ld) is required, re-deploying\n",
                           agent_version, kRequiredAgentVersion);
                }
                if (deploy_agent(false) == false) {
                    return false;
                }
            }
            break;
    }

    agent_version = get_agent_version();
    return (agent_version == kRequiredAgentVersion);
}

static std::string get_aapt2_path() {
    if (use_localagent) {
        // This should never happen on a Windows machine
        const char* host_out = getenv("ANDROID_HOST_OUT");
        if (host_out == nullptr) {
            fatal("Could not locate aapt2 because $ANDROID_HOST_OUT is not defined");
        }
        return android::base::StringPrintf("%s/bin/aapt2", host_out);
    }

    std::string adb_dir = android::base::GetExecutableDirectory();
    if (adb_dir.empty()) {
        fatal("Could not locate aapt2");
    }
    return adb_dir + "/aapt2";
}

static int system_capture(const char* cmd, std::string& output) {
    FILE* pipe = popen(cmd, "re");
    int fd = -1;

    if (pipe != nullptr) {
        fd = fileno(pipe);
    }

    if (fd == -1) {
        fatal_errno("Could not create pipe for process '%s'", cmd);
    }

    if (!android::base::ReadFdToString(fd, &output)) {
        fatal_errno("Error reading from process '%s'", cmd);
    }

    return pclose(pipe);
}

// output is required to point to a valid output string (non-null)
static bool get_packagename_from_apk(const char* apkPath, std::string* output) {
    const char* kAapt2DumpNameCommandPattern = R"(%s dump packagename "%s")";
    std::string aapt2_path_string = get_aapt2_path();
    std::string getPackagenameCommand = android::base::StringPrintf(
            kAapt2DumpNameCommandPattern, aapt2_path_string.c_str(), apkPath);

    if (system_capture(getPackagenameCommand.c_str(), *output) == 0) {
        // strip any line end characters from the output
        *output = android::base::Trim(*output);
        return true;
    }
    return false;
}

int extract_metadata(const char* apkPath, FILE* outputFp) {
    std::string packageName;
    if (get_packagename_from_apk(apkPath, &packageName) == false) {
        return -1;
    }

    const char* kAgentExtractCommandPattern = "/data/local/tmp/deployagent extract %s";
    std::string extractCommand =
            android::base::StringPrintf(kAgentExtractCommandPattern, packageName.c_str());

    std::vector<char> extractErrorBuffer;
    int statusCode;
    DeployAgentFileCallback cb(outputFp, &extractErrorBuffer, &statusCode);
    int ret = send_shell_command(extractCommand, false, &cb);

    if (ret == 0) {
        return cb.getBytesWritten();
    }

    return ret;
}

static std::string get_patch_generator_command() {
    if (use_localagent) {
        // This should never happen on a Windows machine
        const char* host_out = getenv("ANDROID_HOST_OUT");
        if (host_out == nullptr) {
            fatal("Could not locate deploypatchgenerator.jar because $ANDROID_HOST_OUT is not "
                  "defined");
        }
        return android::base::StringPrintf("java -jar %s/framework/deploypatchgenerator.jar",
                                           host_out);
    }

    std::string adb_dir = android::base::GetExecutableDirectory();
    if (adb_dir.empty()) {
        fatal("Could not locate deploypatchgenerator.jar");
    }
    return android::base::StringPrintf(R"(java -jar "%s/deploypatchgenerator.jar")",
                                       adb_dir.c_str());
}

int create_patch(const char* apkPath, const char* metadataPath, const char* patchPath) {
    std::string generatePatchCommand = android::base::StringPrintf(
            R"(%s "%s" "%s" > "%s")", get_patch_generator_command().c_str(), apkPath, metadataPath,
            patchPath);
    return system(generatePatchCommand.c_str());
}

std::string get_patch_path(const char* apkPath) {
    std::string packageName;
    if (get_packagename_from_apk(apkPath, &packageName) == false) {
        return "";
    }

    std::string patchDevicePath =
            android::base::StringPrintf("%s%s.patch", kDeviceAgentPath, packageName.c_str());
    return patchDevicePath;
}

int apply_patch_on_device(const char* apkPath, const char* patchPath, const char* outputPath) {
    const std::string kAgentApplyCommandPattern = "/data/local/tmp/deployagent apply %s %s -o %s";

    std::string packageName;
    if (get_packagename_from_apk(apkPath, &packageName) == false) {
        return -1;
    }

    std::string patchDevicePath = get_patch_path(apkPath);

    std::vector<const char*> srcs = {patchPath};
    bool push_ok = do_sync_push(srcs, patchDevicePath.c_str(), false);

    if (!push_ok) {
        return -1;
    }

    std::string applyPatchCommand =
            android::base::StringPrintf(kAgentApplyCommandPattern.c_str(), packageName.c_str(),
                                        patchDevicePath.c_str(), outputPath);

    return send_shell_command(applyPatchCommand);
}

int install_patch(const char* apkPath, const char* patchPath, int argc, const char** argv) {
    const std::string kAgentApplyCommandPattern = "/data/local/tmp/deployagent apply %s %s -pm %s";

    std::string packageName;
    if (get_packagename_from_apk(apkPath, &packageName) == false) {
        return -1;
    }

    std::vector<const char*> srcs;
    std::string patchDevicePath =
            android::base::StringPrintf("%s%s.patch", kDeviceAgentPath, packageName.c_str());
    srcs.push_back(patchPath);
    bool push_ok = do_sync_push(srcs, patchDevicePath.c_str(), false);

    if (!push_ok) {
        return -1;
    }

    std::vector<unsigned char> applyOutputBuffer;
    std::vector<unsigned char> applyErrorBuffer;
    std::string argsString;

    for (int i = 0; i < argc; i++) {
        argsString.append(argv[i]);
        argsString.append(" ");
    }

    std::string applyPatchCommand =
            android::base::StringPrintf(kAgentApplyCommandPattern.c_str(), packageName.c_str(),
                                        patchDevicePath.c_str(), argsString.c_str());
    return send_shell_command(applyPatchCommand);
}
