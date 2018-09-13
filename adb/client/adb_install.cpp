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

#include "adb_install.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "adb.h"
#include "adb_client.h"
#include "adb_utils.h"
#include "android-base/file.h"
#include "android-base/stringprintf.h"
#include "android-base/strings.h"
#include "android-base/test_utils.h"
#include "client/file_sync_client.h"
#include "commandline.h"
#include "fastdeploy.h"
#include "sysdeps.h"

static constexpr int kFastDeployMinApi = 24;

static bool _use_legacy_install() {
    FeatureSet features;
    std::string error;
    if (!adb_get_feature_set(&features, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return true;
    }
    return !CanUseFeature(features, kFeatureCmd);
}

static int pm_command(int argc, const char** argv) {
    std::string cmd = "pm";

    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(cmd);
}

static int uninstall_app_streamed(int argc, const char** argv) {
    // 'adb uninstall' takes the same arguments as 'cmd package uninstall' on device
    std::string cmd = "cmd package";
    while (argc-- > 0) {
        // deny the '-k' option until the remaining data/cache can be removed with adb/UI
        if (strcmp(*argv, "-k") == 0) {
            printf("The -k option uninstalls the application while retaining the "
                   "data/cache.\n"
                   "At the moment, there is no way to remove the remaining data.\n"
                   "You will have to reinstall the application with the same "
                   "signature, and fully "
                   "uninstall it.\n"
                   "If you truly wish to continue, execute 'adb shell cmd package "
                   "uninstall -k'.\n");
            return EXIT_FAILURE;
        }
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(cmd);
}

static int uninstall_app_legacy(int argc, const char** argv) {
    /* if the user choose the -k option, we refuse to do it until devices are
       out with the option to uninstall the remaining data somehow (adb/ui) */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-k")) {
            printf("The -k option uninstalls the application while retaining the "
                   "data/cache.\n"
                   "At the moment, there is no way to remove the remaining data.\n"
                   "You will have to reinstall the application with the same "
                   "signature, and fully "
                   "uninstall it.\n"
                   "If you truly wish to continue, execute 'adb shell pm uninstall "
                   "-k'\n.");
            return EXIT_FAILURE;
        }
    }

    /* 'adb uninstall' takes the same arguments as 'pm uninstall' on device */
    return pm_command(argc, argv);
}

int uninstall_app(int argc, const char** argv) {
    if (_use_legacy_install()) {
        return uninstall_app_legacy(argc, argv);
    }
    return uninstall_app_streamed(argc, argv);
}

static void read_status_line(int fd, char* buf, size_t count) {
    count--;
    while (count > 0) {
        int len = adb_read(fd, buf, count);
        if (len <= 0) {
            break;
        }

        buf += len;
        count -= len;
    }
    *buf = '\0';
}

static int delete_device_patch_file(const char* apkPath) {
    std::string patchDevicePath = get_patch_path(apkPath);
    return delete_device_file(patchDevicePath);
}

static int install_app_streamed(int argc, const char** argv, bool use_fastdeploy,
                                bool use_localagent) {
    printf("Performing Streamed Install\n");

    // The last argument must be the APK file
    const char* file = argv[argc - 1];
    if (!android::base::EndsWithIgnoreCase(file, ".apk")) {
        return syntax_error("filename doesn't end .apk: %s", file);
    }

    if (use_fastdeploy == true) {
        TemporaryFile metadataTmpFile;
        TemporaryFile patchTmpFile;

        FILE* metadataFile = fopen(metadataTmpFile.path, "wb");
        extract_metadata(file, metadataFile);
        fclose(metadataFile);

        create_patch(file, metadataTmpFile.path, patchTmpFile.path);
        // pass all but 1st (command) and last (apk path) parameters through to pm for
        // session creation
        std::vector<const char*> pm_args{argv + 1, argv + argc - 1};
        install_patch(file, patchTmpFile.path, pm_args.size(), pm_args.data());
        delete_device_patch_file(file);
        return 0;
    } else {
        struct stat sb;
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
            return 1;
        }

        int localFd = adb_open(file, O_RDONLY);
        if (localFd < 0) {
            fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
            return 1;
        }

        std::string error;
        std::string cmd = "exec:cmd package";

        // don't copy the APK name, but, copy the rest of the arguments as-is
        while (argc-- > 1) {
            cmd += " " + escape_arg(std::string(*argv++));
        }

        // add size parameter [required for streaming installs]
        // do last to override any user specified value
        cmd += " " + android::base::StringPrintf("-S %" PRIu64, static_cast<uint64_t>(sb.st_size));

        int remoteFd = adb_connect(cmd, &error);
        if (remoteFd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            adb_close(localFd);
            return 1;
        }

        char buf[BUFSIZ];
        copy_to_file(localFd, remoteFd);
        read_status_line(remoteFd, buf, sizeof(buf));

        adb_close(localFd);
        adb_close(remoteFd);

        if (!strncmp("Success", buf, 7)) {
            fputs(buf, stdout);
            return 0;
        }
        fprintf(stderr, "adb: failed to install %s: %s", file, buf);
        return 1;
    }
}

static int install_app_legacy(int argc, const char** argv, bool use_fastdeploy,
                              bool use_localagent) {
    static const char* const DATA_DEST = "/data/local/tmp/%s";
    static const char* const SD_DEST = "/sdcard/tmp/%s";
    const char* where = DATA_DEST;

    printf("Performing Push Install\n");

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s")) {
            where = SD_DEST;
        }
    }

    // Find last APK argument.
    // All other arguments passed through verbatim.
    int last_apk = -1;
    for (int i = argc - 1; i >= 0; i--) {
        if (android::base::EndsWithIgnoreCase(argv[i], ".apk")) {
            last_apk = i;
            break;
        }
    }

    if (last_apk == -1) return syntax_error("need APK file on command line");

    int result = -1;
    std::vector<const char*> apk_file = {argv[last_apk]};
    std::string apk_dest =
            android::base::StringPrintf(where, android::base::Basename(argv[last_apk]).c_str());

    if (use_fastdeploy == true) {
        TemporaryFile metadataTmpFile;
        TemporaryFile patchTmpFile;

        FILE* metadataFile = fopen(metadataTmpFile.path, "wb");
        extract_metadata(apk_file[0], metadataFile);
        fclose(metadataFile);

        create_patch(apk_file[0], metadataTmpFile.path, patchTmpFile.path);
        apply_patch_on_device(apk_file[0], patchTmpFile.path, apk_dest.c_str());
    } else {
        if (!do_sync_push(apk_file, apk_dest.c_str(), false)) goto cleanup_apk;
    }

    argv[last_apk] = apk_dest.c_str(); /* destination name, not source location */
    result = pm_command(argc, argv);

cleanup_apk:
    if (use_fastdeploy == true) {
        delete_device_patch_file(apk_file[0]);
    }
    delete_device_file(apk_dest);
    return result;
}

int install_app(int argc, const char** argv) {
    std::vector<int> processedArgIndicies;
    enum installMode {
        INSTALL_DEFAULT,
        INSTALL_PUSH,
        INSTALL_STREAM
    } installMode = INSTALL_DEFAULT;
    bool use_fastdeploy = false;
    bool is_reinstall = false;
    bool use_localagent = false;
    FastDeploy_AgentUpdateStrategy agent_update_strategy = FastDeploy_AgentUpdateDifferentVersion;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--streaming")) {
            processedArgIndicies.push_back(i);
            installMode = INSTALL_STREAM;
        } else if (!strcmp(argv[i], "--no-streaming")) {
            processedArgIndicies.push_back(i);
            installMode = INSTALL_PUSH;
        } else if (!strcmp(argv[i], "-r")) {
            // Note that this argument is not added to processedArgIndicies because it
            // must be passed through to pm
            is_reinstall = true;
        } else if (!strcmp(argv[i], "--fastdeploy")) {
            processedArgIndicies.push_back(i);
            use_fastdeploy = true;
        } else if (!strcmp(argv[i], "--no-fastdeploy")) {
            processedArgIndicies.push_back(i);
            use_fastdeploy = false;
        } else if (!strcmp(argv[i], "--force-agent")) {
            processedArgIndicies.push_back(i);
            agent_update_strategy = FastDeploy_AgentUpdateAlways;
        } else if (!strcmp(argv[i], "--date-check-agent")) {
            processedArgIndicies.push_back(i);
            agent_update_strategy = FastDeploy_AgentUpdateNewerTimeStamp;
        } else if (!strcmp(argv[i], "--version-check-agent")) {
            processedArgIndicies.push_back(i);
            agent_update_strategy = FastDeploy_AgentUpdateDifferentVersion;
#ifndef _WIN32
        } else if (!strcmp(argv[i], "--local-agent")) {
            processedArgIndicies.push_back(i);
            use_localagent = true;
#endif
        }
    }

    if (installMode == INSTALL_DEFAULT) {
        if (_use_legacy_install()) {
            installMode = INSTALL_PUSH;
        } else {
            installMode = INSTALL_STREAM;
        }
    }

    if (installMode == INSTALL_STREAM && _use_legacy_install() == true) {
        return syntax_error("Attempting to use streaming install on unsupported deivce.");
    }

    if (use_fastdeploy == true && is_reinstall == false) {
        printf("Fast Deploy is only available with -r.\n");
        use_fastdeploy = false;
    }

    if (use_fastdeploy == true && get_device_api_level() < kFastDeployMinApi) {
        printf("Fast Deploy is only compatible with devices of API version %d or higher, "
               "ignoring.\n",
               kFastDeployMinApi);
        use_fastdeploy = false;
    }

    std::vector<const char*> passthrough_argv;
    for (int i = 0; i < argc; i++) {
        if (std::find(processedArgIndicies.begin(), processedArgIndicies.end(), i) ==
            processedArgIndicies.end()) {
            passthrough_argv.push_back(argv[i]);
        }
    }

    if (use_fastdeploy == true) {
        fastdeploy_set_local_agent(use_localagent);
        update_agent(agent_update_strategy);
    }

    switch (installMode) {
        case INSTALL_PUSH:
            return install_app_legacy(passthrough_argv.size(), passthrough_argv.data(),
                                      use_fastdeploy, use_localagent);
        case INSTALL_STREAM:
            return install_app_streamed(passthrough_argv.size(), passthrough_argv.data(),
                                        use_fastdeploy, use_localagent);
        case INSTALL_DEFAULT:
        default:
            return 1;
    }
}

int install_multiple_app(int argc, const char** argv) {
    // Find all APK arguments starting at end.
    // All other arguments passed through verbatim.
    int first_apk = -1;
    uint64_t total_size = 0;
    for (int i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];

        if (android::base::EndsWithIgnoreCase(file, ".apk")) {
            struct stat sb;
            if (stat(file, &sb) != -1) total_size += sb.st_size;
            first_apk = i;
        } else {
            break;
        }
    }

    if (first_apk == -1) return syntax_error("need APK file on command line");

    std::string install_cmd;
    if (_use_legacy_install()) {
        install_cmd = "exec:pm";
    } else {
        install_cmd = "exec:cmd package";
    }

    std::string cmd = android::base::StringPrintf("%s install-create -S %" PRIu64,
                                                  install_cmd.c_str(), total_size);
    for (int i = 1; i < first_apk; i++) {
        cmd += " " + escape_arg(argv[i]);
    }

    // Create install session
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: connect error for create: %s\n", error.c_str());
        return EXIT_FAILURE;
    }
    char buf[BUFSIZ];
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    int session_id = -1;
    if (!strncmp("Success", buf, 7)) {
        char* start = strrchr(buf, '[');
        char* end = strrchr(buf, ']');
        if (start && end) {
            *end = '\0';
            session_id = strtol(start + 1, nullptr, 10);
        }
    }
    if (session_id < 0) {
        fprintf(stderr, "adb: failed to create session\n");
        fputs(buf, stderr);
        return EXIT_FAILURE;
    }

    // Valid session, now stream the APKs
    int success = 1;
    for (int i = first_apk; i < argc; i++) {
        const char* file = argv[i];
        struct stat sb;
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string cmd =
                android::base::StringPrintf("%s install-write -S %" PRIu64 " %d %d_%s -",
                                            install_cmd.c_str(), static_cast<uint64_t>(sb.st_size),
                                            session_id, i, android::base::Basename(file).c_str());

        int localFd = adb_open(file, O_RDONLY);
        if (localFd < 0) {
            fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string error;
        int remoteFd = adb_connect(cmd, &error);
        if (remoteFd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            adb_close(localFd);
            success = 0;
            goto finalize_session;
        }

        copy_to_file(localFd, remoteFd);
        read_status_line(remoteFd, buf, sizeof(buf));

        adb_close(localFd);
        adb_close(remoteFd);

        if (strncmp("Success", buf, 7)) {
            fprintf(stderr, "adb: failed to write %s\n", file);
            fputs(buf, stderr);
            success = 0;
            goto finalize_session;
        }
    }

finalize_session:
    // Commit session if we streamed everything okay; otherwise abandon
    std::string service = android::base::StringPrintf("%s install-%s %d", install_cmd.c_str(),
                                                      success ? "commit" : "abandon", session_id);
    fd = adb_connect(service, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
        return EXIT_FAILURE;
    }
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stdout);
        return 0;
    }
    fprintf(stderr, "adb: failed to finalize session\n");
    fputs(buf, stderr);
    return EXIT_FAILURE;
}

int delete_device_file(const std::string& filename) {
    std::string cmd = "rm -f " + escape_arg(filename);
    return send_shell_command(cmd);
}
