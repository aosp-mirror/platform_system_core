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

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb.h"
#include "adb_client.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "client/file_sync_client.h"
#include "commandline.h"
#include "fastdeploy.h"

#if defined(ENABLE_FASTDEPLOY)
static constexpr int kFastDeployMinApi = 24;
#endif

static bool can_use_feature(const char* feature) {
    FeatureSet features;
    std::string error;
    if (!adb_get_feature_set(&features, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return true;
    }
    return CanUseFeature(features, feature);
}

static bool use_legacy_install() {
    return !can_use_feature(kFeatureCmd);
}

static bool is_apex_supported() {
    return can_use_feature(kFeatureApex);
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
    if (use_legacy_install()) {
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

#if defined(ENABLE_FASTDEPLOY)
static int delete_device_patch_file(const char* apkPath) {
    std::string patchDevicePath = get_patch_path(apkPath);
    return delete_device_file(patchDevicePath);
}
#endif

static int install_app_streamed(int argc, const char** argv, bool use_fastdeploy,
                                bool use_localagent) {
    printf("Performing Streamed Install\n");

    // The last argument must be the APK file
    const char* file = argv[argc - 1];
    if (!android::base::EndsWithIgnoreCase(file, ".apk") &&
        !android::base::EndsWithIgnoreCase(file, ".apex")) {
        error_exit("filename doesn't end .apk or .apex: %s", file);
    }

    bool is_apex = false;
    if (android::base::EndsWithIgnoreCase(file, ".apex")) {
        is_apex = true;
    }
    if (is_apex && !is_apex_supported()) {
        error_exit(".apex is not supported on the target device");
    }

    if (is_apex && use_fastdeploy) {
        error_exit("--fastdeploy doesn't support .apex files");
    }

    if (use_fastdeploy == true) {
#if defined(ENABLE_FASTDEPLOY)
        TemporaryFile metadataTmpFile;
        std::string patchTmpFilePath;
        {
            TemporaryFile patchTmpFile;
            patchTmpFile.DoNotRemove();
            patchTmpFilePath = patchTmpFile.path;
        }

        FILE* metadataFile = fopen(metadataTmpFile.path, "wb");
        extract_metadata(file, metadataFile);
        fclose(metadataFile);

        create_patch(file, metadataTmpFile.path, patchTmpFilePath.c_str());
        // pass all but 1st (command) and last (apk path) parameters through to pm for
        // session creation
        std::vector<const char*> pm_args{argv + 1, argv + argc - 1};
        install_patch(file, patchTmpFilePath.c_str(), pm_args.size(), pm_args.data());
        adb_unlink(patchTmpFilePath.c_str());
        delete_device_patch_file(file);
        return 0;
#else
        error_exit("fastdeploy is disabled");
#endif
    } else {
        struct stat sb;
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
            return 1;
        }

        unique_fd local_fd(adb_open(file, O_RDONLY | O_CLOEXEC));
        if (local_fd < 0) {
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

        if (is_apex) {
            cmd += " --apex";
        }

        unique_fd remote_fd(adb_connect(cmd, &error));
        if (remote_fd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            return 1;
        }

        char buf[BUFSIZ];
        copy_to_file(local_fd.get(), remote_fd.get());
        read_status_line(remote_fd.get(), buf, sizeof(buf));

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
    printf("Performing Push Install\n");

    // Find last APK argument.
    // All other arguments passed through verbatim.
    int last_apk = -1;
    for (int i = argc - 1; i >= 0; i--) {
        if (android::base::EndsWithIgnoreCase(argv[i], ".apex")) {
            error_exit("APEX packages are only compatible with Streamed Install");
        }
        if (android::base::EndsWithIgnoreCase(argv[i], ".apk")) {
            last_apk = i;
            break;
        }
    }

    if (last_apk == -1) error_exit("need APK file on command line");

    int result = -1;
    std::vector<const char*> apk_file = {argv[last_apk]};
    std::string apk_dest =
            "/data/local/tmp/" + android::base::Basename(argv[last_apk]);

    if (use_fastdeploy == true) {
#if defined(ENABLE_FASTDEPLOY)
        TemporaryFile metadataTmpFile;
        TemporaryFile patchTmpFile;

        FILE* metadataFile = fopen(metadataTmpFile.path, "wb");
        extract_metadata(apk_file[0], metadataFile);
        fclose(metadataFile);

        create_patch(apk_file[0], metadataTmpFile.path, patchTmpFile.path);
        apply_patch_on_device(apk_file[0], patchTmpFile.path, apk_dest.c_str());
#else
        error_exit("fastdeploy is disabled");
#endif
    } else {
        if (!do_sync_push(apk_file, apk_dest.c_str(), false)) goto cleanup_apk;
    }

    argv[last_apk] = apk_dest.c_str(); /* destination name, not source location */
    result = pm_command(argc, argv);

cleanup_apk:
    if (use_fastdeploy == true) {
#if defined(ENABLE_FASTDEPLOY)
        delete_device_patch_file(apk_file[0]);
#endif
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
        if (use_legacy_install()) {
            installMode = INSTALL_PUSH;
        } else {
            installMode = INSTALL_STREAM;
        }
    }

    if (installMode == INSTALL_STREAM && use_legacy_install() == true) {
        error_exit("Attempting to use streaming install on unsupported device");
    }

#if defined(ENABLE_FASTDEPLOY)
    if (use_fastdeploy == true && get_device_api_level() < kFastDeployMinApi) {
        printf("Fast Deploy is only compatible with devices of API version %d or higher, "
               "ignoring.\n",
               kFastDeployMinApi);
        use_fastdeploy = false;
    }
#endif

    std::vector<const char*> passthrough_argv;
    for (int i = 0; i < argc; i++) {
        if (std::find(processedArgIndicies.begin(), processedArgIndicies.end(), i) ==
            processedArgIndicies.end()) {
            passthrough_argv.push_back(argv[i]);
        }
    }
    if (passthrough_argv.size() < 2) {
        error_exit("install requires an apk argument");
    }

    if (use_fastdeploy == true) {
#if defined(ENABLE_FASTDEPLOY)
        fastdeploy_set_local_agent(use_localagent);
        update_agent(agent_update_strategy);

        // The last argument must be the APK file
        const char* file = passthrough_argv.back();
        use_fastdeploy = find_package(file);
#else
        error_exit("fastdeploy is disabled");
#endif
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
        if (android::base::EndsWithIgnoreCase(argv[i], ".apex")) {
            error_exit("APEX packages are not compatible with install-multiple");
        }

        if (android::base::EndsWithIgnoreCase(file, ".apk") ||
            android::base::EndsWithIgnoreCase(file, ".dm") ||
            android::base::EndsWithIgnoreCase(file, ".fsv_sig")) {
            struct stat sb;
            if (stat(file, &sb) != -1) total_size += sb.st_size;
            first_apk = i;
        } else {
            break;
        }
    }

    if (first_apk == -1) error_exit("need APK file on command line");

    std::string install_cmd;
    if (use_legacy_install()) {
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
    char buf[BUFSIZ];
    {
        unique_fd fd(adb_connect(cmd, &error));
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for create: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }

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
                android::base::StringPrintf("%s install-write -S %" PRIu64 " %d %s -",
                                            install_cmd.c_str(), static_cast<uint64_t>(sb.st_size),
                                            session_id, android::base::Basename(file).c_str());

        unique_fd local_fd(adb_open(file, O_RDONLY | O_CLOEXEC));
        if (local_fd < 0) {
            fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string error;
        unique_fd remote_fd(adb_connect(cmd, &error));
        if (remote_fd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            success = 0;
            goto finalize_session;
        }

        copy_to_file(local_fd.get(), remote_fd.get());
        read_status_line(remote_fd.get(), buf, sizeof(buf));

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
    {
        unique_fd fd(adb_connect(service, &error));
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stdout);
        return 0;
    }
    fprintf(stderr, "adb: failed to finalize session\n");
    fputs(buf, stderr);
    return EXIT_FAILURE;
}

int install_multi_package(int argc, const char** argv) {
    // Find all APK arguments starting at end.
    // All other arguments passed through verbatim.
    bool apex_found = false;
    int first_package = -1;
    for (int i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];
        if (android::base::EndsWithIgnoreCase(file, ".apk") ||
            android::base::EndsWithIgnoreCase(file, ".apex")) {
            first_package = i;
            if (android::base::EndsWithIgnoreCase(file, ".apex")) {
                apex_found = true;
            }
        } else {
            break;
        }
    }

    if (first_package == -1) error_exit("need APK or APEX files on command line");

    if (use_legacy_install()) {
        fprintf(stderr, "adb: multi-package install is not supported on this device\n");
        return EXIT_FAILURE;
    }
    std::string install_cmd = "exec:cmd package";

    std::string multi_package_cmd =
            android::base::StringPrintf("%s install-create --multi-package", install_cmd.c_str());
    for (int i = 1; i < first_package; i++) {
        multi_package_cmd += " " + escape_arg(argv[i]);
    }

    if (apex_found) {
        multi_package_cmd += " --staged";
    }

    // Create multi-package install session
    std::string error;
    char buf[BUFSIZ];
    {
        unique_fd fd(adb_connect(multi_package_cmd, &error));
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for create multi-package: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }

    int parent_session_id = -1;
    if (!strncmp("Success", buf, 7)) {
        char* start = strrchr(buf, '[');
        char* end = strrchr(buf, ']');
        if (start && end) {
            *end = '\0';
            parent_session_id = strtol(start + 1, nullptr, 10);
        }
    }
    if (parent_session_id < 0) {
        fprintf(stderr, "adb: failed to create multi-package session\n");
        fputs(buf, stderr);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Created parent session ID %d.\n", parent_session_id);

    std::vector<int> session_ids;

    // Valid session, now create the individual sessions and stream the APKs
    int success = EXIT_FAILURE;
    std::string individual_cmd =
            android::base::StringPrintf("%s install-create", install_cmd.c_str());
    std::string all_session_ids = "";
    for (int i = 1; i < first_package; i++) {
        individual_cmd += " " + escape_arg(argv[i]);
    }
    if (apex_found) {
        individual_cmd += " --staged";
    }
    std::string individual_apex_cmd = individual_cmd + " --apex";
    std::string cmd = "";
    for (int i = first_package; i < argc; i++) {
        const char* file = argv[i];
        char buf[BUFSIZ];
        {
            unique_fd fd;
            // Create individual install session
            if (android::base::EndsWithIgnoreCase(file, ".apex")) {
                fd.reset(adb_connect(individual_apex_cmd, &error));
            } else {
                fd.reset(adb_connect(individual_cmd, &error));
            }
            if (fd < 0) {
                fprintf(stderr, "adb: connect error for create: %s\n", error.c_str());
                goto finalize_multi_package_session;
            }
            read_status_line(fd.get(), buf, sizeof(buf));
        }

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
            fprintf(stderr, "adb: failed to create multi-package session\n");
            fputs(buf, stderr);
            goto finalize_multi_package_session;
        }

        fprintf(stdout, "Created child session ID %d.\n", session_id);
        session_ids.push_back(session_id);

        struct stat sb;
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "adb: failed to stat %s: %s\n", file, strerror(errno));
            goto finalize_multi_package_session;
        }

        std::string cmd =
                android::base::StringPrintf("%s install-write -S %" PRIu64 " %d %d_%s -",
                                            install_cmd.c_str(), static_cast<uint64_t>(sb.st_size),
                                            session_id, i, android::base::Basename(file).c_str());

        unique_fd local_fd(adb_open(file, O_RDONLY | O_CLOEXEC));
        if (local_fd < 0) {
            fprintf(stderr, "adb: failed to open %s: %s\n", file, strerror(errno));
            goto finalize_multi_package_session;
        }

        std::string error;
        unique_fd remote_fd(adb_connect(cmd, &error));
        if (remote_fd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            goto finalize_multi_package_session;
        }

        copy_to_file(local_fd.get(), remote_fd.get());
        read_status_line(remote_fd.get(), buf, sizeof(buf));

        if (strncmp("Success", buf, 7)) {
            fprintf(stderr, "adb: failed to write %s\n", file);
            fputs(buf, stderr);
            goto finalize_multi_package_session;
        }

        all_session_ids += android::base::StringPrintf(" %d", session_id);
    }

    cmd = android::base::StringPrintf("%s install-add-session %d%s", install_cmd.c_str(),
                                      parent_session_id, all_session_ids.c_str());
    {
        unique_fd fd(adb_connect(cmd, &error));
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for install-add-session: %s\n", error.c_str());
            goto finalize_multi_package_session;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }

    if (strncmp("Success", buf, 7)) {
        fprintf(stderr, "adb: failed to link sessions (%s)\n", cmd.c_str());
        fputs(buf, stderr);
        goto finalize_multi_package_session;
    }

    // no failures means we can proceed with the assumption of success
    success = 0;

finalize_multi_package_session:
    // Commit session if we streamed everything okay; otherwise abandon
    std::string service =
            android::base::StringPrintf("%s install-%s %d", install_cmd.c_str(),
                                        success == 0 ? "commit" : "abandon", parent_session_id);
    {
        unique_fd fd(adb_connect(service, &error));
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stdout);
        if (success == 0) {
            return 0;
        }
    } else {
        fprintf(stderr, "adb: failed to finalize session\n");
        fputs(buf, stderr);
    }

    // try to abandon all remaining sessions
    for (std::size_t i = 0; i < session_ids.size(); i++) {
        service = android::base::StringPrintf("%s install-abandon %d", install_cmd.c_str(),
                                              session_ids[i]);
        fprintf(stderr, "Attempting to abandon session ID %d\n", session_ids[i]);
        unique_fd fd(adb_connect(service, &error));
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
            continue;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }
    return EXIT_FAILURE;
}

int delete_device_file(const std::string& filename) {
    std::string cmd = "rm -f " + escape_arg(filename);
    return send_shell_command(cmd);
}
