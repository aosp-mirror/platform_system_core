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

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

#include <android-base/file.h>
#include <android-base/parsebool.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "adb.h"
#include "adb_client.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "client/file_sync_client.h"
#include "commandline.h"
#include "fastdeploy.h"
#include "incremental.h"

using namespace std::literals;

static constexpr int kFastDeployMinApi = 24;

namespace {

enum InstallMode {
    INSTALL_DEFAULT,
    INSTALL_PUSH,
    INSTALL_STREAM,
    INSTALL_INCREMENTAL,
};

enum class CmdlineOption { None, Enable, Disable };
}

static bool can_use_feature(const char* feature) {
    FeatureSet features;
    std::string error;
    if (!adb_get_feature_set(&features, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return false;
    }
    return CanUseFeature(features, feature);
}

static InstallMode best_install_mode() {
    if (can_use_feature(kFeatureCmd)) {
        return INSTALL_STREAM;
    }
    return INSTALL_PUSH;
}

static bool is_apex_supported() {
    return can_use_feature(kFeatureApex);
}

static bool is_abb_exec_supported() {
    return can_use_feature(kFeatureAbbExec);
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
    if (best_install_mode() == INSTALL_PUSH) {
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

static unique_fd send_command(const std::vector<std::string>& cmd_args, std::string* error) {
    if (is_abb_exec_supported()) {
        return send_abb_exec_command(cmd_args, error);
    } else {
        return unique_fd(adb_connect(android::base::Join(cmd_args, " "), error));
    }
}

static int install_app_streamed(int argc, const char** argv, bool use_fastdeploy) {
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

    if (use_fastdeploy) {
        auto metadata = extract_metadata(file);
        if (metadata.has_value()) {
            // pass all but 1st (command) and last (apk path) parameters through to pm for
            // session creation
            std::vector<const char*> pm_args{argv + 1, argv + argc - 1};
            auto patchFd = install_patch(pm_args.size(), pm_args.data());
            return stream_patch(file, std::move(metadata.value()), std::move(patchFd));
        }
    }

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

#ifdef __linux__
    posix_fadvise(local_fd.get(), 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);
#endif

    const bool use_abb_exec = is_abb_exec_supported();
    std::string error;
    std::vector<std::string> cmd_args = {use_abb_exec ? "package" : "exec:cmd package"};
    cmd_args.reserve(argc + 3);

    // don't copy the APK name, but, copy the rest of the arguments as-is
    while (argc-- > 1) {
        if (use_abb_exec) {
            cmd_args.push_back(*argv++);
        } else {
            cmd_args.push_back(escape_arg(*argv++));
        }
    }

    // add size parameter [required for streaming installs]
    // do last to override any user specified value
    cmd_args.push_back("-S");
    cmd_args.push_back(android::base::StringPrintf("%" PRIu64, static_cast<uint64_t>(sb.st_size)));

    if (is_apex) {
        cmd_args.push_back("--apex");
    }

    unique_fd remote_fd = send_command(cmd_args, &error);
    if (remote_fd < 0) {
        fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
        return 1;
    }

    if (!copy_to_file(local_fd.get(), remote_fd.get())) {
        fprintf(stderr, "adb: failed to install: copy_to_file: %s: %s", file, strerror(errno));
        return 1;
    }

    char buf[BUFSIZ];
    read_status_line(remote_fd.get(), buf, sizeof(buf));
    if (strncmp("Success", buf, 7) != 0) {
        fprintf(stderr, "adb: failed to install %s: %s", file, buf);
        return 1;
    }

    fputs(buf, stdout);
    return 0;
}

static int install_app_legacy(int argc, const char** argv, bool use_fastdeploy) {
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
    std::string apk_dest = "/data/local/tmp/" + android::base::Basename(argv[last_apk]);
    argv[last_apk] = apk_dest.c_str(); /* destination name, not source location */

    if (use_fastdeploy) {
        auto metadata = extract_metadata(apk_file[0]);
        if (metadata.has_value()) {
            auto patchFd = apply_patch_on_device(apk_dest.c_str());
            int status = stream_patch(apk_file[0], std::move(metadata.value()), std::move(patchFd));

            result = pm_command(argc, argv);
            delete_device_file(apk_dest);

            return status;
        }
    }

    if (do_sync_push(apk_file, apk_dest.c_str(), false, true)) {
        result = pm_command(argc, argv);
        delete_device_file(apk_dest);
    }

    return result;
}

template <class TimePoint>
static int ms_between(TimePoint start, TimePoint end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
}

static int install_app_incremental(int argc, const char** argv, bool wait, bool silent) {
    using clock = std::chrono::high_resolution_clock;
    const auto start = clock::now();
    int first_apk = -1;
    int last_apk = -1;
    incremental::Args passthrough_args = {};
    for (int i = 0; i < argc; ++i) {
        const auto arg = std::string_view(argv[i]);
        if (android::base::EndsWithIgnoreCase(arg, ".apk"sv)) {
            last_apk = i;
            if (first_apk == -1) {
                first_apk = i;
            }
        } else if (arg.starts_with("install"sv)) {
            // incremental installation command on the device is the same for all its variations in
            // the adb, e.g. install-multiple or install-multi-package
        } else {
            passthrough_args.push_back(arg);
        }
    }

    if (first_apk == -1) {
        if (!silent) {
            fprintf(stderr, "error: need at least one APK file on command line\n");
        }
        return -1;
    }

    auto files = incremental::Files{argv + first_apk, argv + last_apk + 1};
    if (silent) {
        // For a silent installation we want to do the lightweight check first and bail early and
        // quietly if it fails.
        if (!incremental::can_install(files)) {
            return -1;
        }
    }

    printf("Performing Incremental Install\n");
    auto server_process = incremental::install(files, passthrough_args, silent);
    if (!server_process) {
        return -1;
    }

    const auto end = clock::now();
    printf("Install command complete in %d ms\n", ms_between(start, end));

    if (wait) {
        (*server_process).wait();
    }

    return 0;
}

static std::pair<InstallMode, std::optional<InstallMode>> calculate_install_mode(
        InstallMode modeFromArgs, bool fastdeploy, CmdlineOption incremental_request) {
    if (incremental_request == CmdlineOption::Enable) {
        if (fastdeploy) {
            error_exit(
                    "--incremental and --fast-deploy options are incompatible. "
                    "Please choose one");
        }
    }

    if (modeFromArgs != INSTALL_DEFAULT) {
        if (incremental_request == CmdlineOption::Enable) {
            error_exit("--incremental is not compatible with other installation modes");
        }
        return {modeFromArgs, std::nullopt};
    }

    if (incremental_request != CmdlineOption::Disable && !is_abb_exec_supported()) {
        if (incremental_request == CmdlineOption::None) {
            incremental_request = CmdlineOption::Disable;
        } else {
            error_exit("Device doesn't support incremental installations");
        }
    }
    if (incremental_request == CmdlineOption::None) {
        // check if the host is ok with incremental by default
        if (const char* incrementalFromEnv = getenv("ADB_INSTALL_DEFAULT_INCREMENTAL")) {
            using namespace android::base;
            auto val = ParseBool(incrementalFromEnv);
            if (val == ParseBoolResult::kFalse) {
                incremental_request = CmdlineOption::Disable;
            }
        }
    }
    if (incremental_request == CmdlineOption::None) {
        // still ok: let's see if the device allows using incremental by default
        // it starts feeling like we're looking for an excuse to not to use incremental...
        std::string error;
        std::vector<std::string> args = {"settings", "get",
                                         "enable_adb_incremental_install_default"};
        auto fd = send_abb_exec_command(args, &error);
        if (!fd.ok()) {
            fprintf(stderr, "adb: retrieving the default device installation mode failed: %s",
                    error.c_str());
        } else {
            char buf[BUFSIZ] = {};
            read_status_line(fd.get(), buf, sizeof(buf));
            using namespace android::base;
            auto val = ParseBool(buf);
            if (val == ParseBoolResult::kFalse) {
                incremental_request = CmdlineOption::Disable;
            }
        }
    }

    if (incremental_request == CmdlineOption::Enable) {
        // explicitly requested - no fallback
        return {INSTALL_INCREMENTAL, std::nullopt};
    }
    const auto bestMode = best_install_mode();
    if (incremental_request == CmdlineOption::None) {
        // no opinion - use incremental, fallback to regular on a failure.
        return {INSTALL_INCREMENTAL, bestMode};
    }
    // incremental turned off - use the regular best mode without a fallback.
    return {bestMode, std::nullopt};
}

static std::vector<const char*> parse_install_mode(std::vector<const char*> argv,
                                                   InstallMode* install_mode,
                                                   CmdlineOption* incremental_request,
                                                   bool* incremental_wait) {
    *install_mode = INSTALL_DEFAULT;
    *incremental_request = CmdlineOption::None;
    *incremental_wait = false;

    std::vector<const char*> passthrough;
    for (auto&& arg : argv) {
        if (arg == "--streaming"sv) {
            *install_mode = INSTALL_STREAM;
        } else if (arg == "--no-streaming"sv) {
            *install_mode = INSTALL_PUSH;
        } else if (strlen(arg) >= "--incr"sv.size() && "--incremental"sv.starts_with(arg)) {
            *incremental_request = CmdlineOption::Enable;
        } else if (strlen(arg) >= "--no-incr"sv.size() && "--no-incremental"sv.starts_with(arg)) {
            *incremental_request = CmdlineOption::Disable;
        } else if (arg == "--wait"sv) {
            *incremental_wait = true;
        } else {
            passthrough.push_back(arg);
        }
    }
    return passthrough;
}

static std::vector<const char*> parse_fast_deploy_mode(
        std::vector<const char*> argv, bool* use_fastdeploy,
        FastDeploy_AgentUpdateStrategy* agent_update_strategy) {
    *use_fastdeploy = false;
    *agent_update_strategy = FastDeploy_AgentUpdateDifferentVersion;

    std::vector<const char*> passthrough;
    for (auto&& arg : argv) {
        if (arg == "--fastdeploy"sv) {
            *use_fastdeploy = true;
        } else if (arg == "--no-fastdeploy"sv) {
            *use_fastdeploy = false;
        } else if (arg == "--force-agent"sv) {
            *agent_update_strategy = FastDeploy_AgentUpdateAlways;
        } else if (arg == "--date-check-agent"sv) {
            *agent_update_strategy = FastDeploy_AgentUpdateNewerTimeStamp;
        } else if (arg == "--version-check-agent"sv) {
            *agent_update_strategy = FastDeploy_AgentUpdateDifferentVersion;
        } else {
            passthrough.push_back(arg);
        }
    }
    return passthrough;
}

int install_app(int argc, const char** argv) {
    InstallMode install_mode = INSTALL_DEFAULT;
    auto incremental_request = CmdlineOption::None;
    bool incremental_wait = false;

    bool use_fastdeploy = false;
    FastDeploy_AgentUpdateStrategy agent_update_strategy = FastDeploy_AgentUpdateDifferentVersion;

    auto unused_argv = parse_install_mode({argv, argv + argc}, &install_mode, &incremental_request,
                                          &incremental_wait);
    auto passthrough_argv =
            parse_fast_deploy_mode(std::move(unused_argv), &use_fastdeploy, &agent_update_strategy);

    auto [primary_mode, fallback_mode] =
            calculate_install_mode(install_mode, use_fastdeploy, incremental_request);
    if ((primary_mode == INSTALL_STREAM ||
         fallback_mode.value_or(INSTALL_PUSH) == INSTALL_STREAM) &&
        best_install_mode() == INSTALL_PUSH) {
        error_exit("Attempting to use streaming install on unsupported device");
    }

    if (use_fastdeploy && get_device_api_level() < kFastDeployMinApi) {
        fprintf(stderr,
                "Fast Deploy is only compatible with devices of API version %d or higher, "
                "ignoring.\n",
                kFastDeployMinApi);
        use_fastdeploy = false;
    }
    fastdeploy_set_agent_update_strategy(agent_update_strategy);

    if (passthrough_argv.size() < 2) {
        error_exit("install requires an apk argument");
    }

    auto run_install_mode = [&](InstallMode install_mode, bool silent) {
        switch (install_mode) {
            case INSTALL_PUSH:
                return install_app_legacy(passthrough_argv.size(), passthrough_argv.data(),
                                          use_fastdeploy);
            case INSTALL_STREAM:
                return install_app_streamed(passthrough_argv.size(), passthrough_argv.data(),
                                            use_fastdeploy);
            case INSTALL_INCREMENTAL:
                return install_app_incremental(passthrough_argv.size(), passthrough_argv.data(),
                                               incremental_wait, silent);
            case INSTALL_DEFAULT:
            default:
                error_exit("invalid install mode");
        }
    };
    auto res = run_install_mode(primary_mode, fallback_mode.has_value());
    if (res && fallback_mode.value_or(primary_mode) != primary_mode) {
        res = run_install_mode(*fallback_mode, false);
    }
    return res;
}

static int install_multiple_app_streamed(int argc, const char** argv) {
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
            if (stat(file, &sb) == -1) perror_exit("failed to stat \"%s\"", file);
            total_size += sb.st_size;
            first_apk = i;
        } else {
            break;
        }
    }

    if (first_apk == -1) error_exit("need APK file on command line");

    const bool use_abb_exec = is_abb_exec_supported();
    const std::string install_cmd =
            use_abb_exec ? "package"
                         : best_install_mode() == INSTALL_PUSH ? "exec:pm" : "exec:cmd package";

    std::vector<std::string> cmd_args = {install_cmd, "install-create", "-S",
                                         std::to_string(total_size)};
    cmd_args.reserve(first_apk + 4);
    for (int i = 1; i < first_apk; i++) {
        if (use_abb_exec) {
            cmd_args.push_back(argv[i]);
        } else {
            cmd_args.push_back(escape_arg(argv[i]));
        }
    }

    // Create install session
    std::string error;
    char buf[BUFSIZ];
    {
        unique_fd fd = send_command(cmd_args, &error);
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
    const auto session_id_str = std::to_string(session_id);

    // Valid session, now stream the APKs
    bool success = true;
    for (int i = first_apk; i < argc; i++) {
        const char* file = argv[i];
        struct stat sb;
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "adb: failed to stat \"%s\": %s\n", file, strerror(errno));
            success = false;
            goto finalize_session;
        }

        std::vector<std::string> cmd_args = {
                install_cmd,
                "install-write",
                "-S",
                std::to_string(sb.st_size),
                session_id_str,
                android::base::Basename(file),
                "-",
        };

        unique_fd local_fd(adb_open(file, O_RDONLY | O_CLOEXEC));
        if (local_fd < 0) {
            fprintf(stderr, "adb: failed to open \"%s\": %s\n", file, strerror(errno));
            success = false;
            goto finalize_session;
        }

        std::string error;
        unique_fd remote_fd = send_command(cmd_args, &error);
        if (remote_fd < 0) {
            fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
            success = false;
            goto finalize_session;
        }

        if (!copy_to_file(local_fd.get(), remote_fd.get())) {
            fprintf(stderr, "adb: failed to write \"%s\": %s\n", file, strerror(errno));
            success = false;
            goto finalize_session;
        }

        read_status_line(remote_fd.get(), buf, sizeof(buf));

        if (strncmp("Success", buf, 7)) {
            fprintf(stderr, "adb: failed to write \"%s\"\n", file);
            fputs(buf, stderr);
            success = false;
            goto finalize_session;
        }
    }

finalize_session:
    // Commit session if we streamed everything okay; otherwise abandon.
    std::vector<std::string> service_args = {
            install_cmd,
            success ? "install-commit" : "install-abandon",
            session_id_str,
    };
    {
        unique_fd fd = send_command(service_args, &error);
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
            return EXIT_FAILURE;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }
    if (!success) return EXIT_FAILURE;

    if (strncmp("Success", buf, 7)) {
        fprintf(stderr, "adb: failed to finalize session\n");
        fputs(buf, stderr);
        return EXIT_FAILURE;
    }

    fputs(buf, stdout);
    return EXIT_SUCCESS;
}

int install_multiple_app(int argc, const char** argv) {
    InstallMode install_mode = INSTALL_DEFAULT;
    auto incremental_request = CmdlineOption::None;
    bool incremental_wait = false;
    bool use_fastdeploy = false;

    auto passthrough_argv = parse_install_mode({argv + 1, argv + argc}, &install_mode,
                                               &incremental_request, &incremental_wait);

    auto [primary_mode, fallback_mode] =
            calculate_install_mode(install_mode, use_fastdeploy, incremental_request);
    if ((primary_mode == INSTALL_STREAM ||
         fallback_mode.value_or(INSTALL_PUSH) == INSTALL_STREAM) &&
        best_install_mode() == INSTALL_PUSH) {
        error_exit("Attempting to use streaming install on unsupported device");
    }

    auto run_install_mode = [&](InstallMode install_mode, bool silent) {
        switch (install_mode) {
            case INSTALL_PUSH:
            case INSTALL_STREAM:
                return install_multiple_app_streamed(passthrough_argv.size(),
                                                     passthrough_argv.data());
            case INSTALL_INCREMENTAL:
                return install_app_incremental(passthrough_argv.size(), passthrough_argv.data(),
                                               incremental_wait, silent);
            case INSTALL_DEFAULT:
            default:
                error_exit("invalid install mode");
        }
    };
    auto res = run_install_mode(primary_mode, fallback_mode.has_value());
    if (res && fallback_mode.value_or(primary_mode) != primary_mode) {
        res = run_install_mode(*fallback_mode, false);
    }
    return res;
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

    if (best_install_mode() == INSTALL_PUSH) {
        fprintf(stderr, "adb: multi-package install is not supported on this device\n");
        return EXIT_FAILURE;
    }

    const bool use_abb_exec = is_abb_exec_supported();
    const std::string install_cmd = use_abb_exec ? "package" : "exec:cmd package";

    std::vector<std::string> multi_package_cmd_args = {install_cmd, "install-create",
                                                       "--multi-package"};

    multi_package_cmd_args.reserve(first_package + 4);
    for (int i = 1; i < first_package; i++) {
        if (use_abb_exec) {
            multi_package_cmd_args.push_back(argv[i]);
        } else {
            multi_package_cmd_args.push_back(escape_arg(argv[i]));
        }
    }

    if (apex_found) {
        multi_package_cmd_args.emplace_back("--staged");
    }

    // Create multi-package install session
    std::string error;
    char buf[BUFSIZ];
    {
        unique_fd fd = send_command(multi_package_cmd_args, &error);
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
    const auto parent_session_id_str = std::to_string(parent_session_id);

    fprintf(stdout, "Created parent session ID %d.\n", parent_session_id);

    std::vector<int> session_ids;

    // Valid session, now create the individual sessions and stream the APKs
    int success = EXIT_FAILURE;
    std::vector<std::string> individual_cmd_args = {install_cmd, "install-create"};
    for (int i = 1; i < first_package; i++) {
        if (use_abb_exec) {
            individual_cmd_args.push_back(argv[i]);
        } else {
            individual_cmd_args.push_back(escape_arg(argv[i]));
        }
    }
    if (apex_found) {
        individual_cmd_args.emplace_back("--staged");
    }

    std::vector<std::string> individual_apex_cmd_args;
    if (apex_found) {
        individual_apex_cmd_args = individual_cmd_args;
        individual_apex_cmd_args.emplace_back("--apex");
    }

    std::vector<std::string> add_session_cmd_args = {
            install_cmd,
            "install-add-session",
            parent_session_id_str,
    };

    for (int i = first_package; i < argc; i++) {
        const char* file = argv[i];
        char buf[BUFSIZ];
        {
            unique_fd fd;
            // Create individual install session
            if (android::base::EndsWithIgnoreCase(file, ".apex")) {
                fd = send_command(individual_apex_cmd_args, &error);
            } else {
                fd = send_command(individual_cmd_args, &error);
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
        const auto session_id_str = std::to_string(session_id);

        fprintf(stdout, "Created child session ID %d.\n", session_id);
        session_ids.push_back(session_id);

        // Support splitAPKs by allowing the notation split1.apk:split2.apk:split3.apk as argument.
        std::vector<std::string> splits = android::base::Split(file, ":");

        for (const std::string& split : splits) {
            struct stat sb;
            if (stat(split.c_str(), &sb) == -1) {
                fprintf(stderr, "adb: failed to stat %s: %s\n", split.c_str(), strerror(errno));
                goto finalize_multi_package_session;
            }

            std::vector<std::string> cmd_args = {
                    install_cmd,
                    "install-write",
                    "-S",
                    std::to_string(sb.st_size),
                    session_id_str,
                    android::base::StringPrintf("%d_%s", i, android::base::Basename(file).c_str()),
                    "-",
            };

            unique_fd local_fd(adb_open(split.c_str(), O_RDONLY | O_CLOEXEC));
            if (local_fd < 0) {
                fprintf(stderr, "adb: failed to open %s: %s\n", split.c_str(), strerror(errno));
                goto finalize_multi_package_session;
            }

            std::string error;
            unique_fd remote_fd = send_command(cmd_args, &error);
            if (remote_fd < 0) {
                fprintf(stderr, "adb: connect error for write: %s\n", error.c_str());
                goto finalize_multi_package_session;
            }

            if (!copy_to_file(local_fd.get(), remote_fd.get())) {
                fprintf(stderr, "adb: failed to write %s: %s\n", split.c_str(), strerror(errno));
                goto finalize_multi_package_session;
            }

            read_status_line(remote_fd.get(), buf, sizeof(buf));

            if (strncmp("Success", buf, 7)) {
                fprintf(stderr, "adb: failed to write %s\n", split.c_str());
                fputs(buf, stderr);
                goto finalize_multi_package_session;
            }
        }
        add_session_cmd_args.push_back(std::to_string(session_id));
    }

    {
        unique_fd fd = send_command(add_session_cmd_args, &error);
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for install-add-session: %s\n", error.c_str());
            goto finalize_multi_package_session;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }

    if (strncmp("Success", buf, 7)) {
        fprintf(stderr, "adb: failed to link sessions (%s)\n",
                android::base::Join(add_session_cmd_args, " ").c_str());
        fputs(buf, stderr);
        goto finalize_multi_package_session;
    }

    // no failures means we can proceed with the assumption of success
    success = 0;

finalize_multi_package_session:
    // Commit session if we streamed everything okay; otherwise abandon
    std::vector<std::string> service_args = {
            install_cmd,
            success == 0 ? "install-commit" : "install-abandon",
            parent_session_id_str,
    };

    {
        unique_fd fd = send_command(service_args, &error);
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

    session_ids.push_back(parent_session_id);
    // try to abandon all remaining sessions
    for (std::size_t i = 0; i < session_ids.size(); i++) {
        std::vector<std::string> service_args = {
                install_cmd,
                "install-abandon",
                std::to_string(session_ids[i]),
        };
        fprintf(stderr, "Attempting to abandon session ID %d\n", session_ids[i]);
        unique_fd fd = send_command(service_args, &error);
        if (fd < 0) {
            fprintf(stderr, "adb: connect error for finalize: %s\n", error.c_str());
            continue;
        }
        read_status_line(fd.get(), buf, sizeof(buf));
    }
    return EXIT_FAILURE;
}

int delete_device_file(const std::string& filename) {
    // http://b/17339227 "Sideloading a Readonly File Results in a Prompt to
    // Delete" caused us to add `-f` here, to avoid the equivalent of the `-i`
    // prompt that you get from BSD rm (used in Android 5) if you have a
    // non-writable file and stdin is a tty (which is true for old versions of
    // adbd).
    //
    // Unfortunately, `rm -f` requires Android 4.3, so that workaround broke
    // earlier Android releases. This was reported as http://b/37704384 "adb
    // install -r passes invalid argument to rm on Android 4.1" and
    // http://b/37035817 "ADB Fails: rm failed for -f, No such file or
    // directory".
    //
    // Testing on a variety of devices and emulators shows that redirecting
    // stdin is sufficient to avoid the pseudo-`-i`, and works on toolbox,
    // BSD, and toybox versions of rm.
    return send_shell_command("rm " + escape_arg(filename) + " </dev/null");
}
