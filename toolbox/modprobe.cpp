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

#include <ctype.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <modprobe/modprobe.h>

#include <sys/utsname.h>

namespace {

enum modprobe_mode {
    AddModulesMode,
    RemoveModulesMode,
    ListModulesMode,
    ShowDependenciesMode,
};

void print_usage(void) {
    LOG(INFO) << "Usage:";
    LOG(INFO);
    LOG(INFO) << "  modprobe [options] [-d DIR] [--all=FILE|MODULE]...";
    LOG(INFO) << "  modprobe [options] [-d DIR] MODULE [symbol=value]...";
    LOG(INFO);
    LOG(INFO) << "Options:";
    LOG(INFO) << "  --all=FILE: FILE to acquire module names from";
    LOG(INFO) << "  -b, --use-blocklist: Apply blocklist to module names too";
    LOG(INFO) << "  -d, --dirname=DIR: Load modules from DIR, option may be used multiple times";
    LOG(INFO) << "  -D, --show-depends: Print dependencies for modules only, do not load";
    LOG(INFO) << "  -h, --help: Print this help";
    LOG(INFO) << "  -l, --list: List modules matching pattern";
    LOG(INFO) << "  -r, --remove: Remove MODULE (multiple modules may be specified)";
    LOG(INFO) << "  -s, --syslog: print to syslog also";
    LOG(INFO) << "  -q, --quiet: disable messages";
    LOG(INFO) << "  -v, --verbose: enable more messages, even more with a second -v";
    LOG(INFO);
}

#define check_mode()                                   \
    if (mode != AddModulesMode) {                      \
        LOG(ERROR) << "multiple mode flags specified"; \
        print_usage();                                 \
        return EXIT_FAILURE;                           \
    }

std::string stripComments(const std::string& str) {
    for (std::string rv = str;;) {
        auto comment = rv.find('#');
        if (comment == std::string::npos) return rv;
        auto end = rv.find('\n', comment);
        if (end != std::string::npos) end = end - comment;
        rv.erase(comment, end);
    }
    /* NOTREACHED */
}

auto syslog = false;

void MyLogger(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
              const char* file, unsigned int line, const char* message) {
    android::base::StdioLogger(id, severity, tag, file, line, message);
    if (syslog && message[0]) {
        android::base::KernelLogger(id, severity, tag, file, line, message);
    }
}

static bool ModDirMatchesKernelPageSize(const char* mod_dir) {
    static const unsigned int kernel_pgsize_kb = getpagesize() / 1024;
    unsigned int mod_pgsize_kb = 16;  // 16k default since android15-6.6

    if (mod_dir && strstr(mod_dir, "-4k") != NULL) {
        mod_pgsize_kb = 4;
    }

    return kernel_pgsize_kb == mod_pgsize_kb;
}

static bool ModDirMatchesKernelPageSizeLegacy(const char* mod_dir) {
    static const unsigned int kernel_pgsize_kb = getpagesize() / 1024;
    const char* mod_sfx = strrchr(mod_dir, '_');
    unsigned int mod_pgsize_kb;
    int mod_sfx_len;

    if (mod_sfx == NULL || sscanf(mod_sfx, "_%uk%n", &mod_pgsize_kb, &mod_sfx_len) != 1 ||
        strlen(mod_sfx) != mod_sfx_len) {
        mod_pgsize_kb = 4;
    }

    return kernel_pgsize_kb == mod_pgsize_kb;
}

// Find directories in format of "/lib/modules/x.y.z-*".
static int KernelVersionNameFilter(const dirent* de) {
    static unsigned int major, minor;
    static std::string kernel_version;
    utsname uts;

    if (kernel_version.empty()) {
        if ((uname(&uts) != 0) || (sscanf(uts.release, "%u.%u", &major, &minor) != 2)) {
            LOG(ERROR) << "Could not parse the kernel version from uname";
            return 0;
        }
        kernel_version = android::base::StringPrintf("%u.%u", major, minor);
    }

    if (android::base::StartsWith(de->d_name, kernel_version)) {
        // Check for GKI to avoid breaking non-GKI Android devices.
        if (UNLIKELY(strstr(de->d_name, "-android") == NULL)) {
            // For non-GKI, just match when the major and minor versions match.
            return 1;
        }

        // For android15-6.6 and later, GKI adds `-4k` to the UTS release
        // string to identify 4kb page size kernels. If there is no page size
        // suffix, then the kernel page size is 16kb.
        if (major > 6 || (major == 6 && minor >= 6)) {
            return ModDirMatchesKernelPageSize(de->d_name);
        } else {
            return ModDirMatchesKernelPageSizeLegacy(de->d_name);
        }
    }
    return 0;
}

}  // anonymous namespace

extern "C" int modprobe_main(int argc, char** argv) {
    android::base::InitLogging(argv, MyLogger);
    android::base::SetMinimumLogSeverity(android::base::INFO);

    std::vector<std::string> modules;
    std::string modules_load_file;
    std::string module_parameters;
    std::string mods;
    std::vector<std::string> mod_dirs;
    modprobe_mode mode = AddModulesMode;
    bool blocklist = false;
    int rv = EXIT_SUCCESS;

    int opt, fd;
    int option_index = 0;
    // NB: We have non-standard short options -l and -D to make it easier for
    // OEMs to transition from toybox.
    // clang-format off
    static struct option long_options[] = {
        { "all",                 optional_argument, 0, 'a' },
        { "use-blocklist",       no_argument,       0, 'b' },
        { "dirname",             required_argument, 0, 'd' },
        { "show-depends",        no_argument,       0, 'D' },
        { "help",                no_argument,       0, 'h' },
        { "list",                no_argument,       0, 'l' },
        { "quiet",               no_argument,       0, 'q' },
        { "remove",              no_argument,       0, 'r' },
        { "syslog",              no_argument,       0, 's' },
        { "verbose",             no_argument,       0, 'v' },
    };
    // clang-format on
    while ((opt = getopt_long(argc, argv, "a::bd:Dhlqrsv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a':
                // toybox modprobe supported -a to load multiple modules, this
                // is supported here by default, ignore flag if no argument.
                check_mode();
                if (optarg == NULL) break;

                // Since libmodprobe doesn't fail when the modules load file
                // doesn't exist, let's check that here so that we don't
                // silently fail.
                fd = open(optarg, O_RDONLY | O_CLOEXEC | O_BINARY);
                if (fd == -1) {
                    PLOG(ERROR) << "Failed to open " << optarg;
                    return EXIT_FAILURE;
                }
                close(fd);

                mod_dirs.emplace_back(android::base::Dirname(optarg));
                modules_load_file = android::base::Basename(optarg);
                break;
            case 'b':
                blocklist = true;
                break;
            case 'd':
                mod_dirs.emplace_back(optarg);
                break;
            case 'D':
                check_mode();
                mode = ShowDependenciesMode;
                break;
            case 'h':
                android::base::SetMinimumLogSeverity(android::base::INFO);
                print_usage();
                return rv;
            case 'l':
                check_mode();
                mode = ListModulesMode;
                break;
            case 'q':
                android::base::SetMinimumLogSeverity(android::base::WARNING);
                break;
            case 'r':
                check_mode();
                mode = RemoveModulesMode;
                break;
            case 's':
                syslog = true;
                break;
            case 'v':
                if (android::base::GetMinimumLogSeverity() <= android::base::DEBUG) {
                    android::base::SetMinimumLogSeverity(android::base::VERBOSE);
                } else {
                    android::base::SetMinimumLogSeverity(android::base::DEBUG);
                }
                break;
            default:
                LOG(ERROR) << "Unrecognized option: " << opt;
                print_usage();
                return EXIT_FAILURE;
        }
    }

    int parameter_count = 0;
    for (opt = optind; opt < argc; opt++) {
        if (!strchr(argv[opt], '=')) {
            modules.emplace_back(argv[opt]);
        } else {
            parameter_count++;
            if (module_parameters.empty()) {
                module_parameters = argv[opt];
            } else {
                module_parameters = module_parameters + " " + argv[opt];
            }
        }
    }

    if (mod_dirs.empty()) {
        static constexpr auto LIB_MODULES_PREFIX = "/lib/modules/";
        dirent** kernel_dirs = NULL;

        int n = scandir(LIB_MODULES_PREFIX, &kernel_dirs, KernelVersionNameFilter, NULL);
        if (n == -1) {
            PLOG(ERROR) << "Failed to scan dir " << LIB_MODULES_PREFIX;
            return EXIT_FAILURE;
        } else if (n > 0) {
            while (n--) {
                mod_dirs.emplace_back(LIB_MODULES_PREFIX + std::string(kernel_dirs[n]->d_name));
            }
        }
        free(kernel_dirs);

        if (mod_dirs.empty() || getpagesize() == 4096) {
            // Allow modules to be directly inside /lib/modules
            mod_dirs.emplace_back(LIB_MODULES_PREFIX);
        }
    }

    LOG(DEBUG) << "mode is " << mode;
    LOG(DEBUG) << "mod_dirs is: " << android::base::Join(mod_dirs, " ");
    LOG(DEBUG) << "modules is: " << android::base::Join(modules, " ");
    LOG(DEBUG) << "modules load file is: " << modules_load_file;
    LOG(DEBUG) << "module parameters is: " << android::base::Join(module_parameters, " ");

    if (modules.empty()) {
        if (mode == ListModulesMode) {
            // emulate toybox modprobe list with no pattern (list all)
            modules.emplace_back("*");
        } else if (modules_load_file.empty()) {
            LOG(ERROR) << "No modules given.";
            print_usage();
            return EXIT_FAILURE;
        }
    }
    if (parameter_count && (modules.size() > 1 || !modules_load_file.empty())) {
        LOG(ERROR) << "Only one module may be loaded when specifying module parameters.";
        print_usage();
        return EXIT_FAILURE;
    }

    Modprobe m(mod_dirs, modules_load_file.empty() ? "modules.load" : modules_load_file, blocklist);
    if (mode == AddModulesMode && !modules_load_file.empty()) {
        if (!m.LoadListedModules(false)) {
            PLOG(ERROR) << "Failed to load all the modules from " << modules_load_file;
            return EXIT_FAILURE;
        }
        /* Fall-through to load modules provided on the command line (if any)*/
    }

    for (const auto& module : modules) {
        switch (mode) {
            case AddModulesMode:
                if (!m.LoadWithAliases(module, true, module_parameters)) {
                    if (m.IsBlocklisted(module)) continue;
                    PLOG(ERROR) << "Failed to load module " << module;
                    rv = EXIT_FAILURE;
                }
                break;
            case RemoveModulesMode:
                if (!m.Remove(module)) {
                    PLOG(ERROR) << "Failed to remove module " << module;
                    rv = EXIT_FAILURE;
                }
                break;
            case ListModulesMode: {
                std::vector<std::string> list = m.ListModules(module);
                LOG(INFO) << android::base::Join(list, "\n");
                break;
            }
            case ShowDependenciesMode: {
                std::vector<std::string> pre_deps;
                std::vector<std::string> deps;
                std::vector<std::string> post_deps;
                if (!m.GetAllDependencies(module, &pre_deps, &deps, &post_deps)) {
                    rv = EXIT_FAILURE;
                    break;
                }
                LOG(INFO) << "Dependencies for " << module << ":";
                LOG(INFO) << "Soft pre-dependencies:";
                LOG(INFO) << android::base::Join(pre_deps, "\n");
                LOG(INFO) << "Hard dependencies:";
                LOG(INFO) << android::base::Join(deps, "\n");
                LOG(INFO) << "Soft post-dependencies:";
                LOG(INFO) << android::base::Join(post_deps, "\n");
                break;
            }
            default:
                LOG(ERROR) << "Bad mode";
                rv = EXIT_FAILURE;
        }
    }

    return rv;
}
