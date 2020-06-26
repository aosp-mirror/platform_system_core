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

#include <iostream>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <modprobe/modprobe.h>

namespace {

enum modprobe_mode {
    AddModulesMode,
    RemoveModulesMode,
    ListModulesMode,
    ShowDependenciesMode,
};

void print_usage(void) {
    std::cerr << "Usage:" << std::endl;
    std::cerr << std::endl;
    // -d option is required on Android
    std::cerr << "  modprobe [options] -d DIR MODULE..." << std::endl;
    std::cerr << "  modprobe [options] -d DIR MODULE [symbol=value]..." << std::endl;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  -b, --use-blocklist: Apply blocklist to module names too" << std::endl;
    std::cerr << "  -d, --dirname=DIR: Load modules from DIR, option may be used multiple times"
              << std::endl;
    std::cerr << "  -D, --show-depends: Print dependencies for modules only, do not load"
              << std::endl;
    std::cerr << "  -h, --help: Print this help" << std::endl;
    std::cerr << "  -l, --list: List modules matching pattern" << std::endl;
    std::cerr << "  -r, --remove: Remove MODULE (multiple modules may be specified)" << std::endl;
    std::cerr << "  -q, --quiet: disable messages" << std::endl;
    std::cerr << "  -v, --verbose: enable more messages" << std::endl;
    std::cerr << std::endl;
}

#define check_mode()                                                      \
    if (mode != AddModulesMode) {                                         \
        std::cerr << "Error, multiple mode flags specified" << std::endl; \
        print_usage();                                                    \
        return EXIT_FAILURE;                                              \
    }

}  // anonymous namespace

extern "C" int modprobe_main(int argc, char** argv) {
    std::vector<std::string> modules;
    std::string module_parameters;
    std::vector<std::string> mod_dirs;
    modprobe_mode mode = AddModulesMode;
    bool blocklist = false;
    bool verbose = false;
    int rv = EXIT_SUCCESS;

    int opt;
    int option_index = 0;
    // NB: We have non-standard short options -l and -D to make it easier for
    // OEMs to transition from toybox.
    // clang-format off
    static struct option long_options[] = {
        { "all",                 no_argument,       0, 'a' },
        { "use-blocklist",       no_argument,       0, 'b' },
        { "dirname",             required_argument, 0, 'd' },
        { "show-depends",        no_argument,       0, 'D' },
        { "help",                no_argument,       0, 'h' },
        { "list",                no_argument,       0, 'l' },
        { "quiet",               no_argument,       0, 'q' },
        { "remove",              no_argument,       0, 'r' },
        { "verbose",             no_argument,       0, 'v' },
    };
    // clang-format on
    while ((opt = getopt_long(argc, argv, "abd:Dhlqrv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a':
                // toybox modprobe supported -a to load multiple modules, this
                // is supported here by default, ignore flag
                check_mode();
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
                print_usage();
                return EXIT_SUCCESS;
            case 'l':
                check_mode();
                mode = ListModulesMode;
                break;
            case 'q':
                verbose = false;
                break;
            case 'r':
                check_mode();
                mode = RemoveModulesMode;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                std::cerr << "Unrecognized option: " << opt << std::endl;
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

    if (verbose) {
        std::cout << "mode is " << mode << std::endl;
        std::cout << "verbose is " << verbose << std::endl;
        std::cout << "mod_dirs is: " << android::base::Join(mod_dirs, " ") << std::endl;
        std::cout << "modules is: " << android::base::Join(modules, " ") << std::endl;
        std::cout << "module parameters is: " << android::base::Join(module_parameters, " ")
                  << std::endl;
    }

    if (modules.empty()) {
        if (mode == ListModulesMode) {
            // emulate toybox modprobe list with no pattern (list all)
            modules.emplace_back("*");
        } else {
            std::cerr << "No modules given." << std::endl;
            print_usage();
            return EXIT_FAILURE;
        }
    }
    if (mod_dirs.empty()) {
        std::cerr << "No module configuration directories given." << std::endl;
        print_usage();
        return EXIT_FAILURE;
    }
    if (parameter_count && modules.size() > 1) {
        std::cerr << "Only one module may be loaded when specifying module parameters."
                  << std::endl;
        print_usage();
        return EXIT_FAILURE;
    }

    Modprobe m(mod_dirs);
    m.EnableVerbose(verbose);
    if (blocklist) {
        m.EnableBlocklist(true);
    }

    for (const auto& module : modules) {
        switch (mode) {
            case AddModulesMode:
                if (!m.LoadWithAliases(module, true, module_parameters)) {
                    std::cerr << "Failed to load module " << module << std::endl;
                    rv = EXIT_FAILURE;
                }
                break;
            case RemoveModulesMode:
                if (!m.Remove(module)) {
                    std::cerr << "Failed to remove module " << module << std::endl;
                    rv = EXIT_FAILURE;
                }
                break;
            case ListModulesMode: {
                std::vector<std::string> list = m.ListModules(module);
                std::cout << android::base::Join(list, "\n") << std::endl;
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
                std::cout << "Dependencies for " << module << ":" << std::endl;
                std::cout << "Soft pre-dependencies:" << std::endl;
                std::cout << android::base::Join(pre_deps, "\n") << std::endl;
                std::cout << "Hard dependencies:" << std::endl;
                std::cout << android::base::Join(deps, "\n") << std::endl;
                std::cout << "Soft post-dependencies:" << std::endl;
                std::cout << android::base::Join(post_deps, "\n") << std::endl;
                break;
            }
            default:
                std::cerr << "Bad mode" << std::endl;
                rv = EXIT_FAILURE;
        }
    }

    return rv;
}
