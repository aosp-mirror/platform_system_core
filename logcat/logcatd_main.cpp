/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <vector>

#include "logcat.h"

int main(int argc, char** argv, char** envp) {
    android_logcat_context ctx = create_android_logcat();
    if (!ctx) return -1;

    signal(SIGPIPE, exit);

    // Save and detect presence of -L or --last flag
    std::vector<std::string> args;
    bool last = false;
    for (int i = 0; i < argc; ++i) {
        if (!argv[i]) continue;
        args.push_back(std::string(argv[i]));
        if (!strcmp(argv[i], "-L") || !strcmp(argv[i], "--last")) last = true;
    }

    // Generate argv from saved content
    std::vector<const char*> argv_hold;
    for (auto& str : args) argv_hold.push_back(str.c_str());
    argv_hold.push_back(nullptr);

    int ret = 0;
    if (last) {
        // Run logcat command with -L flag
        ret = android_logcat_run_command(ctx, -1, -1, argv_hold.size() - 1,
                                         (char* const*)&argv_hold[0], envp);
        // Remove -L and --last flags from argument list
        for (std::vector<const char*>::iterator it = argv_hold.begin();
             it != argv_hold.end();) {
            if (!*it || (strcmp(*it, "-L") && strcmp(*it, "--last"))) {
                ++it;
            } else {
                it = argv_hold.erase(it);
            }
        }
        // fall through to re-run the command regardless of the arguments
        // passed in.  For instance, we expect -h to report help stutter.
    }

    // Run logcat command without -L flag
    int retval = android_logcat_run_command(ctx, -1, -1, argv_hold.size() - 1,
                                            (char* const*)&argv_hold[0], envp);
    if (!ret) ret = retval;
    retval = android_logcat_destroy(&ctx);
    if (!ret) ret = retval;
    return ret;
}
