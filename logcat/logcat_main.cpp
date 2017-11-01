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

#include <log/logcat.h>

int main(int argc, char** argv, char** envp) {
    android_logcat_context ctx = create_android_logcat();
    if (!ctx) return -1;
    signal(SIGPIPE, exit);
    int retval = android_logcat_run_command(ctx, -1, -1, argc, argv, envp);
    int ret = android_logcat_destroy(&ctx);
    if (!ret) ret = retval;
    return ret;
}
