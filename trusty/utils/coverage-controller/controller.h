/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <trusty/line-coverage/coverage.h>
#include <array>
#include <memory>
#include <vector>
#include <set>

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define TEST_SRV_PORT "com.android.trusty.sancov.test.srv"
#define TEST_SRV_MODULE "srv.syms.elf"

#define UUID_STR_SIZE (37)

#define FLAG_NONE               0x0
#define FLAG_RUN                0x1
#define FLAG_TOGGLE_CLEAR       0x2

struct control {
    /* Written by controller, read by instrumented TA */
    uint64_t        cntrl_flags;
    uint64_t        read_buffer_cnt;

    /* Written by instrumented TA, read by controller */
    uint64_t        write_buffer_start_count;
    uint64_t        write_buffer_complete_count;
};

namespace android {
namespace trusty {
namespace controller {

class Controller {
  public:
    public:
        void run(std::string output_dir);

    private:
        std::vector<std::unique_ptr<line_coverage::CoverageRecord>>record_list_;
        std::set<struct uuid>uuid_set_;
        std::vector<std::string>uuid_list_;
        std::vector<uint64_t> counters;
        int coverage_srv_fd;

        void connectCoverageServer();
        void setUpShm();
};

}  // namespace controller
}  // namespace trusty
}  // namespace android
