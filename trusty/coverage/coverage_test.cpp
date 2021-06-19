/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <trusty/coverage/coverage.h>
#include <trusty/tipc.h>
#include <array>
#include <memory>

using android::base::unique_fd;
using std::array;
using std::make_unique;
using std::unique_ptr;

#define TIPC_DEV "/dev/trusty-ipc-dev0"
#define TEST_SRV_PORT "com.android.trusty.sancov.test.srv"
#define TEST_SRV_MODULE "srv.syms.elf"

namespace android {
namespace trusty {
namespace coverage {

/* Test server's UUID is 77f68803-c514-43ba-bdce-3254531c3d24 */
static struct uuid test_srv_uuid = {
        0x77f68803,
        0xc514,
        0x43ba,
        {0xbd, 0xce, 0x32, 0x54, 0x53, 0x1c, 0x3d, 0x24},
};

class CoverageTest : public ::testing::Test {
  public:
    void SetUp() override {
        record_ = make_unique<CoverageRecord>(TIPC_DEV, &test_srv_uuid);
        auto ret = record_->Open();
        ASSERT_TRUE(ret.ok()) << ret.error();
    }

    void TearDown() override { record_.reset(); }

    unique_ptr<CoverageRecord> record_;
};

TEST_F(CoverageTest, CoverageReset) {
    record_->ResetFullRecord();
    auto counter = record_->TotalEdgeCounts();
    ASSERT_EQ(counter, 0);
}

TEST_F(CoverageTest, TestServerCoverage) {
    unique_fd test_srv(tipc_connect(TIPC_DEV, TEST_SRV_PORT));
    ASSERT_GE(test_srv, 0);

    uint32_t mask = (uint32_t)-1;
    uint32_t magic = 0xdeadbeef;
    uint64_t high_watermark = 0;

    for (size_t i = 1; i < sizeof(magic) * 8; i++) {
        /* Reset coverage */
        record_->ResetCounts();

        /* Send message to test server */
        uint32_t msg = magic & ~(mask << i);
        int rc = write(test_srv, &msg, sizeof(msg));
        ASSERT_EQ(rc, sizeof(msg));

        /* Read message from test server */
        rc = read(test_srv, &msg, sizeof(msg));
        ASSERT_EQ(rc, sizeof(msg));

        /* Count number of non-unique blocks executed */
        auto counter = record_->TotalEdgeCounts();
        /* Each consecutive input should exercise more or same blocks */
        ASSERT_GE(counter, high_watermark);
        high_watermark = counter;

        auto sancov_filename = android::base::StringPrintf(
                "/data/local/tmp/" TEST_SRV_MODULE ".%d.sancov", getpid());
        auto res = record_->SaveSancovFile(sancov_filename);
        ASSERT_TRUE(res.ok());
    }

    ASSERT_GT(high_watermark, 0);
}

}  // namespace coverage
}  // namespace trusty
}  // namespace android
