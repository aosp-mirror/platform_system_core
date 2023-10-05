/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <errno.h>
#include <getopt.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <queue>

#include <android-base/expected.h>
#include <android-base/logging.h>
#include <android/frameworks/stats/BnStats.h>
#include <android/frameworks/stats/IStats.h>
#include <android/trusty/stats/nw/setter/IStatsSetter.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <binder/RpcTransportTipcAndroid.h>
#include <binder/RpcTrusty.h>
#include <trusty/tipc.h>

/** DOC:
 * ./build-root/build-qemu-generic-arm64-test-debug/run \
 *       --android $ANDROID_PROJECT_ROOT \
 *       --headless --shell-command \
 *       "/data/nativetest64/vendor/trusty_stats_test/trusty_stats_test"
 *
 * adb -s emulator-5554 shell \
 *       /data/nativetest64/vendor/trusty_stats_test/trusty_stats_test
 */
using ::android::base::unique_fd;
using ::android::binder::Status;
using ::android::frameworks::stats::BnStats;
using ::android::frameworks::stats::IStats;
using ::android::frameworks::stats::VendorAtom;
using ::android::frameworks::stats::VendorAtomValue;
using ::android::trusty::stats::nw::setter::IStatsSetter;

constexpr const char kTrustyDefaultDeviceName[] = "/dev/trusty-ipc-dev0";
constexpr const char kTrustyStatsSetterTest[] =
        "com.android.frameworks.stats.trusty.test.relayer.istats_setter";
constexpr const char kTrustyStatsSetterMetrics[] =
        "com.android.frameworks.stats.trusty.metrics.istats_setter";
constexpr const char kTrustyStatsPortTest[] = "com.android.trusty.stats.test";
constexpr const char kTrustyCrashPortTest[] = "com.android.trusty.crashtest";
constexpr const char kTrustyCrasherUuid[] = "7ee4dddc-177a-420a-96ea-5d413d88228e:crasher";

enum TrustyAtoms : int32_t {
    TrustyAppCrashed = 100072,
    TrustyError = 100145,
    TrustyStorageError = 100146
};

enum TestMsgHeader : int32_t {
    TEST_PASSED = 0,
    TEST_FAILED = 1,
    TEST_MESSAGE = 2,
};

namespace android {
namespace trusty {
namespace stats {

class Stats : public BnStats {
  public:
    Stats() : BnStats() {}

    Status reportVendorAtom(const VendorAtom& vendorAtom) override {
        const char* atomIdStr = vendorAtomStr(vendorAtom.atomId);
        ALOGD("Vendor atom reported of type: %s\n", atomIdStr);
        std::lock_guard lock(mLock);
        mQueueVendorAtom.push(vendorAtom);
        mCondVar.notify_one();
        return Status::ok();
    }

    status_t getVendorAtom(VendorAtom* pVendorAtom, int64_t waitForMs) {
        std::unique_lock lock(mLock);
        while (mQueueVendorAtom.empty()) {
            auto rc = mCondVar.wait_for(lock, std::chrono::milliseconds(waitForMs));
            if (rc == std::cv_status::timeout) {
                return TIMED_OUT;
            }
        }
        *pVendorAtom = mQueueVendorAtom.front();
        mQueueVendorAtom.pop();
        return NO_ERROR;
    }

  private:
    const char* vendorAtomStr(int32_t atomId) {
        switch (atomId) {
            case TrustyAtoms::TrustyAppCrashed:
                return "TrustyAtoms::TrustyAppCrashed";
            case TrustyAtoms::TrustyError:
                return "TrustyAtoms::TrustyError";
            case TrustyAtoms::TrustyStorageError:
                return "TrustyAtoms::TrustyStorageError";
            default:
                return "unknown TrustyAtoms type";
        }
    }
    std::mutex mLock;
    std::condition_variable mCondVar;
    std::queue<VendorAtom> mQueueVendorAtom;
};

class TrustyStatsTestBase : public ::testing::Test {
  protected:
    TrustyStatsTestBase(std::string&& portNameStatsSetter, std::string&& portNamePortTest)
        : mPortTestFd(-1),
          mPortNameStatsSetter(std::move(portNameStatsSetter)),
          mPortNamePortTest(std::move(portNamePortTest)) {}

    void SetUp() override {
        // Commenting out the server portion because we do not have any direct
        // incoming call Calls from TA are currently being handled on the mSession's
        // extra thread. android::sp<::android::RpcServer> server =
        // ::android::RpcServer::make(::android::RpcTransportCtxFactoryRaw::make());

        mStats = android::sp<Stats>::make();
        // Increasing number of incoming threads on mSession to be able to receive
        // callbacks
        auto session_initializer = [](sp<RpcSession>& session) {
            session->setMaxIncomingThreads(1);
        };

        ASSERT_FALSE(mSession);
        mSession = RpcTrustyConnectWithSessionInitializer(
                kTrustyDefaultDeviceName, mPortNameStatsSetter.c_str(), session_initializer);
        ASSERT_TRUE(mSession);

        auto root = mSession->getRootObject();
        ASSERT_TRUE(root);
        auto statsSetter = IStatsSetter::asInterface(root);
        ASSERT_TRUE(statsSetter);
        statsSetter->setInterface(mStats);
    }
    void TearDown() override {
        // close connection to unitest app
        if (mPortTestFd != -1) {
            tipc_close(mPortTestFd);
        }
        mPortTestFd = -1;

        if (mSession) {
            // shutdownAndWait here races with sending out the DecStrong
            // messages after reportVendorAtom returns, so we delay it a little
            // bit to give the messages time to go out over the transport
            usleep(50000);
            ASSERT_TRUE(mSession->shutdownAndWait(true));
        }
        mSession.clear();
        mStats.clear();
    }
    void StartPortTest() {
        // connect to unitest app
        mPortTestFd = tipc_connect(kTrustyDefaultDeviceName, mPortNamePortTest.c_str());
        if (mPortTestFd < 0) {
            ALOGE("Failed to connect to '%s' app: %s\n", kTrustyStatsPortTest,
                  strerror(-mPortTestFd));
        }
        ASSERT_GT(mPortTestFd, 0);
    }
    void WaitPortTestDone() {
        // wait for test to complete
        char rxBuf[1024];
        const char prolog[] = "Trusty PORT_TEST:";
        strncpy(rxBuf, prolog, sizeof(prolog) - 1);
        char* pRxBuf = rxBuf + sizeof(prolog) - 1;
        size_t remainingBufSize = sizeof(rxBuf) - sizeof(prolog) - 1;

        ASSERT_NE(mPortTestFd, -1);
        for (;;) {
            int rc = read(mPortTestFd, pRxBuf, remainingBufSize);
            ASSERT_GT(rc, 0);
            ASSERT_LT(rc, (int)remainingBufSize);
            if (pRxBuf[0] == TEST_PASSED) {
                break;
            } else if (pRxBuf[0] == TEST_FAILED) {
                break;
            } else if (pRxBuf[0] == TEST_MESSAGE) {
                pRxBuf[0] = ' ';
                write(STDOUT_FILENO, rxBuf, rc + sizeof(prolog) - 1);
            } else {
                ALOGE("Bad message header: %d\n", rxBuf[0]);
                break;
            }
        }
        ASSERT_EQ(pRxBuf[0], TEST_PASSED);
    }

    android::sp<Stats> mStats;

  private:
    android::sp<RpcSession> mSession;
    int mPortTestFd;
    std::string mPortNameStatsSetter;
    std::string mPortNamePortTest;
};

class TrustyStatsTest : public TrustyStatsTestBase {
  protected:
    TrustyStatsTest() : TrustyStatsTestBase(kTrustyStatsSetterTest, kTrustyStatsPortTest) {}
};

class TrustyMetricsCrashTest : public TrustyStatsTestBase {
  protected:
    TrustyMetricsCrashTest()
        : TrustyStatsTestBase(kTrustyStatsSetterMetrics, kTrustyCrashPortTest) {}
};

TEST_F(TrustyStatsTest, CheckAtoms) {
    int atomAppCrashedCnt = 0;
    int atomStorageErrorCnt = 0;
    int atomTrustyErrorCnt = 0;
    uint64_t blockForMs = 500;
    StartPortTest();
    WaitPortTestDone();
    for (;;) {
        VendorAtom vendorAtom;
        auto status = mStats->getVendorAtom(&vendorAtom, blockForMs);
        ASSERT_THAT(status, ::testing::AnyOf(NO_ERROR, TIMED_OUT));
        if (status == TIMED_OUT) {
            // No more atoms
            break;
        }

        ASSERT_THAT(vendorAtom.atomId,
                    ::testing::AnyOf(::testing::Eq(TrustyAtoms::TrustyAppCrashed),
                                     ::testing::Eq(TrustyAtoms::TrustyError),
                                     ::testing::Eq(TrustyAtoms::TrustyStorageError)));
        ASSERT_EQ(String8(vendorAtom.reverseDomainName), "google.android.trusty");
        switch (vendorAtom.atomId) {
            case TrustyAtoms::TrustyAppCrashed:
                ++atomAppCrashedCnt;
                ASSERT_EQ(String8(vendorAtom.values[0].get<VendorAtomValue::stringValue>()),
                          "5247d19b-cf09-4272-a450-3ef20dbefc14");
                break;
            case TrustyAtoms::TrustyStorageError:
                ++atomStorageErrorCnt;
                ASSERT_EQ(vendorAtom.values[0].get<VendorAtomValue::intValue>(), 5);
                ASSERT_EQ(String8(vendorAtom.values[1].get<VendorAtomValue::stringValue>()),
                          "5247d19b-cf09-4272-a450-3ef20dbefc14");
                ASSERT_EQ(String8(vendorAtom.values[2].get<VendorAtomValue::stringValue>()),
                          "5247d19b-cf09-4272-a450-3ef20dbefc14");
                ASSERT_EQ(vendorAtom.values[3].get<VendorAtomValue::intValue>(), 1);
                ASSERT_EQ(vendorAtom.values[4].get<VendorAtomValue::intValue>(), 3);
                ASSERT_EQ(vendorAtom.values[5].get<VendorAtomValue::longValue>(),
                          0x4BCDEFABBAFEDCBALL);
                ASSERT_EQ(vendorAtom.values[6].get<VendorAtomValue::intValue>(), 4);
                ASSERT_EQ(vendorAtom.values[7].get<VendorAtomValue::longValue>(), 1023);
                break;
            case TrustyAtoms::TrustyError:
                ++atomTrustyErrorCnt;
                break;
            default:
                FAIL() << "Unknown vendor atom ID: " << vendorAtom.atomId;
                break;
        }
    };
    ASSERT_EQ(atomAppCrashedCnt, 1);
    ASSERT_EQ(atomStorageErrorCnt, 1);
    ASSERT_EQ(atomTrustyErrorCnt, 0);
}

TEST_F(TrustyMetricsCrashTest, CheckTrustyCrashAtoms) {
    const std::vector<uint32_t> kExpectedCrashReasonsArm64{
            0x00000001U,  // exit_failure (twice)
            0x00000001U,
            0x92000004U,  // read_null_ptr
            0xf200002aU,  // brk_instruction
            0x92000004U,  // read_bad_ptr
            0x92000044U,  // crash_write_bad_ptr
            0x9200004fU,  // crash_write_ro_ptr
            0x8200000fU,  // crash_exec_rodata
            0x8200000fU,  // crash_exec_data
    };
    const std::vector<uint32_t> kExpectedCrashReasonsArm32{
            0x00000001U,  // exit_failure (twice)
            0x00000001U,
            0x20000007U,  // read_null_ptr
            0x20000007U,  // read_bad_ptr
            0x20000807U,  // crash_write_bad_ptr
            0x2000080fU,  // crash_write_ro_ptr
            0x3000000fU,  // crash_exec_rodata
            0x3000000fU,  // crash_exec_data
    };

    int expectedAtomCnt = 7;
    int atomAppCrashedCnt = 0;
    int atomStorageErrorCnt = 0;
    int atomTrustyErrorCnt = 0;
    std::vector<uint32_t> atomCrashReasons;
    uint64_t blockForMs = 500;
    StartPortTest();
    WaitPortTestDone();
    for (;;) {
        VendorAtom vendorAtom;
        auto status = mStats->getVendorAtom(&vendorAtom, blockForMs);
        ASSERT_THAT(status, ::testing::AnyOf(NO_ERROR, TIMED_OUT));
        if (status == TIMED_OUT) {
            // No more atoms
            break;
        }

        ASSERT_THAT(vendorAtom.atomId,
                    ::testing::AnyOf(::testing::Eq(TrustyAtoms::TrustyAppCrashed),
                                     ::testing::Eq(TrustyAtoms::TrustyError),
                                     ::testing::Eq(TrustyAtoms::TrustyStorageError)));
        ASSERT_EQ(String8(vendorAtom.reverseDomainName), "google.android.trusty");

        switch (vendorAtom.atomId) {
            case TrustyAtoms::TrustyAppCrashed:
                ++atomAppCrashedCnt;
                ASSERT_EQ(String8(vendorAtom.values[0].get<VendorAtomValue::stringValue>()),
                          kTrustyCrasherUuid);
                atomCrashReasons.push_back(vendorAtom.values[1].get<VendorAtomValue::intValue>());
                break;
            case TrustyAtoms::TrustyStorageError:
                ++atomStorageErrorCnt;
                break;
            case TrustyAtoms::TrustyError:
                ++atomTrustyErrorCnt;
                ASSERT_EQ(String8(vendorAtom.values[1].get<VendorAtomValue::stringValue>()), "");
                break;
            default:
                FAIL() << "Unknown vendor atom ID: " << vendorAtom.atomId;
        }
    }
    ASSERT_GE(atomAppCrashedCnt, expectedAtomCnt - 1);
    ASSERT_EQ(atomStorageErrorCnt, 0);
    // There is one dropped event left over from Trusty boot,
    // it may show up here
    ASSERT_LE(atomTrustyErrorCnt, 1);
    ASSERT_THAT(atomCrashReasons,
                ::testing::AnyOf(kExpectedCrashReasonsArm64, kExpectedCrashReasonsArm32));
};

}  // namespace stats
}  // namespace trusty
}  // namespace android
