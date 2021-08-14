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

#include "reboot.h"

#include <errno.h>
#include <unistd.h>

#include <memory>
#include <string_view>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>
#include <selinux/selinux.h>

#include "builtin_arguments.h"
#include "builtins.h"
#include "parser.h"
#include "service_list.h"
#include "service_parser.h"
#include "subcontext.h"
#include "util.h"

using namespace std::literals;

using android::base::GetProperty;
using android::base::Join;
using android::base::SetProperty;
using android::base::Split;
using android::base::StringReplace;
using android::base::WaitForProperty;
using android::base::WriteStringToFd;

namespace android {
namespace init {

class RebootTest : public ::testing::Test {
  public:
    RebootTest() {
        std::vector<std::string> names = GetServiceNames();
        if (!names.empty()) {
            ADD_FAILURE() << "Expected empty ServiceList but found: [" << Join(names, ',') << "]";
        }
    }

    ~RebootTest() {
        std::vector<std::string> names = GetServiceNames();
        for (const auto& name : names) {
            auto s = ServiceList::GetInstance().FindService(name);
            auto pid = s->pid();
            ServiceList::GetInstance().RemoveService(*s);
            if (pid > 0) {
                kill(pid, SIGTERM);
                kill(pid, SIGKILL);
            }
        }
    }

  private:
    std::vector<std::string> GetServiceNames() const {
        std::vector<std::string> names;
        for (const auto& s : ServiceList::GetInstance()) {
            names.push_back(s->name());
        }
        return names;
    }
};

std::string GetSecurityContext() {
    char* ctx;
    if (getcon(&ctx) == -1) {
        ADD_FAILURE() << "Failed to call getcon : " << strerror(errno);
    }
    std::string result = std::string(ctx);
    freecon(ctx);
    return result;
}

void AddTestService(const std::string& name) {
    static constexpr std::string_view kScriptTemplate = R"init(
service $name /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";

    std::string script = StringReplace(StringReplace(kScriptTemplate, "$name", name, false),
                                       "$selabel", GetSecurityContext(), false);
    ServiceList& service_list = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(&service_list, nullptr, std::nullopt));

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(WriteStringToFd(script, tf.fd));
    ASSERT_TRUE(parser.ParseConfig(tf.path));
}

TEST_F(RebootTest, StopServicesSIGTERM) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping test, must be run as root.";
        return;
    }

    AddTestService("A");
    AddTestService("B");

    auto service_a = ServiceList::GetInstance().FindService("A");
    ASSERT_NE(nullptr, service_a);
    auto service_b = ServiceList::GetInstance().FindService("B");
    ASSERT_NE(nullptr, service_b);

    ASSERT_RESULT_OK(service_a->Start());
    ASSERT_TRUE(service_a->IsRunning());
    ASSERT_RESULT_OK(service_b->Start());
    ASSERT_TRUE(service_b->IsRunning());

    std::unique_ptr<Service> oneshot_service;
    {
        auto result = Service::MakeTemporaryOneshotService(
                {"exec", GetSecurityContext(), "--", "/system/bin/yes"});
        ASSERT_RESULT_OK(result);
        oneshot_service = std::move(*result);
    }
    std::string oneshot_service_name = oneshot_service->name();
    oneshot_service->Start();
    ASSERT_TRUE(oneshot_service->IsRunning());
    ServiceList::GetInstance().AddService(std::move(oneshot_service));

    EXPECT_EQ(0, StopServicesAndLogViolations({"A", "B", oneshot_service_name}, 10s,
                                              /* terminate= */ true));
    EXPECT_FALSE(service_a->IsRunning());
    EXPECT_FALSE(service_b->IsRunning());
    // Oneshot services are deleted from the ServiceList after they are destroyed.
    auto oneshot_service_after_stop = ServiceList::GetInstance().FindService(oneshot_service_name);
    EXPECT_EQ(nullptr, oneshot_service_after_stop);
}

TEST_F(RebootTest, StopServicesSIGKILL) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping test, must be run as root.";
        return;
    }

    AddTestService("A");
    AddTestService("B");

    auto service_a = ServiceList::GetInstance().FindService("A");
    ASSERT_NE(nullptr, service_a);
    auto service_b = ServiceList::GetInstance().FindService("B");
    ASSERT_NE(nullptr, service_b);

    ASSERT_RESULT_OK(service_a->Start());
    ASSERT_TRUE(service_a->IsRunning());
    ASSERT_RESULT_OK(service_b->Start());
    ASSERT_TRUE(service_b->IsRunning());

    std::unique_ptr<Service> oneshot_service;
    {
        auto result = Service::MakeTemporaryOneshotService(
                {"exec", GetSecurityContext(), "--", "/system/bin/yes"});
        ASSERT_RESULT_OK(result);
        oneshot_service = std::move(*result);
    }
    std::string oneshot_service_name = oneshot_service->name();
    oneshot_service->Start();
    ASSERT_TRUE(oneshot_service->IsRunning());
    ServiceList::GetInstance().AddService(std::move(oneshot_service));

    EXPECT_EQ(0, StopServicesAndLogViolations({"A", "B", oneshot_service_name}, 10s,
                                              /* terminate= */ false));
    EXPECT_FALSE(service_a->IsRunning());
    EXPECT_FALSE(service_b->IsRunning());
    // Oneshot services are deleted from the ServiceList after they are destroyed.
    auto oneshot_service_after_stop = ServiceList::GetInstance().FindService(oneshot_service_name);
    EXPECT_EQ(nullptr, oneshot_service_after_stop);
}

}  // namespace init
}  // namespace android
