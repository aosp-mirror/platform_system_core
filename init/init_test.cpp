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

#include <fstream>
#include <functional>
#include <string_view>
#include <thread>
#include <type_traits>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android/api-level.h>
#include <gtest/gtest.h>
#include <selinux/selinux.h>
#include <sys/resource.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "builtin_arguments.h"
#include "builtins.h"
#include "import_parser.h"
#include "init.h"
#include "keyword_map.h"
#include "parser.h"
#include "service.h"
#include "service_list.h"
#include "service_parser.h"
#include "util.h"

using android::base::GetIntProperty;
using android::base::GetProperty;
using android::base::SetProperty;
using android::base::StringPrintf;
using android::base::StringReplace;
using android::base::WaitForProperty;
using namespace std::literals;

namespace android {
namespace init {

using ActionManagerCommand = std::function<void(ActionManager&)>;

void TestInit(const std::string& init_script_file, const BuiltinFunctionMap& test_function_map,
              const std::vector<ActionManagerCommand>& commands, ActionManager* action_manager,
              ServiceList* service_list) {
    Action::set_function_map(&test_function_map);

    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(service_list, nullptr));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(action_manager, nullptr));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    ASSERT_TRUE(parser.ParseConfig(init_script_file));

    for (const auto& command : commands) {
        command(*action_manager);
    }

    while (action_manager->HasMoreCommands()) {
        action_manager->ExecuteOneCommand();
    }
}

void TestInitText(const std::string& init_script, const BuiltinFunctionMap& test_function_map,
                  const std::vector<ActionManagerCommand>& commands, ActionManager* action_manager,
                  ServiceList* service_list) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));
    TestInit(tf.path, test_function_map, commands, action_manager, service_list);
}

TEST(init, SimpleEventTrigger) {
    bool expect_true = false;
    std::string init_script =
        R"init(
on boot
pass_test
)init";

    auto do_pass_test = [&expect_true](const BuiltinArguments&) {
        expect_true = true;
        return Result<void>{};
    };
    BuiltinFunctionMap test_function_map = {
            {"pass_test", {0, 0, {false, do_pass_test}}},
    };

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    ActionManager action_manager;
    ServiceList service_list;
    TestInitText(init_script, test_function_map, commands, &action_manager, &service_list);

    EXPECT_TRUE(expect_true);
}

TEST(init, WrongEventTrigger) {
    std::string init_script =
            R"init(
on boot:
pass_test
)init";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));

    ActionManager am;

    Parser parser;
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));

    ASSERT_TRUE(parser.ParseConfig(tf.path));
    ASSERT_EQ(1u, parser.parse_error_count());
}

TEST(init, EventTriggerOrder) {
    std::string init_script =
        R"init(
on boot
execute_first

on boot && property:ro.hardware=*
execute_second

on boot
execute_third

)init";

    int num_executed = 0;
    auto do_execute_first = [&num_executed](const BuiltinArguments&) {
        EXPECT_EQ(0, num_executed++);
        return Result<void>{};
    };
    auto do_execute_second = [&num_executed](const BuiltinArguments&) {
        EXPECT_EQ(1, num_executed++);
        return Result<void>{};
    };
    auto do_execute_third = [&num_executed](const BuiltinArguments&) {
        EXPECT_EQ(2, num_executed++);
        return Result<void>{};
    };

    BuiltinFunctionMap test_function_map = {
            {"execute_first", {0, 0, {false, do_execute_first}}},
            {"execute_second", {0, 0, {false, do_execute_second}}},
            {"execute_third", {0, 0, {false, do_execute_third}}},
    };

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    ActionManager action_manager;
    ServiceList service_list;
    TestInitText(init_script, test_function_map, commands, &action_manager, &service_list);
    EXPECT_EQ(3, num_executed);
}

TEST(init, OverrideService) {
    std::string init_script = R"init(
service A something
    class first
    user nobody

service A something
    class second
    user nobody
    override

)init";

    ActionManager action_manager;
    ServiceList service_list;
    TestInitText(init_script, BuiltinFunctionMap(), {}, &action_manager, &service_list);
    ASSERT_EQ(1, std::distance(service_list.begin(), service_list.end()));

    auto service = service_list.begin()->get();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(std::set<std::string>({"second"}), service->classnames());
    EXPECT_EQ("A", service->name());
    EXPECT_TRUE(service->is_override());
}

TEST(init, StartConsole) {
    if (GetProperty("ro.build.type", "") == "user") {
        GTEST_SKIP() << "Must run on userdebug/eng builds. b/262090304";
        return;
    }
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string init_script = R"init(
service console /system/bin/sh
    class core
    console null
    disabled
    user root
    group root shell log readproc
    seclabel u:r:shell:s0
    setenv HOSTNAME console
)init";

    ActionManager action_manager;
    ServiceList service_list;
    TestInitText(init_script, BuiltinFunctionMap(), {}, &action_manager, &service_list);
    ASSERT_EQ(std::distance(service_list.begin(), service_list.end()), 1);

    auto service = service_list.begin()->get();
    ASSERT_NE(service, nullptr);
    ASSERT_RESULT_OK(service->Start());
    const pid_t pid = service->pid();
    ASSERT_GT(pid, 0);
    EXPECT_NE(getsid(pid), 0);
    service->Stop();
}

static std::string GetSecurityContext() {
    char* ctx;
    if (getcon(&ctx) == -1) {
        ADD_FAILURE() << "Failed to call getcon : " << strerror(errno);
    }
    std::string result = std::string(ctx);
    freecon(ctx);
    return result;
}

void TestStartApexServices(const std::vector<std::string>& service_names,
        const std::string& apex_name) {
    for (auto const& svc : service_names) {
        auto service = ServiceList::GetInstance().FindService(svc);
        ASSERT_NE(nullptr, service);
        ASSERT_RESULT_OK(service->Start());
        ASSERT_TRUE(service->IsRunning());
        LOG(INFO) << "Service " << svc << " is running";
        if (!apex_name.empty()) {
            service->set_filename("/apex/" + apex_name + "/init_test.rc");
        } else {
            service->set_filename("");
        }
    }
    if (!apex_name.empty()) {
        auto apex_services = ServiceList::GetInstance().FindServicesByApexName(apex_name);
        EXPECT_EQ(service_names.size(), apex_services.size());
    }
}

void TestStopApexServices(const std::vector<std::string>& service_names, bool expect_to_run) {
    for (auto const& svc : service_names) {
        auto service = ServiceList::GetInstance().FindService(svc);
        ASSERT_NE(nullptr, service);
        EXPECT_EQ(expect_to_run, service->IsRunning());
    }
}

void TestRemoveApexService(const std::vector<std::string>& service_names, bool exist) {
    for (auto const& svc : service_names) {
        auto service = ServiceList::GetInstance().FindService(svc);
        ASSERT_EQ(exist, service != nullptr);
    }
}

void InitApexService(const std::string_view& init_template) {
    std::string init_script = StringReplace(init_template, "$selabel",
                                    GetSecurityContext(), true);

    TestInitText(init_script, BuiltinFunctionMap(), {}, &ActionManager::GetInstance(),
            &ServiceList::GetInstance());
}

void CleanupApexServices() {
    std::vector<std::string> names;
    for (const auto& s : ServiceList::GetInstance()) {
        names.push_back(s->name());
    }

    for (const auto& name : names) {
        auto s = ServiceList::GetInstance().FindService(name);
        auto pid = s->pid();
        ServiceList::GetInstance().RemoveService(*s);
        if (pid > 0) {
            kill(pid, SIGTERM);
            kill(pid, SIGKILL);
        }
    }

    ActionManager::GetInstance().RemoveActionIf([&](const std::unique_ptr<Action>& s) -> bool {
        return true;
    });
}

void TestApexServicesInit(const std::vector<std::string>& apex_services,
            const std::vector<std::string>& other_apex_services,
            const std::vector<std::string> non_apex_services) {
    auto num_svc = apex_services.size() + other_apex_services.size() + non_apex_services.size();
    ASSERT_EQ(num_svc, ServiceList::GetInstance().size());

    TestStartApexServices(apex_services, "com.android.apex.test_service");
    TestStartApexServices(other_apex_services, "com.android.other_apex.test_service");
    TestStartApexServices(non_apex_services, /*apex_anme=*/ "");

    StopServicesFromApex("com.android.apex.test_service");
    TestStopApexServices(apex_services, /*expect_to_run=*/ false);
    TestStopApexServices(other_apex_services, /*expect_to_run=*/ true);
    TestStopApexServices(non_apex_services, /*expect_to_run=*/ true);

    RemoveServiceAndActionFromApex("com.android.apex.test_service");
    ASSERT_EQ(other_apex_services.size() + non_apex_services.size(),
        ServiceList::GetInstance().size());

    // TODO(b/244232142): Add test to check if actions are removed
    TestRemoveApexService(apex_services, /*exist*/ false);
    TestRemoveApexService(other_apex_services, /*exist*/ true);
    TestRemoveApexService(non_apex_services, /*exist*/ true);

    CleanupApexServices();
}

TEST(init, StopServiceByApexName) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string_view script_template = R"init(
service apex_test_service /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(script_template);
    TestApexServicesInit({"apex_test_service"}, {}, {});
}

TEST(init, StopMultipleServicesByApexName) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string_view script_template = R"init(
service apex_test_service_multiple_a /system/bin/yes
    user shell
    group shell
    seclabel $selabel
service apex_test_service_multiple_b /system/bin/id
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(script_template);
    TestApexServicesInit({"apex_test_service_multiple_a",
            "apex_test_service_multiple_b"}, {}, {});
}

TEST(init, StopServicesFromMultipleApexes) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string_view apex_script_template = R"init(
service apex_test_service_multi_apex_a /system/bin/yes
    user shell
    group shell
    seclabel $selabel
service apex_test_service_multi_apex_b /system/bin/id
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(apex_script_template);

    std::string_view other_apex_script_template = R"init(
service apex_test_service_multi_apex_c /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(other_apex_script_template);

    TestApexServicesInit({"apex_test_service_multi_apex_a",
            "apex_test_service_multi_apex_b"}, {"apex_test_service_multi_apex_c"}, {});
}

TEST(init, StopServicesFromApexAndNonApex) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string_view apex_script_template = R"init(
service apex_test_service_apex_a /system/bin/yes
    user shell
    group shell
    seclabel $selabel
service apex_test_service_apex_b /system/bin/id
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(apex_script_template);

    std::string_view non_apex_script_template = R"init(
service apex_test_service_non_apex /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(non_apex_script_template);

    TestApexServicesInit({"apex_test_service_apex_a",
            "apex_test_service_apex_b"}, {}, {"apex_test_service_non_apex"});
}

TEST(init, StopServicesFromApexMixed) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string_view script_template = R"init(
service apex_test_service_mixed_a /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(script_template);

    std::string_view other_apex_script_template = R"init(
service apex_test_service_mixed_b /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(other_apex_script_template);

    std::string_view non_apex_script_template = R"init(
service apex_test_service_mixed_c /system/bin/yes
    user shell
    group shell
    seclabel $selabel
)init";
    InitApexService(non_apex_script_template);

    TestApexServicesInit({"apex_test_service_mixed_a"},
            {"apex_test_service_mixed_b"}, {"apex_test_service_mixed_c"});
}

TEST(init, EventTriggerOrderMultipleFiles) {
    // 6 total files, which should have their triggers executed in the following order:
    // 1: start - original script parsed
    // 2: first_import - immediately imported by first_script
    // 3: dir_a - file named 'a.rc' in dir; dir is imported after first_import
    // 4: a_import - file imported by dir_a
    // 5: dir_b - file named 'b.rc' in dir
    // 6: last_import - imported after dir is imported

    TemporaryFile first_import;
    ASSERT_TRUE(first_import.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 2", first_import.fd));

    TemporaryFile dir_a_import;
    ASSERT_TRUE(dir_a_import.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 4", dir_a_import.fd));

    TemporaryFile last_import;
    ASSERT_TRUE(last_import.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 6", last_import.fd));

    TemporaryDir dir;
    // clang-format off
    std::string dir_a_script = "import " + std::string(dir_a_import.path) + "\n"
                               "on boot\n"
                               "execute 3";
    // clang-format on
    // WriteFile() ensures the right mode is set
    ASSERT_RESULT_OK(WriteFile(std::string(dir.path) + "/a.rc", dir_a_script));

    ASSERT_RESULT_OK(WriteFile(std::string(dir.path) + "/b.rc", "on boot\nexecute 5"));

    // clang-format off
    std::string start_script = "import " + std::string(first_import.path) + "\n"
                               "import " + std::string(dir.path) + "\n"
                               "import " + std::string(last_import.path) + "\n"
                               "on boot\n"
                               "execute 1";
    // clang-format on
    TemporaryFile start;
    ASSERT_TRUE(android::base::WriteStringToFd(start_script, start.fd));

    int num_executed = 0;
    auto execute_command = [&num_executed](const BuiltinArguments& args) {
        EXPECT_EQ(2U, args.size());
        EXPECT_EQ(++num_executed, std::stoi(args[1]));
        return Result<void>{};
    };

    BuiltinFunctionMap test_function_map = {
            {"execute", {1, 1, {false, execute_command}}},
    };

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    ActionManager action_manager;
    ServiceList service_list;
    TestInit(start.path, test_function_map, commands, &action_manager, &service_list);

    EXPECT_EQ(6, num_executed);
}

BuiltinFunctionMap GetTestFunctionMapForLazyLoad(int& num_executed, ActionManager& action_manager) {
    auto execute_command = [&num_executed](const BuiltinArguments& args) {
        EXPECT_EQ(2U, args.size());
        EXPECT_EQ(++num_executed, std::stoi(args[1]));
        return Result<void>{};
    };
    auto load_command = [&action_manager](const BuiltinArguments& args) -> Result<void> {
        EXPECT_EQ(2U, args.size());
        Parser parser;
        parser.AddSectionParser("on", std::make_unique<ActionParser>(&action_manager, nullptr));
        if (!parser.ParseConfig(args[1])) {
            return Error() << "Failed to load";
        }
        return Result<void>{};
    };
    auto trigger_command = [&action_manager](const BuiltinArguments& args) {
        EXPECT_EQ(2U, args.size());
        LOG(INFO) << "Queue event trigger: " << args[1];
        action_manager.QueueEventTrigger(args[1]);
        return Result<void>{};
    };
    BuiltinFunctionMap test_function_map = {
            {"execute", {1, 1, {false, execute_command}}},
            {"load", {1, 1, {false, load_command}}},
            {"trigger", {1, 1, {false, trigger_command}}},
    };
    return test_function_map;
}

TEST(init, LazilyLoadedActionsCantBeTriggeredByTheSameTrigger) {
    // "start" script loads "lazy" script. Even though "lazy" scripts
    // defines "on boot" action, it's not executed by the current "boot"
    // event because it's already processed.
    TemporaryFile lazy;
    ASSERT_TRUE(lazy.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 2", lazy.fd));

    TemporaryFile start;
    // clang-format off
    std::string start_script = "on boot\n"
                               "load " + std::string(lazy.path) + "\n"
                               "execute 1";
    // clang-format on
    ASSERT_TRUE(android::base::WriteStringToFd(start_script, start.fd));

    int num_executed = 0;
    ActionManager action_manager;
    ServiceList service_list;
    BuiltinFunctionMap test_function_map =
            GetTestFunctionMapForLazyLoad(num_executed, action_manager);

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};
    TestInit(start.path, test_function_map, commands, &action_manager, &service_list);

    EXPECT_EQ(1, num_executed);
}

TEST(init, LazilyLoadedActionsCanBeTriggeredByTheNextTrigger) {
    // "start" script loads "lazy" script and then triggers "next" event
    // which executes "on next" action loaded by the previous command.
    TemporaryFile lazy;
    ASSERT_TRUE(lazy.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on next\nexecute 2", lazy.fd));

    TemporaryFile start;
    // clang-format off
    std::string start_script = "on boot\n"
                               "load " + std::string(lazy.path) + "\n"
                               "execute 1\n"
                               "trigger next";
    // clang-format on
    ASSERT_TRUE(android::base::WriteStringToFd(start_script, start.fd));

    int num_executed = 0;
    ActionManager action_manager;
    ServiceList service_list;
    BuiltinFunctionMap test_function_map =
            GetTestFunctionMapForLazyLoad(num_executed, action_manager);

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};
    TestInit(start.path, test_function_map, commands, &action_manager, &service_list);

    EXPECT_EQ(2, num_executed);
}

TEST(init, RejectsNoUserStartingInV) {
    std::string init_script =
            R"init(
service A something
    class first
)init";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));

    ServiceList service_list;
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, nullptr));

    ASSERT_TRUE(parser.ParseConfig(tf.path));

    if (GetIntProperty("ro.vendor.api_level", 0) > 202404) {
        ASSERT_EQ(1u, parser.parse_error_count());
    } else {
        ASSERT_EQ(0u, parser.parse_error_count());
    }
}

TEST(init, RejectsCriticalAndOneshotService) {
    if (GetIntProperty("ro.product.first_api_level", 10000) < 30) {
        GTEST_SKIP() << "Test only valid for devices launching with R or later";
    }

    std::string init_script =
            R"init(
service A something
  class first
  user root
  critical
  oneshot
)init";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));

    ServiceList service_list;
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&service_list, nullptr));

    ASSERT_TRUE(parser.ParseConfig(tf.path));
    ASSERT_EQ(1u, parser.parse_error_count());
}

TEST(init, MemLockLimit) {
    // Test is enforced only for U+ devices
    if (android::base::GetIntProperty("ro.vendor.api_level", 0) < __ANDROID_API_U__) {
        GTEST_SKIP();
    }

    // Verify we are running memlock at, or under, 64KB
    const unsigned long max_limit = 65536;
    struct rlimit curr_limit;
    ASSERT_EQ(getrlimit(RLIMIT_MEMLOCK, &curr_limit), 0);
    ASSERT_LE(curr_limit.rlim_cur, max_limit);
    ASSERT_LE(curr_limit.rlim_max, max_limit);
}

void CloseAllFds() {
    DIR* dir;
    struct dirent* ent;
    int fd;

    if ((dir = opendir("/proc/self/fd"))) {
        while ((ent = readdir(dir))) {
            if (sscanf(ent->d_name, "%d", &fd) == 1) {
                close(fd);
            }
        }
        closedir(dir);
    }
}

pid_t ForkExecvpAsync(const char* argv[]) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child process.
        CloseAllFds();

        execvp(argv[0], const_cast<char**>(argv));
        PLOG(ERROR) << "exec in ForkExecvpAsync init test";
        _exit(EXIT_FAILURE);
    }
    // Parent process.
    if (pid == -1) {
        PLOG(ERROR) << "fork in ForkExecvpAsync init test";
        return -1;
    }
    return pid;
}

pid_t TracerPid(pid_t pid) {
    static constexpr std::string_view prefix{"TracerPid:"};
    std::ifstream is(StringPrintf("/proc/%d/status", pid));
    std::string line;
    while (std::getline(is, line)) {
        if (line.find(prefix) == 0) {
            return atoi(line.substr(prefix.length()).c_str());
        }
    }
    return -1;
}

TEST(init, GentleKill) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Must be run as root.";
        return;
    }
    std::string init_script = R"init(
service test_gentle_kill /system/bin/sleep 1000
    disabled
    oneshot
    gentle_kill
    user root
    group root
    seclabel u:r:toolbox:s0
)init";

    ActionManager action_manager;
    ServiceList service_list;
    TestInitText(init_script, BuiltinFunctionMap(), {}, &action_manager, &service_list);
    ASSERT_EQ(std::distance(service_list.begin(), service_list.end()), 1);

    auto service = service_list.begin()->get();
    ASSERT_NE(service, nullptr);
    ASSERT_RESULT_OK(service->Start());
    const pid_t pid = service->pid();
    ASSERT_GT(pid, 0);
    EXPECT_NE(getsid(pid), 0);

    TemporaryFile logfile;
    logfile.DoNotRemove();
    ASSERT_TRUE(logfile.fd != -1);

    std::string pid_str = std::to_string(pid);
    const char* argv[] = {"/system/bin/strace", "-o", logfile.path, "-e", "signal", "-p",
                          pid_str.c_str(),      nullptr};
    pid_t strace_pid = ForkExecvpAsync(argv);

    // Give strace the chance to connect
    while (TracerPid(pid) == 0) {
        std::this_thread::sleep_for(10ms);
    }
    service->Stop();

    int status;
    waitpid(strace_pid, &status, 0);

    std::string logs;
    android::base::ReadFdToString(logfile.fd, &logs);
    ASSERT_NE(logs.find("killed by SIGTERM"), std::string::npos);
}

class TestCaseLogger : public ::testing::EmptyTestEventListener {
    void OnTestStart(const ::testing::TestInfo& test_info) override {
#ifdef __ANDROID__
        LOG(INFO) << "===== " << test_info.test_suite_name() << "::" << test_info.name() << " ("
                  << test_info.file() << ":" << test_info.line() << ")";
#else
        UNUSED(test_info);
#endif
    }
};

}  // namespace init
}  // namespace android

int SubcontextTestChildMain(int, char**);
int FirmwareTestChildMain(int, char**);

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "subcontext")) {
        return SubcontextTestChildMain(argc, argv);
    }

    if (argc > 1 && !strcmp(argv[1], "firmware")) {
        return FirmwareTestChildMain(argc, argv);
    }

    testing::InitGoogleTest(&argc, argv);
    testing::UnitTest::GetInstance()->listeners().Append(new android::init::TestCaseLogger());
    return RUN_ALL_TESTS();
}
