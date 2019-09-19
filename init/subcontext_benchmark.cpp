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

#include "subcontext.h"

#include <benchmark/benchmark.h>
#include <selinux/selinux.h>

namespace android {
namespace init {

static void BenchmarkSuccess(benchmark::State& state) {
    if (getuid() != 0) {
        state.SkipWithError("Skipping benchmark, must be run as root.");
        return;
    }
    char* context;
    if (getcon(&context) != 0) {
        state.SkipWithError("getcon() failed");
        return;
    }

    auto subcontext = Subcontext({"path"}, context);
    free(context);

    while (state.KeepRunning()) {
        subcontext.Execute(std::vector<std::string>{"return_success"});
    }

    if (subcontext.pid() > 0) {
        kill(subcontext.pid(), SIGTERM);
        kill(subcontext.pid(), SIGKILL);
    }
}

BENCHMARK(BenchmarkSuccess);

BuiltinFunctionMap BuildTestFunctionMap() {
    auto function = [](const BuiltinArguments& args) { return Result<void>{}; };
    BuiltinFunctionMap test_function_map = {
            {"return_success", {0, 0, {true, function}}},
    };
    return test_function_map;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(basename(argv[1]), "subcontext")) {
        auto test_function_map = android::init::BuildTestFunctionMap();
        return android::init::SubcontextMain(argc, argv, &test_function_map);
    }

    ::benchmark::Initialize(&argc, argv);
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    ::benchmark::RunSpecifiedBenchmarks();
}
