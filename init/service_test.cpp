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

#include "service.h"

#include <algorithm>
#include <memory>
#include <type_traits>
#include <vector>

#include <gtest/gtest.h>

TEST(service, pod_initialized) {
    constexpr auto memory_size = sizeof(Service);
    alignas(alignof(Service)) char old_memory[memory_size];

    for (std::size_t i = 0; i < memory_size; ++i) {
        old_memory[i] = 0xFF;
    }

    std::vector<std::string> dummy_args{"/bin/test"};
    Service* service_in_old_memory = new (old_memory) Service("test_old_memory", dummy_args);

    EXPECT_EQ(0U, service_in_old_memory->flags());
    EXPECT_EQ(0, service_in_old_memory->pid());
    EXPECT_EQ(0, service_in_old_memory->crash_count());
    EXPECT_EQ(0U, service_in_old_memory->uid());
    EXPECT_EQ(0U, service_in_old_memory->gid());
    EXPECT_EQ(0U, service_in_old_memory->namespace_flags());
    EXPECT_EQ(0, service_in_old_memory->keychord_id());
    EXPECT_EQ(IoSchedClass_NONE, service_in_old_memory->ioprio_class());
    EXPECT_EQ(0, service_in_old_memory->ioprio_pri());
    EXPECT_EQ(0, service_in_old_memory->priority());
    EXPECT_EQ(-1000, service_in_old_memory->oom_score_adjust());
    EXPECT_FALSE(service_in_old_memory->process_cgroup_empty());

    for (std::size_t i = 0; i < memory_size; ++i) {
        old_memory[i] = 0xFF;
    }

    Service* service_in_old_memory2 = new (old_memory)
        Service("test_old_memory", 0U, 0U, 0U, std::vector<gid_t>(), CapSet(), 0U, "", dummy_args);

    EXPECT_EQ(0U, service_in_old_memory2->flags());
    EXPECT_EQ(0, service_in_old_memory2->pid());
    EXPECT_EQ(0, service_in_old_memory2->crash_count());
    EXPECT_EQ(0U, service_in_old_memory2->uid());
    EXPECT_EQ(0U, service_in_old_memory2->gid());
    EXPECT_EQ(0U, service_in_old_memory2->namespace_flags());
    EXPECT_EQ(0, service_in_old_memory2->keychord_id());
    EXPECT_EQ(IoSchedClass_NONE, service_in_old_memory2->ioprio_class());
    EXPECT_EQ(0, service_in_old_memory2->ioprio_pri());
    EXPECT_EQ(0, service_in_old_memory2->priority());
    EXPECT_EQ(-1000, service_in_old_memory2->oom_score_adjust());
    EXPECT_FALSE(service_in_old_memory->process_cgroup_empty());
}
