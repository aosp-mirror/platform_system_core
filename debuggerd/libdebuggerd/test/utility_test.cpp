/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <sys/prctl.h>

#include "libdebuggerd/utility.h"

TEST(UtilityTest, describe_tagged_addr_ctrl) {
  EXPECT_EQ("", describe_tagged_addr_ctrl(0));
  EXPECT_EQ(" (PR_TAGGED_ADDR_ENABLE)", describe_tagged_addr_ctrl(PR_TAGGED_ADDR_ENABLE));
  EXPECT_EQ(" (PR_TAGGED_ADDR_ENABLE, PR_MTE_TCF_SYNC, mask 0xfffe)",
            describe_tagged_addr_ctrl(PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
                                      (0xfffe << PR_MTE_TAG_SHIFT)));
  EXPECT_EQ(
      " (PR_TAGGED_ADDR_ENABLE, PR_MTE_TCF_SYNC, PR_MTE_TCF_ASYNC, mask 0xfffe, unknown "
      "0xf0000000)",
      describe_tagged_addr_ctrl(0xf0000000 | PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_SYNC |
                                PR_MTE_TCF_ASYNC | (0xfffe << PR_MTE_TAG_SHIFT)));
}
