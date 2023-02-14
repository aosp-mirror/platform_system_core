//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "fastboot_driver.h"

#include <optional>

#include <gtest/gtest.h>
#include "mock_transport.h"

using namespace ::testing;
using namespace fastboot;

class DriverTest : public ::testing::Test {
  protected:
    InSequence s_;
};

TEST_F(DriverTest, GetVar) {
    MockTransport transport;
    FastBootDriver driver(&transport);

    EXPECT_CALL(transport, Write(_, _))
            .With(AllArgs(RawData("getvar:version")))
            .WillOnce(ReturnArg<1>());
    EXPECT_CALL(transport, Read(_, _)).WillOnce(Invoke(CopyData("OKAY0.4")));

    std::string output;
    ASSERT_EQ(driver.GetVar("version", &output), SUCCESS) << driver.Error();
    ASSERT_EQ(output, "0.4");
}

TEST_F(DriverTest, InfoMessage) {
    MockTransport transport;
    FastBootDriver driver(&transport);

    EXPECT_CALL(transport, Write(_, _))
            .With(AllArgs(RawData("oem dmesg")))
            .WillOnce(ReturnArg<1>());
    EXPECT_CALL(transport, Read(_, _)).WillOnce(Invoke(CopyData("INFOthis is an info line")));
    EXPECT_CALL(transport, Read(_, _)).WillOnce(Invoke(CopyData("OKAY")));

    std::vector<std::string> info;
    ASSERT_EQ(driver.RawCommand("oem dmesg", "", nullptr, &info), SUCCESS) << driver.Error();
    ASSERT_EQ(info.size(), size_t(1));
    ASSERT_EQ(info[0], "this is an info line");
}
