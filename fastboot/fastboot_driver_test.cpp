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

#include <memory>
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
    std::unique_ptr<MockTransport> transport_pointer = std::make_unique<MockTransport>();
    MockTransport* transport = transport_pointer.get();
    FastBootDriver driver(std::move(transport_pointer));

    EXPECT_CALL(*transport, Write(_, _))
            .With(AllArgs(RawData("getvar:version")))
            .WillOnce(ReturnArg<1>());
    EXPECT_CALL(*transport, Read(_, _)).WillOnce(Invoke(CopyData("OKAY0.4")));

    std::string output;
    ASSERT_EQ(driver.GetVar("version", &output), SUCCESS) << driver.Error();
    ASSERT_EQ(output, "0.4");
}

TEST_F(DriverTest, InfoMessage) {
    std::unique_ptr<MockTransport> transport_pointer = std::make_unique<MockTransport>();
    MockTransport* transport = transport_pointer.get();
    FastBootDriver driver(std::move(transport_pointer));

    EXPECT_CALL(*transport, Write(_, _))
            .With(AllArgs(RawData("oem dmesg")))
            .WillOnce(ReturnArg<1>());
    EXPECT_CALL(*transport, Read(_, _)).WillOnce(Invoke(CopyData("INFOthis is an info line")));
    EXPECT_CALL(*transport, Read(_, _)).WillOnce(Invoke(CopyData("OKAY")));

    std::vector<std::string> info;
    ASSERT_EQ(driver.RawCommand("oem dmesg", "", nullptr, &info), SUCCESS) << driver.Error();
    ASSERT_EQ(info.size(), size_t(1));
    ASSERT_EQ(info[0], "this is an info line");
}

TEST_F(DriverTest, TextMessage) {
    std::string text;
    std::unique_ptr<MockTransport> transport_pointer = std::make_unique<MockTransport>();
    MockTransport* transport = transport_pointer.get();

    DriverCallbacks callbacks{[](const std::string&) {}, [](int) {}, [](const std::string&) {},
                              [&text](const std::string& extra_text) { text += extra_text; }};

    FastBootDriver driver(std::move(transport_pointer), callbacks);

    EXPECT_CALL(*transport, Write(_, _))
            .With(AllArgs(RawData("oem trusty runtest trusty.hwaes.bench")))
            .WillOnce(ReturnArg<1>());
    EXPECT_CALL(*transport, Read(_, _)).WillOnce(Invoke(CopyData("TEXTthis is a text line")));
    EXPECT_CALL(*transport, Read(_, _))
            .WillOnce(Invoke(
                    CopyData("TEXT, albeit very long and split over multiple TEXT messages.")));
    EXPECT_CALL(*transport, Read(_, _))
            .WillOnce(Invoke(CopyData("TEXT Indeed we can do that now with a TEXT message whenever "
                                      "we feel like it.")));
    EXPECT_CALL(*transport, Read(_, _))
            .WillOnce(Invoke(CopyData("TEXT Isn't that truly super cool?")));

    EXPECT_CALL(*transport, Read(_, _)).WillOnce(Invoke(CopyData("OKAY")));

    std::vector<std::string> info;
    ASSERT_EQ(driver.RawCommand("oem trusty runtest trusty.hwaes.bench", "", nullptr, &info),
              SUCCESS)
            << driver.Error();
    ASSERT_EQ(text,
              "this is a text line"
              ", albeit very long and split over multiple TEXT messages."
              " Indeed we can do that now with a TEXT message whenever we feel like it."
              " Isn't that truly super cool?");
}
