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

#include "client/mdns_utils.h"

#include <gtest/gtest.h>

namespace mdns {

TEST(mdns_utils, mdns_parse_instance_name) {
    // Just the instance name
    {
        std::string str = ".";
        auto res = mdns_parse_instance_name(str);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(str, res->instance_name);
        EXPECT_TRUE(res->service_name.empty());
        EXPECT_TRUE(res->transport_type.empty());
    }
    {
        std::string str = "my.name";
        auto res = mdns_parse_instance_name(str);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(str, res->instance_name);
        EXPECT_TRUE(res->service_name.empty());
        EXPECT_TRUE(res->transport_type.empty());
    }
    {
        std::string str = "my.name.";
        auto res = mdns_parse_instance_name(str);
        ASSERT_TRUE(res.has_value());
        EXPECT_EQ(str, res->instance_name);
        EXPECT_TRUE(res->service_name.empty());
        EXPECT_TRUE(res->transport_type.empty());
    }

    // With "_tcp", "_udp" transport type
    for (const std::string_view transport : {"._tcp", "._udp"}) {
        {
            std::string str = android::base::StringPrintf("%s", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("%s.", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("service%s", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf(".service%s", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("service.%s", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("my.service%s", transport.data());
            auto res = mdns_parse_instance_name(str);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ(res->instance_name, "my");
            EXPECT_EQ(res->service_name, "service");
            EXPECT_EQ(res->transport_type, transport.substr(1));
        }
        {
            std::string str = android::base::StringPrintf("my.service%s.", transport.data());
            auto res = mdns_parse_instance_name(str);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ(res->instance_name, "my");
            EXPECT_EQ(res->service_name, "service");
            EXPECT_EQ(res->transport_type, transport.substr(1));
        }
        {
            std::string str = android::base::StringPrintf("my..service%s", transport.data());
            auto res = mdns_parse_instance_name(str);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ(res->instance_name, "my.");
            EXPECT_EQ(res->service_name, "service");
            EXPECT_EQ(res->transport_type, transport.substr(1));
        }
        {
            std::string str = android::base::StringPrintf("my.name.service%s.", transport.data());
            auto res = mdns_parse_instance_name(str);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ(res->instance_name, "my.name");
            EXPECT_EQ(res->service_name, "service");
            EXPECT_EQ(res->transport_type, transport.substr(1));
        }
        {
            std::string str = android::base::StringPrintf("name.service.%s.", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }

        // With ".local" domain
        {
            std::string str = ".local";
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = ".local.";
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = "name.local";
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("%s.local", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("service%s.local", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str = android::base::StringPrintf("name.service%s.local", transport.data());
            auto res = mdns_parse_instance_name(str);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ(res->instance_name, "name");
            EXPECT_EQ(res->service_name, "service");
            EXPECT_EQ(res->transport_type, transport.substr(1));
        }
        {
            std::string str =
                    android::base::StringPrintf("name.service%s.local.", transport.data());
            auto res = mdns_parse_instance_name(str);
            ASSERT_TRUE(res.has_value());
            EXPECT_EQ(res->instance_name, "name");
            EXPECT_EQ(res->service_name, "service");
            EXPECT_EQ(res->transport_type, transport.substr(1));
        }
        {
            std::string str =
                    android::base::StringPrintf("name.service%s..local.", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
        {
            std::string str =
                    android::base::StringPrintf("name.service.%s.local.", transport.data());
            auto res = mdns_parse_instance_name(str);
            EXPECT_FALSE(res.has_value());
        }
    }
}

}  // namespace mdns
