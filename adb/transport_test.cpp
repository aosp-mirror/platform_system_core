/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "transport.h"

#include <gtest/gtest.h>

#include "adb.h"
#include "fdevent_test.h"

struct TransportTest : public FdeventTest {};

static void DisconnectFunc(void* arg, atransport*) {
    int* count = reinterpret_cast<int*>(arg);
    ++*count;
}

TEST_F(TransportTest, RunDisconnects) {
    atransport t;
    // RunDisconnects() can be called with an empty atransport.
    t.RunDisconnects();

    int count = 0;
    adisconnect disconnect;
    disconnect.func = DisconnectFunc;
    disconnect.opaque = &count;
    t.AddDisconnect(&disconnect);
    t.RunDisconnects();
    ASSERT_EQ(1, count);

    // disconnect should have been removed automatically.
    t.RunDisconnects();
    ASSERT_EQ(1, count);

    count = 0;
    t.AddDisconnect(&disconnect);
    t.RemoveDisconnect(&disconnect);
    t.RunDisconnects();
    ASSERT_EQ(0, count);
}

TEST_F(TransportTest, SetFeatures) {
    atransport t;
    ASSERT_EQ(0U, t.features().size());

    t.SetFeatures(FeatureSetToString(FeatureSet{"foo"}));
    ASSERT_EQ(1U, t.features().size());
    ASSERT_TRUE(t.has_feature("foo"));

    t.SetFeatures(FeatureSetToString(FeatureSet{"foo", "bar"}));
    ASSERT_EQ(2U, t.features().size());
    ASSERT_TRUE(t.has_feature("foo"));
    ASSERT_TRUE(t.has_feature("bar"));

    t.SetFeatures(FeatureSetToString(FeatureSet{"foo", "bar", "foo"}));
    ASSERT_EQ(2U, t.features().size());
    ASSERT_TRUE(t.has_feature("foo"));
    ASSERT_TRUE(t.has_feature("bar"));

    t.SetFeatures(FeatureSetToString(FeatureSet{"bar", "baz"}));
    ASSERT_EQ(2U, t.features().size());
    ASSERT_FALSE(t.has_feature("foo"));
    ASSERT_TRUE(t.has_feature("bar"));
    ASSERT_TRUE(t.has_feature("baz"));

    t.SetFeatures("");
    ASSERT_EQ(0U, t.features().size());
}

TEST_F(TransportTest, parse_banner_no_features) {
    atransport t;

    parse_banner("host::", &t);

    ASSERT_EQ(0U, t.features().size());
    ASSERT_EQ(kCsHost, t.GetConnectionState());

    ASSERT_EQ(std::string(), t.product);
    ASSERT_EQ(std::string(), t.model);
    ASSERT_EQ(std::string(), t.device);
}

TEST_F(TransportTest, parse_banner_product_features) {
    atransport t;

    const char banner[] =
        "host::ro.product.name=foo;ro.product.model=bar;ro.product.device=baz;";
    parse_banner(banner, &t);

    ASSERT_EQ(kCsHost, t.GetConnectionState());

    ASSERT_EQ(0U, t.features().size());

    ASSERT_EQ(std::string("foo"), t.product);
    ASSERT_EQ(std::string("bar"), t.model);
    ASSERT_EQ(std::string("baz"), t.device);
}

TEST_F(TransportTest, parse_banner_features) {
    atransport t;
    const char banner[] =
        "host::ro.product.name=foo;ro.product.model=bar;ro.product.device=baz;"
        "features=woodly,doodly";
    parse_banner(banner, &t);

    ASSERT_EQ(kCsHost, t.GetConnectionState());

    ASSERT_EQ(2U, t.features().size());
    ASSERT_TRUE(t.has_feature("woodly"));
    ASSERT_TRUE(t.has_feature("doodly"));

    ASSERT_EQ(std::string("foo"), t.product);
    ASSERT_EQ(std::string("bar"), t.model);
    ASSERT_EQ(std::string("baz"), t.device);
}

TEST_F(TransportTest, test_matches_target) {
    std::string serial = "foo";
    std::string devpath = "/path/to/bar";
    std::string product = "test_product";
    std::string model = "test_model";
    std::string device = "test_device";

    atransport t;
    t.serial = &serial[0];
    t.devpath = &devpath[0];
    t.product = &product[0];
    t.model = &model[0];
    t.device = &device[0];

    // These tests should not be affected by the transport type.
    for (TransportType type : {kTransportAny, kTransportLocal}) {
        t.type = type;

        EXPECT_TRUE(t.MatchesTarget(serial));
        EXPECT_TRUE(t.MatchesTarget(devpath));
        EXPECT_TRUE(t.MatchesTarget("product:" + product));
        EXPECT_TRUE(t.MatchesTarget("model:" + model));
        EXPECT_TRUE(t.MatchesTarget("device:" + device));

        // Product, model, and device don't match without the prefix.
        EXPECT_FALSE(t.MatchesTarget(product));
        EXPECT_FALSE(t.MatchesTarget(model));
        EXPECT_FALSE(t.MatchesTarget(device));
    }
}

TEST_F(TransportTest, test_matches_target_local) {
    std::string serial = "100.100.100.100:5555";

    atransport t;
    t.serial = &serial[0];

    // Network address matching should only be used for local transports.
    for (TransportType type : {kTransportAny, kTransportLocal}) {
        t.type = type;
        bool should_match = (type == kTransportLocal);

        EXPECT_EQ(should_match, t.MatchesTarget("100.100.100.100"));
        EXPECT_EQ(should_match, t.MatchesTarget("tcp:100.100.100.100"));
        EXPECT_EQ(should_match, t.MatchesTarget("tcp:100.100.100.100:5555"));
        EXPECT_EQ(should_match, t.MatchesTarget("udp:100.100.100.100"));
        EXPECT_EQ(should_match, t.MatchesTarget("udp:100.100.100.100:5555"));

        // Wrong protocol, hostname, or port should never match.
        EXPECT_FALSE(t.MatchesTarget("100.100.100"));
        EXPECT_FALSE(t.MatchesTarget("100.100.100.100:"));
        EXPECT_FALSE(t.MatchesTarget("100.100.100.100:-1"));
        EXPECT_FALSE(t.MatchesTarget("100.100.100.100:5554"));
        EXPECT_FALSE(t.MatchesTarget("abc:100.100.100.100"));
    }
}
