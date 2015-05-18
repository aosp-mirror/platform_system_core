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

class TestTransport : public atransport {
public:
    bool operator==(const atransport& rhs) const {
        EXPECT_EQ(read_from_remote, rhs.read_from_remote);
        EXPECT_EQ(write_to_remote, rhs.write_to_remote);
        EXPECT_EQ(close, rhs.close);
        EXPECT_EQ(kick, rhs.kick);

        EXPECT_EQ(fd, rhs.fd);
        EXPECT_EQ(transport_socket, rhs.transport_socket);

        EXPECT_EQ(
            0, memcmp(&transport_fde, &rhs.transport_fde, sizeof(fdevent)));

        EXPECT_EQ(ref_count, rhs.ref_count);
        EXPECT_EQ(sync_token, rhs.sync_token);
        EXPECT_EQ(connection_state, rhs.connection_state);
        EXPECT_EQ(online, rhs.online);
        EXPECT_EQ(type, rhs.type);

        EXPECT_EQ(usb, rhs.usb);
        EXPECT_EQ(sfd, rhs.sfd);

        EXPECT_EQ(serial, rhs.serial);
        EXPECT_EQ(product, rhs.product);
        EXPECT_EQ(model, rhs.model);
        EXPECT_EQ(device, rhs.device);
        EXPECT_EQ(devpath, rhs.devpath);
        EXPECT_EQ(adb_port, rhs.adb_port);
        EXPECT_EQ(kicked, rhs.kicked);

        EXPECT_EQ(
            0, memcmp(&disconnects, &rhs.disconnects, sizeof(adisconnect)));

        EXPECT_EQ(key, rhs.key);
        EXPECT_EQ(0, memcmp(token, rhs.token, TOKEN_SIZE));
        EXPECT_EQ(0, memcmp(&auth_fde, &rhs.auth_fde, sizeof(fdevent)));
        EXPECT_EQ(failed_auth_attempts, rhs.failed_auth_attempts);

        return true;
    }
};

TEST(transport, kick_transport) {
  TestTransport t;

  // Mutate some member so we can test that the function is run.
  t.kick = [](atransport* trans) { trans->fd = 42; };

  TestTransport expected;
  expected.kick = t.kick;
  expected.fd = 42;
  expected.kicked = 1;

  kick_transport(&t);
  ASSERT_EQ(42, t.fd);
  ASSERT_EQ(1, t.kicked);
  ASSERT_EQ(expected, t);
}

TEST(transport, kick_transport_already_kicked) {
  // Ensure that the transport is not modified if the transport has already been
  // kicked.
  TestTransport t;
  t.kicked = 1;
  t.kick = [](atransport*) { FAIL() << "Kick should not have been called"; };

  TestTransport expected;
  expected.kicked = 1;
  expected.kick = t.kick;

  kick_transport(&t);
  ASSERT_EQ(expected, t);
}

// Disabled because the function currently segfaults for a zeroed atransport. I
// want to make sure I understand how this is working at all before I try fixing
// that.
TEST(transport, DISABLED_run_transport_disconnects_zeroed_atransport) {
  atransport t;
  run_transport_disconnects(&t);
}
