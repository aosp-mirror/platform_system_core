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

TEST(transport, kick_transport) {
  atransport t = {};
  // Mutate some member so we can test that the function is run.
  t.kick = [](atransport* trans) { trans->fd = 42; };
  atransport expected = t;
  expected.fd = 42;
  expected.kicked = 1;
  kick_transport(&t);
  ASSERT_EQ(42, t.fd);
  ASSERT_EQ(1, t.kicked);
  ASSERT_EQ(0, memcmp(&expected, &t, sizeof(atransport)));
}

TEST(transport, kick_transport_already_kicked) {
  // Ensure that the transport is not modified if the transport has already been
  // kicked.
  atransport t = {};
  t.kicked = 1;
  t.kick = [](atransport*) { FAIL() << "Kick should not have been called"; };
  atransport expected = t;
  kick_transport(&t);
  ASSERT_EQ(0, memcmp(&expected, &t, sizeof(atransport)));
}

// Disabled because the function currently segfaults for a zeroed atransport. I
// want to make sure I understand how this is working at all before I try fixing
// that.
TEST(transport, DISABLED_run_transport_disconnects_zeroed_atransport) {
  atransport t = {};
  run_transport_disconnects(&t);
}
