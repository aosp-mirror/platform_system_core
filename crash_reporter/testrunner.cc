// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <chromeos/test_helpers.h>
#include <glib-object.h>
#include <gtest/gtest.h>

int main(int argc, char** argv) {
  ::g_type_init();
  SetUpTests(&argc, argv, true);
  return RUN_ALL_TESTS();
}
