/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <keyutils.h>

#include <dlfcn.h>

#include <gtest/gtest.h>

TEST(keyutils, smoke) {
  // Check that the exported type is sane.
  ASSERT_EQ(4U, sizeof(key_serial_t));

  // Check that all the functions actually exist.
  ASSERT_TRUE(dlsym(nullptr, "add_key") != nullptr);
  ASSERT_TRUE(dlsym(nullptr, "keyctl_get_keyring_ID") != nullptr);
  ASSERT_TRUE(dlsym(nullptr, "keyctl_revoke") != nullptr);
  ASSERT_TRUE(dlsym(nullptr, "keyctl_search") != nullptr);
  ASSERT_TRUE(dlsym(nullptr, "keyctl_setperm") != nullptr);
  ASSERT_TRUE(dlsym(nullptr, "keyctl_unlink") != nullptr);
}
