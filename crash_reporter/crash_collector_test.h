// Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_CRASH_COLLECTOR_TEST_H_
#define _CRASH_REPORTER_CRASH_COLLECTOR_TEST_H_

#include "crash-reporter/crash_collector.h"

#include <glib.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

class CrashCollectorMock : public CrashCollector {
 public:
  MOCK_METHOD0(GetActiveUserSessions, GHashTable *());
};

#endif  // _CRASH_REPORTER_CRASH_COLLECTOR_TEST_H_
