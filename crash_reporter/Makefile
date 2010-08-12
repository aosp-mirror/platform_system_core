# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CRASH_REPORTER = crash_reporter
REPORTER_BINS = $(CRASH_REPORTER)
CRASH_OBJS = system_logging.o user_collector.o
TEST_OBJS = $(CRASH_OBJS) system_logging_mock.o
TEST_BINS = user_collector_test

# -lglib-2.0 is needed by libbase.a now.
COMMON_LIBS = -lbase -lpthread -lglib-2.0 -lgflags -lrt
REPORTER_LIBS = $(COMMON_LIBS) -lmetrics

TEST_LIBS = $(COMMON_LIBS) -lgtest -lgmock
INCLUDE_DIRS = -I.. -I$(SYSROOT)/usr/include/google-breakpad

CXXFLAGS += -Wall -Werror

all: $(REPORTER_BINS)

$(CRASH_REPORTER): crash_reporter.o $(CRASH_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(REPORTER_LIBS) -o $@

tests: $(TEST_BINS)

user_collector_test: user_collector_test.o $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) $(LIB_DIRS) $^ $(TEST_LIBS) -o $@

.cc.o:
	$(CXX) $(CXXFLAGS) $(INCLUDE_DIRS) -c $< -o $@

clean:
	rm -rf *.o $(CRASH_BIN) $(TEST_BINS)
