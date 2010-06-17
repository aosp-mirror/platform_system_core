# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CRASH_BIN = crash_reporter
CRASH_LIB = libcrash.so
CRASH_OBJS = system_logging.o user_collector.o
TEST_OBJS = $(CRASH_OBJS) system_logging_mock.o
TEST_BINS = user_collector_test

LIBS = -lbase -lpthread -lgflags -lrt -lmetrics

TEST_LIBS = $(LIBS) -lgtest -lgmock
INCLUDE_DIRS = -I.. -I$(SYSROOT)/usr/include/google-breakpad
LIB_DIRS =

# We need -fPIC for linking objects into shared objects.
CXXFLAGS += -fPIC -Wall -Werror

all:
	echo "Specify either $(CRASH_BIN) or $(CRASH_LIB)"

$(CRASH_LIB): crash_dumper.o
	$(CXX) -shared -lbreakpad_client $^ -o $@

$(CRASH_BIN): crash_reporter.o $(CRASH_OBJS)
	$(CXX) $(CXXFLAGS) $(LIB_DIRS) $^ -lcrash $(LIBS) -o $@

tests: $(TEST_BINS)

user_collector_test: user_collector_test.o $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) $(LIB_DIRS) $^ $(TEST_LIBS) -o $@

.cc.o:
	$(CXX) $(CXXFLAGS) $(INCLUDE_DIRS) -c $< -o $@

clean:
	rm -rf *.o $(CRASH_BIN) $(TEST_BINS) $(CRASH_LIB)
