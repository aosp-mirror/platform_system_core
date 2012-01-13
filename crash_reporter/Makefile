# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

CRASH_REPORTER = crash_reporter
LIST_PROXIES_BIN = list_proxies
REPORTER_BINS = $(CRASH_REPORTER) $(LIST_PROXIES_BIN)
CRASH_OBJS = \
	crash_collector.o \
	kernel_collector.o \
	unclean_shutdown_collector.o \
	user_collector.o
LIST_PROXIES_OBJS = list_proxies.o
LIST_PROXIES_PKGS = dbus-1 dbus-glib-1
TEST_OBJS = $(CRASH_OBJS)
TEST_BINS = \
	crash_collector_test \
	kernel_collector_test \
	unclean_shutdown_collector_test \
	user_collector_test

LDCONFIG = $(shell $(PKG_CONFIG) --libs libpcrecpp)

# -lglib-2.0 is needed by libbase.a now.
COMMON_LIBS = -lchromeos -lbase -lgflags $(LDCONFIG) \
	$(shell $(PKG_CONFIG) --libs glib-2.0 $(LIST_PROXIES_PKGS))
REPORTER_LIBS = $(COMMON_LIBS) -lmetrics
LIST_PROXIES_LIBS = $(COMMON_LIBS)

TEST_LIBS = $(COMMON_LIBS) -lgtest -lgmock
INCLUDE_DIRS = -I.. -I$(SYSROOT)/usr/include/google-breakpad \
	$(shell $(PKG_CONFIG) --cflags glib-2.0 $(LIST_PROXIES_PKGS))

CXXFLAGS += -Wall -Werror

all: $(REPORTER_BINS)

$(CRASH_REPORTER): crash_reporter.o $(CRASH_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(REPORTER_LIBS) -o $@

$(LIST_PROXIES_BIN): $(LIST_PROXIES_OBJS)
	$(CXX) $(CXXFLAGS) $^ $(LIST_PROXIES_LIBS) -o $@

tests: $(TEST_BINS)

%_test: %_test.o $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) $(LIB_DIRS) $^ $(TEST_LIBS) -o $@

.cc.o:
	$(CXX) $(CXXFLAGS) $(INCLUDE_DIRS) -c $< -o $@

clean:
	rm -rf *.o $(CRASH_BIN) $(LIST_PROXIES_BIN) $(TEST_BINS)
