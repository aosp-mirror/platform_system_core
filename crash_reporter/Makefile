# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

BASE_VER = 85268
PKG_CONFIG ?= pkg-config

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

PC_DEPS = glib-2.0 $(LIST_PROXIES_PKGS) libpcrecpp \
	libchrome-$(BASE_VER) libchromeos-$(BASE_VER)
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))

COMMON_LIBS = -lgflags $(PC_LIBS)
REPORTER_LIBS = $(COMMON_LIBS) -lmetrics
LIST_PROXIES_LIBS = $(COMMON_LIBS)

TEST_LIBS = $(COMMON_LIBS) -lgtest -lgmock
CPPFLAGS += -I.. -I$(SYSROOT)/usr/include/google-breakpad $(PC_CFLAGS)

CXXFLAGS += -Wall -Werror

all: $(REPORTER_BINS)

$(CRASH_REPORTER): crash_reporter.o $(CRASH_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(REPORTER_LIBS) -o $@

$(LIST_PROXIES_BIN): $(LIST_PROXIES_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(LIST_PROXIES_LIBS) -o $@

tests: $(TEST_BINS)

%_test: %_test.o $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) $^ $(TEST_LIBS) -o $@

.cc.o:
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(CRASH_BIN) $(LIST_PROXIES_BIN) $(TEST_BINS)
