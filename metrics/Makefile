# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Makefile for metrics utilities -- library, client and daemon
#

BASE_VER ?= 180609
PKG_CONFIG ?= pkg-config
PC_DEPS = dbus-1 glib-2.0 gthread-2.0 dbus-glib-1 \
	libchrome-$(BASE_VER) libchromeos-$(BASE_VER)
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
LDLIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))

CXXFLAGS += -Wall -Werror -fPIC -fno-exceptions
CPPFLAGS += $(PC_CFLAGS)

CLIENT = metrics_client
DAEMON = metrics_daemon
DAEMON_TEST = metrics_daemon_test
LIB = libmetrics.a
SHAREDLIB = libmetrics.so
LIB_TEST = metrics_library_test
COUNTER_TEST = counter_test
TIMER_TEST = timer_test

TESTCOUNTER_OBJS = \
	counter.o \
	counter_test.o
TESTTIMER_OBJS = \
	timer.o \
	timer_test.o
CLIENT_OBJS = \
	metrics_client.o
DAEMON_OBJS = \
	counter.o \
	metrics_daemon.o \
	metrics_daemon_main.o
TESTDAEMON_OBJS = \
	counter.o \
	metrics_daemon.o \
	metrics_daemon_test.o
LIB_OBJS = \
	c_metrics_library.o \
	metrics_library.o \
	timer.o
TESTLIB_OBJS = \
	metrics_library_test.o

POLICY_LIBS = -lpolicy-$(BASE_VER)
TEST_LIBS = -lgmock -lgtest
DAEMON_LIBS = -lgflags -lrootdev

LINK = $(CXX) $(CXXFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

all: $(LIB) $(SHAREDLIB) $(CLIENT) $(DAEMON)

tests: $(COUNTER_TEST) $(DAEMON_TEST) $(LIB_TEST) $(TIMER_TEST)

$(CLIENT): $(CLIENT_OBJS) $(SHAREDLIB)
	$(LINK)

$(COUNTER_TEST): $(TESTCOUNTER_OBJS)
	$(LINK) $(TEST_LIBS)

$(TIMER_TEST): $(TESTTIMER_OBJS)
	$(LINK) $(TEST_LIBS)

$(DAEMON): $(DAEMON_OBJS) $(SHAREDLIB)
	$(LINK) $(DAEMON_LIBS)

$(DAEMON_TEST): $(TESTDAEMON_OBJS)
	$(LINK) $(DAEMON_LIBS) $(TEST_LIBS)

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(SHAREDLIB): $(LIB_OBJS)
	$(LINK) -shared $(POLICY_LIBS)

$(LIB_TEST): $(TESTLIB_OBJS) $(SHAREDLIB)
	$(LINK) $(POLICY_LIBS) $(TEST_LIBS)

%.o: %.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(CLIENT) $(DAEMON) $(LIB) $(SHAREDLIB) *.o
	rm -f $(COUNTER_TEST) $(DAEMON_TEST) $(LIB_TEST) $(TIMER_TEST)
