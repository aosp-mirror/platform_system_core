# Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Makefile for metrics utilities -- library, client and daemon
#

PC_DEPS = dbus-1 glib-2.0 dbus-glib-1 libchrome libchromeos

CCONFIG = $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
LDCONFIG = $(shell $(PKG_CONFIG) --libs $(PC_DEPS) gthread-2.0)

CXXFLAGS += -Wall -Werror -fPIC -fno-exceptions $(CCONFIG)

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

TESTCOUNTER_LIBS = -lgmock -lgtest -lbase -lrt -lpthread -lglib-2.0
TESTTIMER_LIBS = -lgmock -lgtest -lbase -lrt -lpthread -lglib-2.0
DAEMON_LDFLAGS = $(LDFLAGS) $(LDCONFIG) -lpthread -lgflags \
		 -lglib-2.0 -lrootdev -lpolicy
TESTDAEMON_LIBS = -lgmock -lgtest
TESTLIB_LIBS = -lgtest -lgmock -lbase -lrt -lpthread -lglib-2.0
POLICY_LIBS = -lpolicy

all: $(LIB) $(SHAREDLIB) $(CLIENT) $(DAEMON)

tests: $(COUNTER_TEST) $(DAEMON_TEST) $(LIB_TEST) $(TIMER_TEST)

$(CLIENT): $(CLIENT_OBJS) $(SHAREDLIB)
	$(CXX) $(LDFLAGS) $(POLICY_LIBS) -lrt $^ -o $@

$(COUNTER_TEST): $(TESTCOUNTER_OBJS)
	$(CXX) -o $@ $^ $(TESTCOUNTER_LIBS)

$(TIMER_TEST): $(TESTTIMER_OBJS)
	$(CXX) -o $@ $^ $(TESTTIMER_LIBS)

$(DAEMON): $(DAEMON_OBJS) $(SHAREDLIB)
	$(CXX) -o $@ $^ $(DAEMON_LDFLAGS)

$(DAEMON_TEST): $(TESTDAEMON_OBJS)
	$(CXX) -o $@ $^ $(DAEMON_LDFLAGS) $(TESTDAEMON_LIBS)

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(SHAREDLIB): $(LIB_OBJS)
	$(CXX) $(LDFLAGS) $(POLICY_LIBS) -shared $^ -o $@

$(LIB_TEST): $(TESTLIB_OBJS) $(SHAREDLIB)
	$(CXX) -o $@ $^ $(LDFLAGS) $(POLICY_LIBS) $(TESTLIB_LIBS)

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(CLIENT) $(DAEMON) $(LIB) $(SHAREDLIB) *.o
	rm -f $(COUNTER_TEST) $(DAEMON_TEST) $(LIB_TEST) $(TIMER_TEST)
