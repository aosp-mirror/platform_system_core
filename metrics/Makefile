# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Makefile for metrics utilities -- library, client and daemon
#

CCONFIG = $(shell $(PKG_CONFIG) --cflags dbus-1 glib-2.0 dbus-glib-1)
LDCONFIG = $(shell $(PKG_CONFIG) --libs dbus-1 glib-2.0 gthread-2.0 dbus-glib-1)

CXXFLAGS += -Wall -Werror -fPIC -fno-exceptions $(CCONFIG)

CLIENT = metrics_client
DAEMON = metrics_daemon
DAEMON_TEST = metrics_daemon_test
LIB = libmetrics.a
SHAREDLIB = libmetrics.so

CLIENT_OBJS = \
	metrics_client.o
LIB_OBJS = \
	metrics_library.o
DAEMON_OBJS = \
	metrics_daemon.o \
	metrics_daemon_main.o
TESTDAEMON_OBJS = \
	metrics_daemon.o \
	metrics_daemon_test.o

DAEMON_LDFLAGS = $(LDCONFIG) -lrt -lbase -lpthread -lgflags
TESTDAEMON_LIBS = -lgtest

all: $(LIB) $(SHAREDLIB) $(CLIENT) $(DAEMON)

tests: $(DAEMON_TEST)

$(CLIENT): $(CLIENT_OBJS) $(SHAREDLIB)
	$(CXX) $(LDFLAGS) $^ -o $@

$(DAEMON): $(DAEMON_OBJS) $(SHAREDLIB)
	$(CXX) -o $@ $^ $(DAEMON_LDFLAGS)

$(DAEMON_TEST): $(TESTDAEMON_OBJS) $(SHAREDLIB)
	$(CXX) -o $@ $^ $(DAEMON_LDFLAGS) $(TESTDAEMON_LIBS)

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(SHAREDLIB): $(LIB_OBJS)
	$(CXX) $(LDFLAGS) -shared $^ -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

# dependencies in addition to those defined by the rules

metrics_daemon.o: \
	metrics_daemon.h \
	network_states.h \
	power_states.h
metrics_daemon_test.o: \
	metrics_daemon.h \
	network_states.h \
	power_states.h

install:
	install $(CLIENT) $(DESTDIR)/usr/bin
	install $(DAEMON) $(DESTDIR)/usr/bin
	install $(LIB) $(DESTDIR)/usr/lib
	install $(SHAREDLIB) $(DESTDIR)/usr/lib
	install metrics_library.h $(DESTDIR)/usr/include
	install syslog_parser.sh $(DESTDIR)/usr/bin
	install omaha_tracker.sh $(DESTDIR)/usr/sbin

clean:
	rm -f $(CLIENT) $(DAEMON) $(LIB) $(SHAREDLIB) $(TESTDAEMON) *.o
