# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Makefile for metrics utilities -- library, client and daemon
#

CCONFIG = $(shell $(PKG_CONFIG) --cflags dbus-1 glib-2.0 dbus-glib-1)
LDCONFIG = $(shell $(PKG_CONFIG) --libs dbus-1 glib-2.0 gthread-2.0 dbus-glib-1)

CFLAGS = -Wall -Werror -I/usr/include -fpic -O2 $(CCONFIG)
CXXFLAGS = $(CFLAGS) -fno-exceptions

CLIENT = metrics_client
DAEMON = metrics_daemon
TESTDAEMON = test_daemon
LIB = libmetrics.a
SHAREDLIB = libmetrics.so

CLIENT_OBJS = \
	metrics_client.o
LIB_OBJS = \
	metrics_library.o
DAEMON_OBJS = \
	marshal_void__string_boxed.o \
	metrics_daemon.o \
	metrics_daemon_main.o
TESTDAEMON_OBJS = \
	marshal_void__string_boxed.o \
	metrics_daemon.o \
	metrics_daemon_unittest.o

DAEMON_LDFLAGS = $(LDCONFIG) -lrt -lbase -lpthread -lgflags
TESTDAEMON_LIBS = -lgtest

all: $(LIB) $(SHAREDLIB) $(CLIENT) $(DAEMON) $(TESTDAEMON)

$(CLIENT): $(CLIENT_OBJS) $(SHAREDLIB)
	$(CXX) $(LDFLAGS) $^ -o $@

$(DAEMON): $(DAEMON_OBJS) $(SHAREDLIB)
	$(CXX) -o $@ $^ $(DAEMON_LDFLAGS)

$(TESTDAEMON): $(TESTDAEMON_OBJS) $(SHAREDLIB)
	$(CXX) -o $@ $^ $(DAEMON_LDFLAGS) $(TESTDAEMON_LIBS)

$(LIB): $(LIB_OBJS)
	ar rcs $@ $^

$(SHAREDLIB): $(LIB_OBJS)
	$(CXX) $(LDFLAGS) -shared $^ -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.c: %.list
	glib-genmarshal --body --prefix=marshal $< > $@

%.h: %.list
	glib-genmarshal --header --prefix=marshal $< > $@

# dependencies in addition to those defined by the rules

metrics_daemon.o: \
	marshal_void__string_boxed.h \
	metrics_daemon.h \
	network_states.h
metrics_daemon_unittest.o: \
	marshal_void__string_boxed.h \
	metrics_daemon.h \
	network_states.h
marshal_void__string_boxed.o: \
	marshal_void__string_boxed.h

.PRECIOUS: marshal_void__string_boxed.c  # keep around for debugging

install:
	install $(CLIENT) $(DESTDIR)/usr/bin
	install $(DAEMON) $(DESTDIR)/usr/bin
	install $(LIB) $(DESTDIR)/usr/lib
	install $(SHAREDLIB) $(DESTDIR)/usr/lib
	install metrics_library.h $(DESTDIR)/usr/include
	install syslog_parser.sh $(DESTDIR)/usr/bin
	install omaha_tracker.sh $(DESTDIR)/usr/sbin

clean:
	rm -f $(CLIENT) $(DAEMON) $(LIB) $(SHAREDLIB) $(TESTDAEMON)
	rm -f *.o marshal_void__string_boxed.[ch]
