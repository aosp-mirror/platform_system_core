# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(mkrebs): This currently grabs a copy we made from
# src/platform/common-mk; we should instead share it.
include common.mk

BASE_VER ?= 125070
PKG_CONFIG ?= pkg-config

CRASH_OBJS = \
	chrome_collector.o \
	crash_collector.o \
	kernel_collector.o \
	kernel_warning_collector.o \
	udev_collector.o \
	unclean_shutdown_collector.o \
	user_collector.o

PC_DEPS = glib-2.0 libpcrecpp libchrome-$(BASE_VER) libchromeos-$(BASE_VER)
PC_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PC_DEPS))
PC_LIBS := $(shell $(PKG_CONFIG) --libs $(PC_DEPS))

CPPFLAGS += -I$(SRC)/.. -I$(SYSROOT)/usr/include/google-breakpad $(PC_CFLAGS)
LDLIBS = -lgflags $(PC_LIBS)


# -- Executable crash_reporter --

CXX_BINARY(crash_reporter): LDLIBS += -lmetrics
CXX_BINARY(crash_reporter): crash_reporter.o $(CRASH_OBJS)
clean: CLEAN(crash_reporter)
all: CXX_BINARY(crash_reporter)


# -- Executable list_proxies --

LIST_PROXIES_PKGS = dbus-1 dbus-glib-1
LIST_PROXIES_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(LIST_PROXIES_PKGS))
LIST_PROXIES_LIBS := $(shell $(PKG_CONFIG) --libs $(LIST_PROXIES_PKGS))
CXX_BINARY(list_proxies): CPPFLAGS += $(LIST_PROXIES_CFLAGS)
CXX_BINARY(list_proxies): LDLIBS += $(LIST_PROXIES_LIBS)
CXX_BINARY(list_proxies): list_proxies.o
clean: CLEAN(list_proxies)
all: CXX_BINARY(list_proxies)


# -- Executable warn_collector --

CC_BINARY(warn_collector): LDLIBS += -lfl -lmetrics
CC_BINARY(warn_collector): lex.yy.o
clean: CLEAN(warn_collector)
all: CC_BINARY(warn_collector)
lex.yy.c: $(SRC)/warn_collector.l
	flex $<
clean: CLEAN(lex.yy.o)
$(eval $(call add_object_rules,lex.yy.o,CC,c))


# -- Unit Tests --

# Uncomment these to just run specific test(s).
#TEST_BINS += chrome_collector_test
#TEST_BINS += crash_collector_test
#TEST_BINS += kernel_collector_test
#TEST_BINS += udev_collector_test
#TEST_BINS += unclean_shutdown_collector_test
#TEST_BINS += user_collector_test


# Define a template that defines the rules for a unittest.  In case you want
# to add options, etc. for a particular test, the rule to build the test will
# be for "CXX_BINARY(<test name>)".  For example, you could add options with:
#  CXX_BINARY(crash_collector_test): CXXFLAGS += -some-other-option
define TEST_RULES_template
CXX_BINARY($(1)): LDLIBS += -lgtest -lgmock
CXX_BINARY($(1)): $(1).o $(CRASH_OBJS)
clean: CLEAN($(1))
tests: TEST(CXX_BINARY($(1)))
endef

CC_BINARY(warn_collector_test): warn_collector_test.o

# If $(TEST_BINS) is not already set, assume any filename matching *_test.cc
# is a test.
TEST_BINS ?= $(patsubst $(SRC)/%.cc,%,$(wildcard $(SRC)/*_test.cc))
$(foreach prog,$(TEST_BINS),$(eval $(call TEST_RULES_template,$(prog))))
tests: TEST(CC_BINARY(warn_collector_test))
