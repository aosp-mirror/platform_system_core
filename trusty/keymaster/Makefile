#####
# Local unit test Makefile
#
# This makefile builds and runs the trusty_keymaster unit tests locally on the development
# machine, not on an Android device.
#
# To build and run these tests, one pre-requisite must be manually installed: BoringSSL.
# This Makefile expects to find BoringSSL in a directory adjacent to $ANDROID_BUILD_TOP.
# To get and build it, first install the Ninja build tool (e.g. apt-get install
# ninja-build), then do:
#
# cd $ANDROID_BUILD_TOP/..
# git clone https://boringssl.googlesource.com/boringssl
# cd boringssl
# mdkir build
# cd build
# cmake -GNinja ..
# ninja
#
# Then return to $ANDROID_BUILD_TOP/system/keymaster and run "make".
#####

BASE=../../../..
SUBS=system/core \
	system/keymaster \
	hardware/libhardware \
	external/gtest
GTEST=$(BASE)/external/gtest
KM=$(BASE)/system/keymaster

INCLUDES=$(foreach dir,$(SUBS),-I $(BASE)/$(dir)/include) \
	-I $(BASE)/libnativehelper/include/nativehelper \
	-I ../tipc/include \
	-I $(BASE)/system/keymaster \
	-I $(GTEST) \
	-I$(BASE)/../boringssl/include

ifdef USE_CLANG
CC=/usr/bin/clang
CXX=/usr/bin/clang
CLANG_TEST_DEFINE=-DKEYMASTER_CLANG_TEST_BUILD
COMPILER_SPECIFIC_ARGS=-std=c++11 $(CLANG_TEST_DEFINE)
else
COMPILER_SPECIFIC_ARGS=-std=c++0x -fprofile-arcs
endif

CPPFLAGS=$(INCLUDES) -g -O0 -MD
CXXFLAGS=-Wall -Werror -Wno-unused -Winit-self -Wpointer-arith	-Wunused-parameter \
	-Wmissing-declarations -ftest-coverage \
	-Wno-deprecated-declarations -fno-exceptions -DKEYMASTER_NAME_TAGS \
	$(COMPILER_SPECIFIC_ARGS)
LDLIBS=-L$(BASE)/../boringssl/build/crypto -lcrypto -lpthread -lstdc++

CPPSRCS=\
	$(KM)/aead_mode_operation.cpp \
	$(KM)/aes_key.cpp \
	$(KM)/aes_operation.cpp \
	$(KM)/android_keymaster.cpp \
	$(KM)/android_keymaster_messages.cpp \
	$(KM)/android_keymaster_messages_test.cpp \
	$(KM)/android_keymaster_test.cpp \
	$(KM)/android_keymaster_test_utils.cpp \
	$(KM)/android_keymaster_utils.cpp \
	$(KM)/asymmetric_key.cpp \
	$(KM)/auth_encrypted_key_blob.cpp \
	$(KM)/auth_encrypted_key_blob.cpp \
	$(KM)/authorization_set.cpp \
	$(KM)/authorization_set_test.cpp \
	$(KM)/ec_key.cpp \
	$(KM)/ec_keymaster0_key.cpp \
	$(KM)/ecdsa_operation.cpp \
	$(KM)/hmac_key.cpp \
	$(KM)/hmac_operation.cpp \
	$(KM)/integrity_assured_key_blob.cpp \
	$(KM)/key.cpp \
	$(KM)/key_blob_test.cpp \
	$(KM)/keymaster0_engine.cpp \
	$(KM)/logger.cpp \
	$(KM)/ocb_utils.cpp \
	$(KM)/openssl_err.cpp \
	$(KM)/openssl_utils.cpp \
	$(KM)/operation.cpp \
	$(KM)/operation_table.cpp \
	$(KM)/rsa_key.cpp \
	$(KM)/rsa_keymaster0_key.cpp \
	$(KM)/rsa_operation.cpp \
	$(KM)/serializable.cpp \
	$(KM)/soft_keymaster_context.cpp \
	$(KM)/symmetric_key.cpp \
	$(KM)/unencrypted_key_blob.cpp \
	trusty_keymaster_device.cpp \
	trusty_keymaster_device_test.cpp
CCSRCS=$(GTEST)/src/gtest-all.cc
CSRCS=ocb.c

OBJS=$(CPPSRCS:.cpp=.o) $(CCSRCS:.cc=.o) $(CSRCS:.c=.o)
DEPS=$(CPPSRCS:.cpp=.d) $(CCSRCS:.cc=.d) $(CSRCS:.c=.d)
GCDA=$(CPPSRCS:.cpp=.gcda) $(CCSRCS:.cc=.gcda) $(CSRCS:.c=.gcda)
GCNO=$(CPPSRCS:.cpp=.gcno) $(CCSRCS:.cc=.gcno) $(CSRCS:.c=.gcno)

LINK.o=$(LINK.cc)

BINARIES=trusty_keymaster_device_test

ifdef TRUSTY
BINARIES += trusty_keymaster_device_test
endif # TRUSTY

.PHONY: coverage memcheck massif clean run

%.run: %
	./$<
	touch $@

run: $(BINARIES:=.run)

coverage: coverage.info
	genhtml coverage.info --output-directory coverage

coverage.info: run
	lcov --capture --directory=. --output-file coverage.info

%.coverage : %
	$(MAKE) clean && $(MAKE) $<
	./$<
	lcov --capture --directory=. --output-file coverage.info
	genhtml coverage.info --output-directory coverage

#UNINIT_OPTS=--track-origins=yes
UNINIT_OPTS=--undef-value-errors=no

MEMCHECK_OPTS=--leak-check=full \
	--show-reachable=yes \
	--vgdb=full \
	$(UNINIT_OPTS) \
	--error-exitcode=1

MASSIF_OPTS=--tool=massif \
	--stacks=yes

%.memcheck : %
	valgrind $(MEMCHECK_OPTS) ./$< && \
	touch $@

%.massif : %
	valgrind $(MASSIF_OPTS) --massif-out-file=$@ ./$<

memcheck: $(BINARIES:=.memcheck)

massif: $(BINARIES:=.massif)

trusty_keymaster_device_test: trusty_keymaster_device_test.o \
	trusty_keymaster_device.o \
	$(KM)/aead_mode_operation.o \
	$(KM)/aes_key.o \
	$(KM)/aes_operation.o \
	$(KM)/android_keymaster.o \
	$(KM)/android_keymaster_messages.o \
	$(KM)/android_keymaster_test_utils.o \
	$(KM)/android_keymaster_utils.o \
	$(KM)/asymmetric_key.o \
	$(KM)/auth_encrypted_key_blob.o \
	$(KM)/auth_encrypted_key_blob.o \
	$(KM)/authorization_set.o \
	$(KM)/ec_key.o \
	$(KM)/ec_keymaster0_key.cpp \
	$(KM)/ecdsa_operation.o \
	$(KM)/hmac_key.o \
	$(KM)/hmac_operation.o \
	$(KM)/integrity_assured_key_blob.o \
	$(KM)/key.o \
	$(KM)/keymaster0_engine.o \
	$(KM)/logger.o \
	$(KM)/ocb.o \
	$(KM)/ocb_utils.o \
	$(KM)/openssl_err.o \
	$(KM)/openssl_utils.o \
	$(KM)/operation.o \
	$(KM)/operation_table.o \
	$(KM)/rsa_key.o \
	$(KM)/rsa_keymaster0_key.o \
	$(KM)/rsa_operation.o \
	$(KM)/serializable.o \
	$(KM)/soft_keymaster_context.o \
	$(KM)/symmetric_key.o \
	$(GTEST)/src/gtest-all.o

$(GTEST)/src/gtest-all.o: CXXFLAGS:=$(subst -Wmissing-declarations,,$(CXXFLAGS))
ocb.o: CFLAGS=$(CLANG_TEST_DEFINE)

clean:
	rm -f $(OBJS) $(DEPS) $(GCDA) $(GCNO) $(BINARIES) \
		$(BINARIES:=.run) $(BINARIES:=.memcheck) $(BINARIES:=.massif) \
		coverage.info
	rm -rf coverage

-include $(CPPSRCS:.cpp=.d)
-include $(CCSRCS:.cc=.d)

