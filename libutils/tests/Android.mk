# Build the unit tests.
LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

# Build the unit tests.
test_src_files := \
    BasicHashtable_test.cpp \
    BlobCache_test.cpp \
    BitSet_test.cpp \
    Looper_test.cpp \
    LruCache_test.cpp \
    String8_test.cpp \
    Unicode_test.cpp \
    Vector_test.cpp

shared_libraries := \
    libz \
    liblog \
    libcutils \
    libutils \
    libstlport

static_libraries := \
    libgtest \
    libgtest_main

$(foreach file,$(test_src_files), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_SHARED_LIBRARIES := $(shared_libraries)) \
    $(eval LOCAL_STATIC_LIBRARIES := $(static_libraries)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.cpp=%))) \
    $(eval include $(BUILD_NATIVE_TEST)) \
)
