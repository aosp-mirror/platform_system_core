# Build the unit tests.
LOCAL_PATH := $(call my-dir)

include $(LOCAL_PATH)/Android.nativebridge-dummy.mk

include $(CLEAR_VARS)

# Build the unit tests.
test_src_files := \
    CodeCacheCreate_test.cpp \
    CodeCacheExists_test.cpp \
    CompleteFlow_test.cpp \
    InvalidCharsNativeBridge_test.cpp \
    NativeBridge2Signal_test.cpp \
    NativeBridgeVersion_test.cpp \
    NeedsNativeBridge_test.cpp \
    PreInitializeNativeBridge_test.cpp \
    PreInitializeNativeBridgeFail1_test.cpp \
    PreInitializeNativeBridgeFail2_test.cpp \
    ReSetupNativeBridge_test.cpp \
    UnavailableNativeBridge_test.cpp \
    ValidNameNativeBridge_test.cpp


shared_libraries := \
    liblog \
    libnativebridge \
    libnativebridge-dummy

$(foreach file,$(test_src_files), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_CLANG := true) \
    $(eval LOCAL_CPPFLAGS := -std=gnu++11) \
    $(eval LOCAL_SHARED_LIBRARIES := $(shared_libraries)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.cpp=%))) \
    $(eval include $(BUILD_NATIVE_TEST)) \
)

$(foreach file,$(test_src_files), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_CLANG := true) \
    $(eval LOCAL_CPPFLAGS := -std=gnu++11) \
    $(eval LOCAL_SHARED_LIBRARIES := $(shared_libraries)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.cpp=%))) \
    $(eval include $(BUILD_HOST_NATIVE_TEST)) \
)
