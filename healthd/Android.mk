# Copyright 2013 The Android Open Source Project

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := libhealthd_draw

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)
LOCAL_STATIC_LIBRARIES := \
	libminui \
	libbase
LOCAL_SRC_FILES := healthd_draw.cpp

ifneq ($(TARGET_HEALTHD_DRAW_SPLIT_SCREEN),)
LOCAL_CFLAGS += -DHEALTHD_DRAW_SPLIT_SCREEN=$(TARGET_HEALTHD_DRAW_SPLIT_SCREEN)
else
LOCAL_CFLAGS += -DHEALTHD_DRAW_SPLIT_SCREEN=0
endif

ifneq ($(TARGET_HEALTHD_DRAW_SPLIT_OFFSET),)
LOCAL_CFLAGS += -DHEALTHD_DRAW_SPLIT_OFFSET=$(TARGET_HEALTHD_DRAW_SPLIT_OFFSET)
else
LOCAL_CFLAGS += -DHEALTHD_DRAW_SPLIT_OFFSET=0
endif

LOCAL_HEADER_LIBRARIES := libbatteryservice_headers

include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)

LOCAL_CFLAGS := -Werror
ifeq ($(strip $(BOARD_CHARGER_DISABLE_INIT_BLANK)),true)
LOCAL_CFLAGS += -DCHARGER_DISABLE_INIT_BLANK
endif
ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_CFLAGS += -DCHARGER_ENABLE_SUSPEND
endif

LOCAL_SRC_FILES := \
    healthd_mode_charger.cpp \
    AnimationParser.cpp

LOCAL_MODULE := libhealthd_charger
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := \
    $(LOCAL_PATH) \
    $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES := \
    android.hardware.health@2.0 \
    android.hardware.health@2.0-impl \
    android.hardware.health@1.0 \
    android.hardware.health@1.0-convert \
    libhealthstoragedefault \
    libminui \
    libpng \
    libz \
    libutils \
    libbase \
    libcutils \
    libhealthd_draw \
    liblog \
    libm \
    libc \

ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_STATIC_LIBRARIES += libsuspend
endif

include $(BUILD_STATIC_LIBRARY)

### charger ###
include $(CLEAR_VARS)
ifeq ($(strip $(BOARD_CHARGER_NO_UI)),true)
LOCAL_CHARGER_NO_UI := true
endif

LOCAL_SRC_FILES := \
    charger.cpp \

LOCAL_MODULE := charger
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_CFLAGS := -Werror
ifeq ($(strip $(LOCAL_CHARGER_NO_UI)),true)
LOCAL_CFLAGS += -DCHARGER_NO_UI
endif

CHARGER_STATIC_LIBRARIES := \
    android.hardware.health@2.0-impl \
    android.hardware.health@2.0 \
    android.hardware.health@1.0 \
    android.hardware.health@1.0-convert \
    libbinderthreadstate \
    libhidltransport \
    libhidlbase \
    libhwbinder_noltopgo \
    libhealthstoragedefault \
    libvndksupport \
    libhealthd_charger \
    libhealthd_draw \
    libbatterymonitor \
    libbase \
    libutils \
    libcutils \
    libprocessgroup \
    liblog \
    libm \
    libc \

LOCAL_STATIC_LIBRARIES := $(CHARGER_STATIC_LIBRARIES)

ifneq ($(strip $(LOCAL_CHARGER_NO_UI)),true)
LOCAL_STATIC_LIBRARIES += \
    libminui \
    libpng \
    libz \

endif

ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_STATIC_LIBRARIES += libsuspend
endif

LOCAL_HAL_STATIC_LIBRARIES := libhealthd

# Symlink /charger to /sbin/charger
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT) \
    && ln -sf /sbin/charger $(TARGET_ROOT_OUT)/charger

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := charger_test
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS := -Wall -Werror -DCHARGER_TEST -DCHARGER_NO_UI
LOCAL_STATIC_LIBRARIES := $(CHARGER_STATIC_LIBRARIES)
LOCAL_SRC_FILES := \
    charger.cpp \
    charger_test.cpp \

include $(BUILD_EXECUTABLE)

CHARGER_STATIC_LIBRARIES :=

ifneq ($(strip $(LOCAL_CHARGER_NO_UI)),true)
define _add-charger-image
include $$(CLEAR_VARS)
LOCAL_MODULE := system_core_charger_res_images_$(notdir $(1))
LOCAL_MODULE_STEM := $(notdir $(1))
_img_modules += $$(LOCAL_MODULE)
LOCAL_SRC_FILES := $1
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $$(TARGET_ROOT_OUT)/res/images/charger
include $$(BUILD_PREBUILT)
endef

_img_modules :=
_images :=
$(foreach _img, $(call find-subdir-subdir-files, "images", "*.png"), \
  $(eval $(call _add-charger-image,$(_img))))

include $(CLEAR_VARS)
LOCAL_MODULE := charger_res_images
LOCAL_MODULE_TAGS := optional
LOCAL_REQUIRED_MODULES := $(_img_modules)
include $(BUILD_PHONY_PACKAGE)

_add-charger-image :=
_img_modules :=
endif # LOCAL_CHARGER_NO_UI
