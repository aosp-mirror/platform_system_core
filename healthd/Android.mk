# Copyright 2013 The Android Open Source Project

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := healthd_board_default.cpp
LOCAL_MODULE := libhealthd.default
LOCAL_CFLAGS := -Werror
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := BatteryMonitor.cpp
LOCAL_MODULE := libbatterymonitor
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := libutils
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_CFLAGS += -DCHARGER_ENABLE_SUSPEND
LOCAL_SHARED_LIBRARIES += libsuspend
endif
LOCAL_SRC_FILES := \
    healthd_mode_android.cpp \
    healthd_mode_charger.cpp \
    AnimationParser.cpp \
    BatteryPropertiesRegistrar.cpp \

LOCAL_MODULE := libhealthd_internal
LOCAL_C_INCLUDES := bootable/recovery
LOCAL_EXPORT_C_INCLUDE_DIRS := \
    $(LOCAL_PATH) \
    $(LOCAL_PATH)/include \

LOCAL_STATIC_LIBRARIES := \
    libbatterymonitor \
    libbatteryservice \
    libbinder \
    libminui \
    libpng \
    libz \
    libutils \
    libbase \
    libcutils \
    liblog \
    libm \
    libc \

include $(BUILD_STATIC_LIBRARY)


include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
    healthd.cpp \

LOCAL_MODULE := healthd
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_CFLAGS := -D__STDC_LIMIT_MACROS -Werror

ifeq ($(strip $(BOARD_CHARGER_DISABLE_INIT_BLANK)),true)
LOCAL_CFLAGS += -DCHARGER_DISABLE_INIT_BLANK
endif

ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_CFLAGS += -DCHARGER_ENABLE_SUSPEND
endif

ifneq ($(BOARD_PERIODIC_CHORES_INTERVAL_FAST),)
LOCAL_CFLAGS += -DBOARD_PERIODIC_CHORES_INTERVAL_FAST=$(BOARD_PERIODIC_CHORES_INTERVAL_FAST)
endif

ifneq ($(BOARD_PERIODIC_CHORES_INTERVAL_SLOW),)
LOCAL_CFLAGS += -DBOARD_PERIODIC_CHORES_INTERVAL_SLOW=$(BOARD_PERIODIC_CHORES_INTERVAL_SLOW)
endif
LOCAL_C_INCLUDES := bootable/recovery

LOCAL_STATIC_LIBRARIES := \
    libhealthd_internal \
    libbatterymonitor \
    libbatteryservice \
    libbinder \
    libminui \
    libpng \
    libz \
    libutils \
    libbase \
    libcutils \
    liblog \
    libm \
    libc

ifeq ($(strip $(BOARD_CHARGER_ENABLE_SUSPEND)),true)
LOCAL_STATIC_LIBRARIES += libsuspend
endif

LOCAL_HAL_STATIC_LIBRARIES := libhealthd

# Symlink /charger to /sbin/healthd
LOCAL_POST_INSTALL_CMD := $(hide) mkdir -p $(TARGET_ROOT_OUT) \
    && ln -sf /sbin/healthd $(TARGET_ROOT_OUT)/charger

include $(BUILD_EXECUTABLE)


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
