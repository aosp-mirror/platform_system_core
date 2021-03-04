LOCAL_PATH:= $(call my-dir)

#######################################
# init-debug.rc
include $(CLEAR_VARS)

LOCAL_MODULE := init-debug.rc
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/init

include $(BUILD_PREBUILT)

#######################################
# asan.options
ifneq ($(filter address,$(SANITIZE_TARGET)),)

include $(CLEAR_VARS)

LOCAL_MODULE := asan.options
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(TARGET_OUT)

include $(BUILD_PREBUILT)

# ASAN extration.
ASAN_EXTRACT_FILES :=
ifeq ($(SANITIZE_TARGET_SYSTEM),true)
include $(CLEAR_VARS)
LOCAL_MODULE:= asan_extract
LOCAL_LICENSE_KINDS:= SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS:= notice
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := asan_extract.sh
LOCAL_INIT_RC := asan_extract.rc
# We need bzip2 on device for extraction.
LOCAL_REQUIRED_MODULES := bzip2
include $(BUILD_PREBUILT)
ASAN_EXTRACT_FILES := asan_extract
endif

endif

#######################################
# init.environ.rc

include $(CLEAR_VARS)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE := init.environ.rc
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)
LOCAL_REQUIRED_MODULES := etc_classpath

EXPORT_GLOBAL_ASAN_OPTIONS :=
ifneq ($(filter address,$(SANITIZE_TARGET)),)
  EXPORT_GLOBAL_ASAN_OPTIONS := export ASAN_OPTIONS include=/system/asan.options
  LOCAL_REQUIRED_MODULES := asan.options $(ASAN_OPTIONS_FILES) $(ASAN_EXTRACT_FILES)
endif

EXPORT_GLOBAL_HWASAN_OPTIONS :=
ifneq ($(filter hwaddress,$(SANITIZE_TARGET)),)
  ifneq ($(HWADDRESS_SANITIZER_GLOBAL_OPTIONS),)
    EXPORT_GLOBAL_HWASAN_OPTIONS := export HWASAN_OPTIONS $(HWADDRESS_SANITIZER_GLOBAL_OPTIONS)
  endif
endif

EXPORT_GLOBAL_GCOV_OPTIONS :=
ifeq ($(NATIVE_COVERAGE),true)
  EXPORT_GLOBAL_GCOV_OPTIONS := export GCOV_PREFIX /data/misc/trace
endif

EXPORT_GLOBAL_CLANG_COVERAGE_OPTIONS :=
ifeq ($(CLANG_COVERAGE),true)
  EXPORT_GLOBAL_CLANG_COVERAGE_OPTIONS := export LLVM_PROFILE_FILE /data/misc/trace/clang-%20m.profraw
endif

# Put it here instead of in init.rc module definition,
# because init.rc is conditionally included.
#
# create some directories (some are mount points) and symlinks
LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
    dev proc sys system data data_mirror odm oem acct config storage mnt apex debug_ramdisk \
    linkerconfig second_stage_resources postinstall $(BOARD_ROOT_EXTRA_FOLDERS)); \
    ln -sf /system/bin $(TARGET_ROOT_OUT)/bin; \
    ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
    ln -sf /data/user_de/0/com.android.shell/files/bugreports $(TARGET_ROOT_OUT)/bugreports; \
    ln -sfn /sys/kernel/debug $(TARGET_ROOT_OUT)/d; \
    ln -sf /storage/self/primary $(TARGET_ROOT_OUT)/sdcard
ifdef BOARD_USES_VENDORIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/vendor
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/vendor $(TARGET_ROOT_OUT)/vendor
endif
ifdef BOARD_USES_PRODUCTIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/product
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/product $(TARGET_ROOT_OUT)/product
endif
ifdef BOARD_USES_SYSTEM_EXTIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/system_ext
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/system_ext $(TARGET_ROOT_OUT)/system_ext
endif
ifdef BOARD_USES_METADATA_PARTITION
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/metadata
endif

# For /odm partition.
LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/odm
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /odm partition. Those symlinks are for devices
# without /odm partition. For devices with /odm partition, mount odm.img under
# /odm will hide those symlinks.
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/app $(TARGET_ROOT_OUT)/odm/app
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/bin $(TARGET_ROOT_OUT)/odm/bin
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/etc $(TARGET_ROOT_OUT)/odm/etc
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/firmware $(TARGET_ROOT_OUT)/odm/firmware
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/framework $(TARGET_ROOT_OUT)/odm/framework
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/lib $(TARGET_ROOT_OUT)/odm/lib
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/lib64 $(TARGET_ROOT_OUT)/odm/lib64
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/overlay $(TARGET_ROOT_OUT)/odm/overlay
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/priv-app $(TARGET_ROOT_OUT)/odm/priv-app
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/odm/usr $(TARGET_ROOT_OUT)/odm/usr


# For /vendor_dlkm partition.
LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/vendor_dlkm
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /vendor_dlkm partition. Those symlinks are for
# devices without /vendor_dlkm partition. For devices with /vendor_dlkm
# partition, mount vendor_dlkm.img under /vendor_dlkm will hide those symlinks.
# Note that /vendor_dlkm/lib is omitted because vendor DLKMs should be accessed
# via /vendor/lib/modules directly.
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/vendor_dlkm/etc $(TARGET_ROOT_OUT)/vendor_dlkm/etc

# For /odm_dlkm partition.
LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/odm_dlkm
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /odm_dlkm partition. Those symlinks are for
# devices without /odm_dlkm partition. For devices with /odm_dlkm
# partition, mount odm_dlkm.img under /odm_dlkm will hide those symlinks.
# Note that /odm_dlkm/lib is omitted because odm DLKMs should be accessed
# via /odm/lib/modules directly.
LOCAL_POST_INSTALL_CMD += ; ln -sf /odm/odm_dlkm/etc $(TARGET_ROOT_OUT)/odm_dlkm/etc

ifdef BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/cache
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /data/cache $(TARGET_ROOT_OUT)/cache
endif
ifdef BOARD_ROOT_EXTRA_SYMLINKS
# BOARD_ROOT_EXTRA_SYMLINKS is a list of <target>:<link_name>.
  LOCAL_POST_INSTALL_CMD += $(foreach s, $(BOARD_ROOT_EXTRA_SYMLINKS),\
    $(eval p := $(subst :,$(space),$(s)))\
    ; mkdir -p $(dir $(TARGET_ROOT_OUT)/$(word 2,$(p))) \
    ; ln -sf $(word 1,$(p)) $(TARGET_ROOT_OUT)/$(word 2,$(p)))
endif

# The init symlink must be a post install command of a file that is to TARGET_ROOT_OUT.
# Since init.environ.rc is required for init and satisfies that requirement, we hijack it to create the symlink.
LOCAL_POST_INSTALL_CMD += ; ln -sf /system/bin/init $(TARGET_ROOT_OUT)/init

include $(BUILD_SYSTEM)/base_rules.mk

$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/init.environ.rc.in
	@echo "Generate: $< -> $@"
	@mkdir -p $(dir $@)
	$(hide) cp $< $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_ASAN_OPTIONS%?$(EXPORT_GLOBAL_ASAN_OPTIONS)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_GCOV_OPTIONS%?$(EXPORT_GLOBAL_GCOV_OPTIONS)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_CLANG_COVERAGE_OPTIONS%?$(EXPORT_GLOBAL_CLANG_COVERAGE_OPTIONS)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_HWASAN_OPTIONS%?$(EXPORT_GLOBAL_HWASAN_OPTIONS)?g' $@

# Append PLATFORM_VNDK_VERSION to base name.
define append_vndk_version
$(strip \
  $(basename $(1)).$(PLATFORM_VNDK_VERSION)$(suffix $(1)) \
)
endef

#######################################
# /etc/classpath
include $(CLEAR_VARS)
LOCAL_MODULE := etc_classpath
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := classpath
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE):
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo "export BOOTCLASSPATH $(PRODUCT_BOOTCLASSPATH)" > $@
	$(hide) echo "export DEX2OATBOOTCLASSPATH $(PRODUCT_DEX2OAT_BOOTCLASSPATH)" >> $@
	$(hide) echo "export SYSTEMSERVERCLASSPATH $(PRODUCT_SYSTEM_SERVER_CLASSPATH)" >> $@

#######################################
# sanitizer.libraries.txt
include $(CLEAR_VARS)
LOCAL_MODULE := sanitizer.libraries.txt
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE): PRIVATE_SANITIZER_RUNTIME_LIBRARIES := $(addsuffix .so,\
  $(ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(HWADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(UBSAN_RUNTIME_LIBRARY) \
  $(TSAN_RUNTIME_LIBRARY) \
  $(2ND_ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(2ND_HWADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(2ND_UBSAN_RUNTIME_LIBRARY) \
  $(2ND_TSAN_RUNTIME_LIBRARY))
$(LOCAL_BUILT_MODULE):
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo -n > $@
	$(hide) $(foreach lib,$(PRIVATE_SANITIZER_RUNTIME_LIBRARIES), \
		echo $(lib) >> $@;)

#######################################
# adb_debug.prop in debug ramdisk
include $(CLEAR_VARS)
LOCAL_MODULE := adb_debug.prop
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_DEBUG_RAMDISK_OUT)
include $(BUILD_PREBUILT)

include $(call all-makefiles-under,$(LOCAL_PATH))
