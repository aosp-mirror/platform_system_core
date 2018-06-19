LOCAL_PATH:= $(call my-dir)

#######################################
# init.rc
include $(CLEAR_VARS)

LOCAL_MODULE := init.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_PREBUILT)

#######################################
# init-debug.rc
include $(CLEAR_VARS)

LOCAL_MODULE := init-debug.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_TAGS := debug
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/init

include $(BUILD_PREBUILT)

#######################################
# asan.options
ifneq ($(filter address,$(SANITIZE_TARGET)),)

include $(CLEAR_VARS)

LOCAL_MODULE := asan.options
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_PATH := $(TARGET_OUT)

include $(BUILD_PREBUILT)

# ASAN extration.
ASAN_EXTRACT_FILES :=
ifeq ($(SANITIZE_TARGET_SYSTEM),true)
include $(CLEAR_VARS)
LOCAL_MODULE:= asan_extract
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
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

EXPORT_GLOBAL_ASAN_OPTIONS :=
ifneq ($(filter address,$(SANITIZE_TARGET)),)
  EXPORT_GLOBAL_ASAN_OPTIONS := export ASAN_OPTIONS include=/system/asan.options
  LOCAL_REQUIRED_MODULES := asan.options $(ASAN_OPTIONS_FILES) $(ASAN_EXTRACT_FILES)
endif

EXPORT_GLOBAL_GCOV_OPTIONS :=
ifeq ($(NATIVE_COVERAGE),true)
  EXPORT_GLOBAL_GCOV_OPTIONS := export GCOV_PREFIX /data/misc/gcov
endif

# Put it here instead of in init.rc module definition,
# because init.rc is conditionally included.
#
# create some directories (some are mount points) and symlinks
LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
    sbin dev proc sys system data odm oem acct config storage mnt $(BOARD_ROOT_EXTRA_FOLDERS)); \
    ln -sf /system/bin $(TARGET_ROOT_OUT)/bin; \
    ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
    ln -sf /data/user_de/0/com.android.shell/files/bugreports $(TARGET_ROOT_OUT)/bugreports; \
    ln -sf /sys/kernel/debug $(TARGET_ROOT_OUT)/d; \
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
# The A/B updater uses a top-level /postinstall directory to mount the new
# system before reboot.
ifeq ($(AB_OTA_UPDATER),true)
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/postinstall
endif

include $(BUILD_SYSTEM)/base_rules.mk

# Regenerate init.environ.rc if PRODUCT_BOOTCLASSPATH has changed.
bcp_md5 := $(word 1, $(shell echo $(PRODUCT_BOOTCLASSPATH) $(PRODUCT_SYSTEM_SERVER_CLASSPATH) | $(MD5SUM)))
bcp_dep := $(intermediates)/$(bcp_md5).bcp.dep
$(bcp_dep) :
	$(hide) mkdir -p $(dir $@) && rm -rf $(dir $@)*.bcp.dep && touch $@

$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/init.environ.rc.in $(bcp_dep)
	@echo "Generate: $< -> $@"
	@mkdir -p $(dir $@)
	$(hide) sed -e 's?%BOOTCLASSPATH%?$(PRODUCT_BOOTCLASSPATH)?g' $< >$@
	$(hide) sed -i -e 's?%SYSTEMSERVERCLASSPATH%?$(PRODUCT_SYSTEM_SERVER_CLASSPATH)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_ASAN_OPTIONS%?$(EXPORT_GLOBAL_ASAN_OPTIONS)?g' $@
	$(hide) sed -i -e 's?%EXPORT_GLOBAL_GCOV_OPTIONS%?$(EXPORT_GLOBAL_GCOV_OPTIONS)?g' $@

bcp_md5 :=
bcp_dep :=

# Append PLATFORM_VNDK_VERSION to base name.
define append_vndk_version
$(strip \
  $(basename $(1)).$(PLATFORM_VNDK_VERSION)$(suffix $(1)) \
)
endef

# Update namespace configuration file with library lists and VNDK version
#
# $(1): Input source file (ld.config.txt)
# $(2): Output built module
# $(3): VNDK version suffix
# $(4): true if libz must be included in llndk not in vndk-sp
define update_and_install_ld_config
# If $(4) is true, move libz to llndk from vndk-sp.
$(if $(filter true,$(4)),\
  $(eval llndk_libraries_list := $(LLNDK_LIBRARIES) libz) \
  $(eval vndksp_libraries_list := $(filter-out libz,$(VNDK_SAMEPROCESS_LIBRARIES))),\
  $(eval llndk_libraries_list := $(LLNDK_LIBRARIES)) \
  $(eval vndksp_libraries_list := $(VNDK_SAMEPROCESS_LIBRARIES)))

llndk_libraries := $(call normalize-path-list,$(addsuffix .so,\
  $(filter-out $(VNDK_PRIVATE_LIBRARIES),$(llndk_libraries_list))))
private_llndk_libraries := $(call normalize-path-list,$(addsuffix .so,\
  $(filter $(VNDK_PRIVATE_LIBRARIES),$(llndk_libraries_list))))
vndk_sameprocess_libraries := $(call normalize-path-list,$(addsuffix .so,\
  $(filter-out $(VNDK_PRIVATE_LIBRARIES),$(vndksp_libraries_list))))
vndk_core_libraries := $(call normalize-path-list,$(addsuffix .so,\
  $(filter-out $(VNDK_PRIVATE_LIBRARIES),$(VNDK_CORE_LIBRARIES))))
sanitizer_runtime_libraries := $(call normalize-path-list,$(addsuffix .so,\
  $(ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(UBSAN_RUNTIME_LIBRARY) \
  $(TSAN_RUNTIME_LIBRARY) \
  $(2ND_ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(2ND_UBSAN_RUNTIME_LIBRARY) \
  $(2ND_TSAN_RUNTIME_LIBRARY)))
# If BOARD_VNDK_VERSION is not defined, VNDK version suffix will not be used.
vndk_version_suffix := $(if $(strip $(3)),-$(strip $(3)))

$(2): PRIVATE_LLNDK_LIBRARIES := $$(llndk_libraries)
$(2): PRIVATE_PRIVATE_LLNDK_LIBRARIES := $$(private_llndk_libraries)
$(2): PRIVATE_VNDK_SAMEPROCESS_LIBRARIES := $$(vndk_sameprocess_libraries)
$(2): PRIVATE_VNDK_CORE_LIBRARIES := $$(vndk_core_libraries)
$(2): PRIVATE_SANITIZER_RUNTIME_LIBRARIES := $$(sanitizer_runtime_libraries)
$(2): PRIVATE_VNDK_VERSION := $$(vndk_version_suffix)
$(2): $(1)
	@echo "Generate: $$< -> $$@"
	@mkdir -p $$(dir $$@)
	$$(hide) sed -e 's?%LLNDK_LIBRARIES%?$$(PRIVATE_LLNDK_LIBRARIES)?g' $$< >$$@
	$$(hide) sed -i -e 's?%PRIVATE_LLNDK_LIBRARIES%?$$(PRIVATE_PRIVATE_LLNDK_LIBRARIES)?g' $$@
	$$(hide) sed -i -e 's?%VNDK_SAMEPROCESS_LIBRARIES%?$$(PRIVATE_VNDK_SAMEPROCESS_LIBRARIES)?g' $$@
	$$(hide) sed -i -e 's?%VNDK_CORE_LIBRARIES%?$$(PRIVATE_VNDK_CORE_LIBRARIES)?g' $$@
	$$(hide) sed -i -e 's?%SANITIZER_RUNTIME_LIBRARIES%?$$(PRIVATE_SANITIZER_RUNTIME_LIBRARIES)?g' $$@
	$$(hide) sed -i -e 's?%VNDK_VER%?$$(PRIVATE_VNDK_VERSION)?g' $$@
	$$(hide) sed -i -e 's?%PRODUCT%?$$(TARGET_COPY_OUT_PRODUCT)?g' $$@

llndk_libraries_list :=
vndksp_libraries_list :=
llndk_libraries :=
private_llndk_libraries :=
vndk_sameprocess_libraries :=
vndk_core_libraries :=
sanitizer_runtime_libraries :=
vndk_version_suffix :=
endef # update_and_install_ld_config


#######################################
# ld.config.txt selection variables
#
_enforce_vndk_at_runtime := false
ifdef BOARD_VNDK_VERSION
  ifneq ($(BOARD_VNDK_RUNTIME_DISABLE),true)
    _enforce_vndk_at_runtime := true
  endif
endif

_enforce_vndk_lite_at_runtime := false
ifeq ($(_enforce_vndk_at_runtime),false)
  ifeq ($(PRODUCT_TREBLE_LINKER_NAMESPACES)|$(SANITIZE_TARGET),true|)
    _enforce_vndk_lite_at_runtime := true
  endif
endif

#######################################
# ld.config.txt
#
# For VNDK enforced devices that have defined BOARD_VNDK_VERSION, use
# "ld.config.txt" as a source file. This configuration includes strict VNDK
# run-time restrictions for vendor process.
#
# Other treblized devices, that have not defined BOARD_VNDK_VERSION or that
# have set BOARD_VNDK_RUNTIME_DISABLE to true, use "ld.config.vndk_lite.txt"
# as a source file. This configuration does not have strict VNDK run-time
# restrictions.
#
# If the device is not treblized, use "ld.config.legacy.txt" for legacy
# namespace configuration.
#
include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)

ifeq ($(_enforce_vndk_at_runtime),true)

# for VNDK enforced devices
LOCAL_MODULE_STEM := $(call append_vndk_version,$(LOCAL_MODULE))
include $(BUILD_SYSTEM)/base_rules.mk
$(eval $(call update_and_install_ld_config,\
  $(LOCAL_PATH)/etc/ld.config.txt,\
  $(LOCAL_BUILT_MODULE),\
  $(PLATFORM_VNDK_VERSION)))

else ifeq ($(_enforce_vndk_lite_at_runtime),true)

# for treblized but VNDK lightly enforced devices
LOCAL_MODULE_STEM := ld.config.vndk_lite.txt
include $(BUILD_SYSTEM)/base_rules.mk
$(eval $(call update_and_install_ld_config,\
  $(LOCAL_PATH)/etc/ld.config.vndk_lite.txt,\
  $(LOCAL_BUILT_MODULE),\
  $(PLATFORM_VNDK_VERSION),\
  true))

else

# for legacy non-treblized devices
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
LOCAL_SRC_FILES := etc/ld.config.legacy.txt
include $(BUILD_PREBUILT)

endif  # ifeq ($(_enforce_vndk_at_runtime),true)


#######################################
# ld.config.vndk_lite.txt
#
# This module is only for GSI.
#
ifeq ($(_enforce_vndk_lite_at_runtime),false)

include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.vndk_lite.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
$(eval $(call update_and_install_ld_config,\
  $(LOCAL_PATH)/etc/ld.config.vndk_lite.txt,\
  $(LOCAL_BUILT_MODULE),\
  $(PLATFORM_VNDK_VERSION),\
  true))

endif  # ifeq ($(_enforce_vndk_lite_at_runtime),false)

_enforce_vndk_at_runtime :=
_enforce_vndk_lite_at_runtime :=

#######################################
# ld.config.txt for recovery
include $(CLEAR_VARS)
LOCAL_MODULE := ld.config.recovery.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_SRC_FILES := etc/ld.config.recovery.txt
LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/etc
LOCAL_MODULE_STEM := ld.config.txt
include $(BUILD_PREBUILT)

#######################################
# llndk.libraries.txt
include $(CLEAR_VARS)
LOCAL_MODULE := llndk.libraries.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(call append_vndk_version,$(LOCAL_MODULE))
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE): PRIVATE_LLNDK_LIBRARIES := $(LLNDK_LIBRARIES)
$(LOCAL_BUILT_MODULE):
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo -n > $@
	$(hide) $(foreach lib,$(PRIVATE_LLNDK_LIBRARIES), \
		echo $(lib).so >> $@;)

#######################################
# vndksp.libraries.txt
include $(CLEAR_VARS)
LOCAL_MODULE := vndksp.libraries.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(call append_vndk_version,$(LOCAL_MODULE))
include $(BUILD_SYSTEM)/base_rules.mk
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_SAMEPROCESS_LIBRARIES := $(VNDK_SAMEPROCESS_LIBRARIES)
$(LOCAL_BUILT_MODULE):
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo -n > $@
	$(hide) $(foreach lib,$(PRIVATE_VNDK_SAMEPROCESS_LIBRARIES), \
		echo $(lib).so >> $@;)
