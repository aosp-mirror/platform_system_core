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

# Modules for asan.options.X files.

ASAN_OPTIONS_FILES :=

define create-asan-options-module
include $$(CLEAR_VARS)
LOCAL_MODULE := asan.options.$(1)
ASAN_OPTIONS_FILES += asan.options.$(1)
LOCAL_MODULE_CLASS := ETC
# The asan.options.off.template tries to turn off as much of ASAN as is possible.
LOCAL_SRC_FILES := asan.options.off.template
LOCAL_MODULE_PATH := $(TARGET_OUT)
include $$(BUILD_PREBUILT)
endef

# Pretty comprehensive set of native services. This list is helpful if all that's to be checked is an
# app.
ifeq ($(SANITIZE_LITE_SERVICES),true)
SANITIZE_ASAN_OPTIONS_FOR := \
  adbd \
  ATFWD-daemon \
  audioserver \
  bridgemgrd \
  cameraserver \
  cnd \
  debuggerd \
  debuggerd64 \
  dex2oat \
  drmserver \
  fingerprintd \
  gatekeeperd \
  installd \
  keystore \
  lmkd \
  logcat \
  logd \
  lowi-server \
  media.codec \
  mediadrmserver \
  media.extractor \
  mediaserver \
  mm-qcamera-daemon \
  mpdecision \
  netmgrd \
  perfd \
  perfprofd \
  qmuxd \
  qseecomd \
  rild \
  sdcard \
  servicemanager \
  slim_daemon \
  surfaceflinger \
  thermal-engine \
  time_daemon \
  update_engine \
  vold \
  wpa_supplicant \
  zip
endif

ifneq ($(SANITIZE_ASAN_OPTIONS_FOR),)
  $(foreach binary, $(SANITIZE_ASAN_OPTIONS_FOR), $(eval $(call create-asan-options-module,$(binary))))
endif

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
    sbin dev proc sys system data oem acct config storage mnt root $(BOARD_ROOT_EXTRA_FOLDERS)); \
    ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
    ln -sf /data/user_de/0/com.android.shell/files/bugreports $(TARGET_ROOT_OUT)/bugreports; \
    ln -sf /sys/kernel/debug $(TARGET_ROOT_OUT)/d; \
    ln -sf /storage/self/primary $(TARGET_ROOT_OUT)/sdcard
ifdef BOARD_USES_VENDORIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/vendor
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/vendor $(TARGET_ROOT_OUT)/vendor
endif
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

#######################################
# ld.config.txt
include $(CLEAR_VARS)

_enforce_vndk_at_runtime := false

ifdef BOARD_VNDK_VERSION
ifneq ($(BOARD_VNDK_RUNTIME_DISABLE),true)
  _enforce_vndk_at_runtime := true
endif
endif

ifeq ($(_enforce_vndk_at_runtime),true)
LOCAL_MODULE := ld.config.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
vndk_lib_md5 := $(word 1, $(shell echo $(LLNDK_LIBRARIES) $(VNDK_SAMEPROCESS_LIBRARIES) | $(MD5SUM)))
vndk_lib_dep := $(intermediates)/$(vndk_lib_md5).dep
$(vndk_lib_dep):
	$(hide) mkdir -p $(dir $@) && rm -rf $(dir $@)*.dep && touch $@

llndk_libraries := $(subst $(space),:,$(addsuffix .so,$(LLNDK_LIBRARIES)))

vndk_sameprocess_libraries := $(subst $(space),:,$(addsuffix .so,$(VNDK_SAMEPROCESS_LIBRARIES)))

vndk_core_libraries := $(subst $(space),:,$(addsuffix .so,$(VNDK_CORE_LIBRARIES)))

sanitizer_runtime_libraries := $(subst $(space),:,$(addsuffix .so,\
$(ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
$(UBSAN_RUNTIME_LIBRARY) \
$(TSAN_RUNTIME_LIBRARY) \
$(2ND_ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
$(2ND_UBSAN_RUNTIME_LIBRARY) \
$(2ND_TSAN_RUNTIME_LIBRARY)))

$(LOCAL_BUILT_MODULE): PRIVATE_LLNDK_LIBRARIES := $(llndk_libraries)
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_SAMEPROCESS_LIBRARIES := $(vndk_sameprocess_libraries)
$(LOCAL_BUILT_MODULE): PRIVATE_LLNDK_PRIVATE_LIBRARIES := $(llndk_private_libraries)
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_CORE_LIBRARIES := $(vndk_core_libraries)
$(LOCAL_BUILT_MODULE): PRIVATE_SANITIZER_RUNTIME_LIBRARIES := $(sanitizer_runtime_libraries)
$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/etc/ld.config.txt.in $(vndk_lib_dep)
	@echo "Generate: $< -> $@"
	@mkdir -p $(dir $@)
	$(hide) sed -e 's?%LLNDK_LIBRARIES%?$(PRIVATE_LLNDK_LIBRARIES)?g' $< >$@
	$(hide) sed -i -e 's?%VNDK_SAMEPROCESS_LIBRARIES%?$(PRIVATE_VNDK_SAMEPROCESS_LIBRARIES)?g' $@
	$(hide) sed -i -e 's?%VNDK_CORE_LIBRARIES%?$(PRIVATE_VNDK_CORE_LIBRARIES)?g' $@
	$(hide) sed -i -e 's?%SANITIZER_RUNTIME_LIBRARIES%?$(PRIVATE_SANITIZER_RUNTIME_LIBRARIES)?g' $@

vndk_lib_md5 :=
vndk_lib_dep :=
llndk_libraries :=
vndk_sameprocess_libraries :=
vndk_core_libraries :=
sanitizer_runtime_libraries :=
else # if _enforce_vndk_at_runtime is not true

LOCAL_MODULE := ld.config.txt
ifeq ($(PRODUCT_FULL_TREBLE)|$(SANITIZE_TARGET),true|)
LOCAL_SRC_FILES := etc/ld.config.txt
else
LOCAL_SRC_FILES := etc/ld.config.legacy.txt
endif
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_PREBUILT)
endif

#######################################
# llndk.libraries.txt
include $(CLEAR_VARS)
LOCAL_MODULE := llndk.libraries.txt
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
llndk_md5 = $(word 1, $(shell echo $(LLNDK_LIBRARIES) | $(MD5SUM)))
llndk_dep = $(intermediates)/$(llndk_md5).dep
$(llndk_dep):
	$(hide) mkdir -p $(dir $@) && rm -rf $(dir $@)*.dep && touch $@

$(LOCAL_BUILT_MODULE): PRIVATE_LLNDK_LIBRARIES := $(LLNDK_LIBRARIES)
$(LOCAL_BUILT_MODULE): $(llndk_dep)
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
LOCAL_MODULE_STEM := $(LOCAL_MODULE)
include $(BUILD_SYSTEM)/base_rules.mk
vndksp_md5 = $(word 1, $(shell echo $(LLNDK_LIBRARIES) | $(MD5SUM)))
vndksp_dep = $(intermediates)/$(vndksp_md5).dep
$(vndksp_dep):
	$(hide) mkdir -p $(dir $@) && rm -rf $(dir $@)*.dep && touch $@

$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_SAMEPROCESS_LIBRARIES := $(VNDK_SAMEPROCESS_LIBRARIES)
$(LOCAL_BUILT_MODULE): $(vndksp_dep)
	@echo "Generate: $@"
	@mkdir -p $(dir $@)
	$(hide) echo -n > $@
	$(hide) $(foreach lib,$(PRIVATE_VNDK_SAMEPROCESS_LIBRARIES), \
		echo $(lib).so >> $@;)
