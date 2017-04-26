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
ifeq ($(SANITIZE_LITE),true)
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
  LOCAL_REQUIRED_MODULES := asan.options $(ASAN_OPTIONS_FILES)
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

bcp_md5 :=
bcp_dep :=
#######################################
