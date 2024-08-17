LOCAL_PATH:= $(call my-dir)

$(eval $(call declare-1p-copy-files,system/core/rootdir,))

#######################################
ifneq ($(filter address,$(SANITIZE_TARGET)),)
ASAN_EXTRACT_FILES :=
ifeq ($(SANITIZE_TARGET_SYSTEM),true)
ASAN_EXTRACT_FILES := asan_extract
endif
endif
#######################################
# init.environ.rc
# TODO(b/353429422): move LOCAL_POST_INSTALL_CMD to other rules and remove Android.mk module.

include $(CLEAR_VARS)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE := init.environ.rc
LOCAL_LICENSE_KINDS := SPDX-license-identifier-Apache-2.0
LOCAL_LICENSE_CONDITIONS := notice
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

ifneq ($(filter address,$(SANITIZE_TARGET)),)
  LOCAL_REQUIRED_MODULES := asan.options $(ASAN_EXTRACT_FILES)
endif

# Put it here instead of in init.rc module definition,
# because init.rc is conditionally included.
#
# create some directories (some are mount points) and symlinks
LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
    dev proc sys system data data_mirror odm oem acct config storage mnt apex bootstrap-apex debug_ramdisk \
    linkerconfig second_stage_resources postinstall tmp $(BOARD_ROOT_EXTRA_FOLDERS)); \
    ln -sf /system/bin $(TARGET_ROOT_OUT)/bin; \
    ln -sf /system/etc $(TARGET_ROOT_OUT)/etc; \
    ln -sf /data/user_de/0/com.android.shell/files/bugreports $(TARGET_ROOT_OUT)/bugreports; \
    ln -sfn /sys/kernel/debug $(TARGET_ROOT_OUT)/d; \
    ln -sf /storage/self/primary $(TARGET_ROOT_OUT)/sdcard

ALL_ROOTDIR_SYMLINKS := \
  $(TARGET_ROOT_OUT)/bin \
  $(TARGET_ROOT_OUT)/etc \
  $(TARGET_ROOT_OUT)/bugreports \
  $(TARGET_ROOT_OUT)/d \
  $(TARGET_ROOT_OUT)/sdcard

ifdef BOARD_USES_VENDORIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/vendor
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/vendor $(TARGET_ROOT_OUT)/vendor
  ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/vendor
endif
ifdef BOARD_USES_PRODUCTIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/product
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/product $(TARGET_ROOT_OUT)/product
  ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/product
endif
ifdef BOARD_USES_SYSTEM_EXTIMAGE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/system_ext
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /system/system_ext $(TARGET_ROOT_OUT)/system_ext
  ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/system_ext
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

ALL_ROOTDIR_SYMLINKS += \
  $(TARGET_ROOT_OUT)/odm/app \
  $(TARGET_ROOT_OUT)/odm/bin \
  $(TARGET_ROOT_OUT)/odm/etc \
  $(TARGET_ROOT_OUT)/odm/firmware \
  $(TARGET_ROOT_OUT)/odm/framework \
  $(TARGET_ROOT_OUT)/odm/lib \
  $(TARGET_ROOT_OUT)/odm/lib64 \
  $(TARGET_ROOT_OUT)/odm/overlay \
  $(TARGET_ROOT_OUT)/odm/priv-app \
  $(TARGET_ROOT_OUT)/odm/usr


# For /vendor_dlkm partition.
LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/vendor_dlkm
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /vendor_dlkm partition. Those symlinks are for
# devices without /vendor_dlkm partition. For devices with /vendor_dlkm
# partition, mount vendor_dlkm.img under /vendor_dlkm will hide those symlinks.
# Note that /vendor_dlkm/lib is omitted because vendor DLKMs should be accessed
# via /vendor/lib/modules directly.
LOCAL_POST_INSTALL_CMD += ; ln -sf /vendor/vendor_dlkm/etc $(TARGET_ROOT_OUT)/vendor_dlkm/etc
ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/vendor_dlkm/etc

# For /odm_dlkm partition.
LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/odm_dlkm
# For Treble Generic System Image (GSI), system-as-root GSI needs to work on
# both devices with and without /odm_dlkm partition. Those symlinks are for
# devices without /odm_dlkm partition. For devices with /odm_dlkm
# partition, mount odm_dlkm.img under /odm_dlkm will hide those symlinks.
# Note that /odm_dlkm/lib is omitted because odm DLKMs should be accessed
# via /odm/lib/modules directly.
LOCAL_POST_INSTALL_CMD += ; ln -sf /odm/odm_dlkm/etc $(TARGET_ROOT_OUT)/odm_dlkm/etc
ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/odm_dlkm/etc

# For /system_dlkm partition
LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/system_dlkm

ifdef BOARD_CACHEIMAGE_FILE_SYSTEM_TYPE
  LOCAL_POST_INSTALL_CMD += ; mkdir -p $(TARGET_ROOT_OUT)/cache
else
  LOCAL_POST_INSTALL_CMD += ; ln -sf /data/cache $(TARGET_ROOT_OUT)/cache
  ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/cache
endif
ifdef BOARD_ROOT_EXTRA_SYMLINKS
# BOARD_ROOT_EXTRA_SYMLINKS is a list of <target>:<link_name>.
  LOCAL_POST_INSTALL_CMD += $(foreach s, $(BOARD_ROOT_EXTRA_SYMLINKS),\
    $(eval p := $(subst :,$(space),$(s)))\
    ; mkdir -p $(dir $(TARGET_ROOT_OUT)/$(word 2,$(p))) \
    ; ln -sf $(word 1,$(p)) $(TARGET_ROOT_OUT)/$(word 2,$(p)))
  ALL_ROOTDIR_SYMLINKS += $(foreach s,$(BOARD_ROOT_EXTRA_SYMLINKS),$(TARGET_ROOT_OUT)/$(call word-colon,2,$s))
endif

# The init symlink must be a post install command of a file that is to TARGET_ROOT_OUT.
# Since init.environ.rc is required for init and satisfies that requirement, we hijack it to create the symlink.
LOCAL_POST_INSTALL_CMD += ; ln -sf /system/bin/init $(TARGET_ROOT_OUT)/init
ALL_ROOTDIR_SYMLINKS += $(TARGET_ROOT_OUT)/init

ALL_DEFAULT_INSTALLED_MODULES += $(ALL_ROOTDIR_SYMLINKS)

include $(BUILD_SYSTEM)/base_rules.mk

$(ALL_ROOTDIR_SYMLINKS): $(LOCAL_BUILT_MODULE)

init.environ.rc-soong := $(call intermediates-dir-for,ETC,init.environ.rc-soong)/init.environ.rc-soong
$(eval $(call copy-one-file,$(init.environ.rc-soong),$(LOCAL_BUILT_MODULE)))
init.environ.rc-soong :=

