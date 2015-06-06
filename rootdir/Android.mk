LOCAL_PATH:= $(call my-dir)

#######################################
# init.rc
# Only copy init.rc if the target doesn't have its own.
ifneq ($(TARGET_PROVIDES_INIT_RC),true)
include $(CLEAR_VARS)

LOCAL_MODULE := init.rc
LOCAL_SRC_FILES := $(LOCAL_MODULE)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

include $(BUILD_PREBUILT)
endif
#######################################
# init.environ.rc

include $(CLEAR_VARS)
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE := init.environ.rc
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)

# Put it here instead of in init.rc module definition,
# because init.rc is conditionally included.
#
# create some directories (some are mount points)
LOCAL_POST_INSTALL_CMD := mkdir -p $(addprefix $(TARGET_ROOT_OUT)/, \
    sbin dev proc sys system data oem acct config storage mnt root)

include $(BUILD_SYSTEM)/base_rules.mk

EXPORT_GLOBAL_ASAN_OPTIONS :=
ifeq (address,$(strip $(SANITIZE_TARGET)))
  EXPORT_GLOBAL_ASAN_OPTIONS := export ASAN_OPTIONS allow_user_segv_handler=1:detect_odr_violation=0:alloc_dealloc_mismatch=0
endif

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
