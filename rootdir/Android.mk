LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

# files that live under /system/etc/...

copy_from := \
	etc/dbus.conf \
	etc/init.goldfish.sh \
	etc/hosts

ifeq ($(TARGET_PRODUCT),generic)
copy_from := etc/vold.conf
endif

copy_to := $(addprefix $(TARGET_OUT)/,$(copy_from))
copy_from := $(addprefix $(LOCAL_PATH)/,$(copy_from))

$(copy_to) : PRIVATE_MODULE := system_etcdir
$(copy_to) : $(TARGET_OUT)/% : $(LOCAL_PATH)/% | $(ACP)
	$(transform-prebuilt-to-target)

ALL_PREBUILT += $(copy_to)


# files that live under /...

# Only copy init.rc if the target doesn't have its own.
ifneq ($(TARGET_PROVIDES_INIT_RC),true)
file := $(TARGET_ROOT_OUT)/init.rc
$(file) : $(LOCAL_PATH)/init.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
endif

file := $(TARGET_ROOT_OUT)/init.goldfish.rc
$(file) : $(LOCAL_PATH)/etc/init.goldfish.rc | $(ACP)
	$(transform-prebuilt-to-target)
ALL_PREBUILT += $(file)
	

# create some directories (some are mount points)
DIRS := $(addprefix $(TARGET_ROOT_OUT)/, \
		sbin \
		dev \
		proc \
		sys \
		system \
		data \
	) \
	$(TARGET_OUT_DATA)

$(DIRS):
	@echo Directory: $@
	@mkdir -p $@

ALL_PREBUILT += $(DIRS)
