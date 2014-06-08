LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

TOOLS := \
	cat \
	chcon \
	chmod \
	chown \
	clear \
	cmp \
	date \
	dd \
	df \
	dmesg \
	du \
	getenforce \
	getevent \
	getprop \
	getsebool \
	hd \
	id \
	ifconfig \
	iftop \
	insmod \
	ioctl \
	ionice \
	kill \
	ln \
	load_policy \
	log \
	ls \
	lsmod \
	lsof \
	md5 \
	mkdir \
	mkswap \
	mount \
	mv \
	nandread \
	netstat \
	newfs_msdos \
	notify \
	printenv \
	ps \
	readlink \
	renice \
	restorecon \
	rm \
	rmdir \
	rmmod \
	route \
	runcon \
	schedtop \
	sendevent \
	setenforce \
	setprop \
	setsebool \
	sleep \
	smd \
	start \
	stop \
	swapoff \
	swapon \
	sync \
	top \
	touch \
	umount \
	uptime \
	vmstat \
	watchprops \
	wipe \

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
TOOLS += r
endif

ALL_TOOLS = $(TOOLS)
ALL_TOOLS += \
	cp \
	grep

LOCAL_SRC_FILES := \
	cp/cp.c \
	cp/utils.c \
	dynarray.c \
	grep/fastgrep.c \
	grep/file.c \
	grep/grep.c \
	grep/queue.c \
	grep/util.c \
	$(patsubst %,%.c,$(TOOLS)) \
	toolbox.c \
	uid_from_user.c \

LOCAL_CFLAGS += \
    -std=gnu99 \
    -Werror -Wno-unused-parameter \
    -include bsd-compatibility.h \

LOCAL_C_INCLUDES += external/openssl/include

LOCAL_SHARED_LIBRARIES := \
    libcrypto \
    libcutils \
    libselinux \

# libusbhost is only used by lsusb, and that isn't usually included in toolbox.
# The linker strips out all the unused library code in the normal case.
LOCAL_STATIC_LIBRARIES := \
    libusbhost \

LOCAL_MODULE := toolbox
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk

# Including this will define $(intermediates).
#
include $(BUILD_EXECUTABLE)

$(LOCAL_PATH)/toolbox.c: $(intermediates)/tools.h

TOOLS_H := $(intermediates)/tools.h
$(TOOLS_H): PRIVATE_TOOLS := $(ALL_TOOLS)
$(TOOLS_H): PRIVATE_CUSTOM_TOOL = echo "/* file generated automatically */" > $@ ; for t in $(PRIVATE_TOOLS) ; do echo "TOOL($$t)" >> $@ ; done
$(TOOLS_H): $(LOCAL_PATH)/Android.mk
$(TOOLS_H):
	$(transform-generated-source)

# Make #!/system/bin/toolbox launchers for each tool.
#
SYMLINKS := $(addprefix $(TARGET_OUT)/bin/,$(ALL_TOOLS))
$(SYMLINKS): TOOLBOX_BINARY := $(LOCAL_MODULE)
$(SYMLINKS): $(LOCAL_INSTALLED_MODULE) $(LOCAL_PATH)/Android.mk
	@echo "Symlink: $@ -> $(TOOLBOX_BINARY)"
	@mkdir -p $(dir $@)
	@rm -rf $@
	$(hide) ln -sf $(TOOLBOX_BINARY) $@

ALL_DEFAULT_INSTALLED_MODULES += $(SYMLINKS)

# We need this so that the installed files could be picked up based on the
# local module name
ALL_MODULES.$(LOCAL_MODULE).INSTALLED := \
    $(ALL_MODULES.$(LOCAL_MODULE).INSTALLED) $(SYMLINKS)
