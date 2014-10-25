LOCAL_PATH:= $(call my-dir)


common_cflags := \
    -std=gnu99 \
    -Werror -Wno-unused-parameter \
    -I$(LOCAL_PATH)/upstream-netbsd/include/ \
    -include bsd-compatibility.h \


include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/cat/cat.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=cat_main
LOCAL_MODULE := libtoolbox_cat
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/sbin/chown/chown.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=chown_main
LOCAL_MODULE := libtoolbox_chown
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    upstream-netbsd/bin/cp/cp.c \
    upstream-netbsd/bin/cp/utils.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=cp_main
LOCAL_MODULE := libtoolbox_cp
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    upstream-netbsd/bin/dd/args.c \
    upstream-netbsd/bin/dd/conv.c \
    upstream-netbsd/bin/dd/dd.c \
    upstream-netbsd/bin/dd/dd_hostops.c \
    upstream-netbsd/bin/dd/misc.c \
    upstream-netbsd/bin/dd/position.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=dd_main -DNO_CONV
LOCAL_MODULE := libtoolbox_dd
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/usr.bin/du/du.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=du_main
LOCAL_MODULE := libtoolbox_du
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    upstream-netbsd/usr.bin/grep/fastgrep.c \
    upstream-netbsd/usr.bin/grep/file.c \
    upstream-netbsd/usr.bin/grep/grep.c \
    upstream-netbsd/usr.bin/grep/queue.c \
    upstream-netbsd/usr.bin/grep/util.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=grep_main
LOCAL_MODULE := libtoolbox_grep
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/kill/kill.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=kill_main
LOCAL_MODULE := libtoolbox_kill
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/ln/ln.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=ln_main
LOCAL_MODULE := libtoolbox_ln
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/mv/mv.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=mv_main -D__SVR4
LOCAL_MODULE := libtoolbox_mv
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/usr.bin/printenv/printenv.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=printenv_main
LOCAL_MODULE := libtoolbox_printenv
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/rm/rm.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=rm_main
LOCAL_MODULE := libtoolbox_rm
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/rmdir/rmdir.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=rmdir_main
LOCAL_MODULE := libtoolbox_rmdir
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/sleep/sleep.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=sleep_main
LOCAL_MODULE := libtoolbox_sleep
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/bin/sync/sync.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=sync_main
LOCAL_MODULE := libtoolbox_sync
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
include $(BUILD_STATIC_LIBRARY)


include $(CLEAR_VARS)

BSD_TOOLS := \
    cat \
    chown \
    cp \
    dd \
    du \
    grep \
    kill \
    ln \
    mv \
    printenv \
    rm \
    rmdir \
    sleep \
    sync \

OUR_TOOLS := \
    chcon \
    chmod \
    clear \
    cmp \
    date \
    df \
    dmesg \
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
    load_policy \
    log \
    ls \
    lsmod \
    lsof \
    md5 \
    mkdir \
    mknod \
    mkswap \
    mount \
    nandread \
    netstat \
    newfs_msdos \
    nohup \
    notify \
    ps \
    readlink \
    renice \
    restorecon \
    prlimit \
    rmmod \
    route \
    runcon \
    schedtop \
    sendevent \
    setenforce \
    setprop \
    setsebool \
    smd \
    start \
    stop \
    swapoff \
    swapon \
    top \
    touch \
    umount \
    uptime \
    vmstat \
    watchprops \
    wipe \

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
OUR_TOOLS += r
endif

ALL_TOOLS = $(BSD_TOOLS) $(OUR_TOOLS)

LOCAL_SRC_FILES := \
    upstream-netbsd/lib/libc/gen/getbsize.c \
    upstream-netbsd/lib/libc/gen/humanize_number.c \
    upstream-netbsd/lib/libc/stdlib/strsuftoll.c \
    upstream-netbsd/lib/libc/string/swab.c \
    upstream-netbsd/lib/libutil/raise_default_signal.c \
    dynarray.c \
    pwcache.c \
    $(patsubst %,%.c,$(OUR_TOOLS)) \
    toolbox.c \

LOCAL_CFLAGS += $(common_cflags)

LOCAL_C_INCLUDES += external/openssl/include

LOCAL_SHARED_LIBRARIES := \
    libcrypto \
    libcutils \
    libselinux \

# libusbhost is only used by lsusb, and that isn't usually included in toolbox.
# The linker strips out all the unused library code in the normal case.
LOCAL_STATIC_LIBRARIES := \
    libusbhost \

LOCAL_WHOLE_STATIC_LIBRARIES := $(patsubst %,libtoolbox_%,$(BSD_TOOLS))

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
