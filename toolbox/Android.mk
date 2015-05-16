LOCAL_PATH:= $(call my-dir)


common_cflags := \
    -std=gnu99 \
    -Werror -Wno-unused-parameter \
    -I$(LOCAL_PATH)/upstream-netbsd/include/ \
    -include bsd-compatibility.h \


include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    upstream-netbsd/bin/dd/args.c \
    upstream-netbsd/bin/dd/conv.c \
    upstream-netbsd/bin/dd/dd.c \
    upstream-netbsd/bin/dd/dd_hostops.c \
    upstream-netbsd/bin/dd/misc.c \
    upstream-netbsd/bin/dd/position.c \
    upstream-netbsd/lib/libc/gen/getbsize.c \
    upstream-netbsd/lib/libc/gen/humanize_number.c \
    upstream-netbsd/lib/libc/stdlib/strsuftoll.c \
    upstream-netbsd/lib/libc/string/swab.c \
    upstream-netbsd/lib/libutil/raise_default_signal.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=dd_main -DNO_CONV
LOCAL_MODULE := libtoolbox_dd
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := upstream-netbsd/usr.bin/du/du.c
LOCAL_CFLAGS += $(common_cflags) -Dmain=du_main
LOCAL_MODULE := libtoolbox_du
include $(BUILD_STATIC_LIBRARY)


include $(CLEAR_VARS)

BSD_TOOLS := \
    dd \
    du \

OUR_TOOLS := \
    df \
    getevent \
    iftop \
    ioctl \
    ionice \
    log \
    ls \
    lsof \
    mount \
    nandread \
    newfs_msdos \
    ps \
    prlimit \
    renice \
    sendevent \
    start \
    stop \
    top \
    uptime \
    watchprops \

ALL_TOOLS = $(BSD_TOOLS) $(OUR_TOOLS)

LOCAL_SRC_FILES := \
    toolbox.c \
    $(patsubst %,%.c,$(OUR_TOOLS)) \

LOCAL_CFLAGS += $(common_cflags)

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libselinux \

LOCAL_WHOLE_STATIC_LIBRARIES := $(patsubst %,libtoolbox_%,$(BSD_TOOLS))

LOCAL_MODULE := toolbox

# Install the symlinks.
LOCAL_POST_INSTALL_CMD := $(hide) $(foreach t,$(ALL_TOOLS),ln -sf toolbox $(TARGET_OUT)/bin/$(t);)

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

$(LOCAL_PATH)/getevent.c: $(intermediates)/input.h-labels.h

INPUT_H_LABELS_H := $(intermediates)/input.h-labels.h
$(INPUT_H_LABELS_H): PRIVATE_LOCAL_PATH := $(LOCAL_PATH)
$(INPUT_H_LABELS_H): PRIVATE_CUSTOM_TOOL = $(PRIVATE_LOCAL_PATH)/generate-input.h-labels.py > $@
$(INPUT_H_LABELS_H): $(LOCAL_PATH)/Android.mk $(LOCAL_PATH)/generate-input.h-labels.py
$(INPUT_H_LABELS_H):
	$(transform-generated-source)

# We only want 'r' on userdebug and eng builds.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := r.c
LOCAL_CFLAGS += $(common_cflags)
LOCAL_MODULE := r
LOCAL_MODULE_TAGS := debug
include $(BUILD_EXECUTABLE)


# We build BSD grep separately, so it can provide egrep and fgrep too.
include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    upstream-netbsd/usr.bin/grep/fastgrep.c \
    upstream-netbsd/usr.bin/grep/file.c \
    upstream-netbsd/usr.bin/grep/grep.c \
    upstream-netbsd/usr.bin/grep/queue.c \
    upstream-netbsd/usr.bin/grep/util.c
LOCAL_CFLAGS += $(common_cflags)
LOCAL_MODULE := grep
LOCAL_POST_INSTALL_CMD := $(hide) $(foreach t,egrep fgrep,ln -sf grep $(TARGET_OUT)/bin/$(t);)
include $(BUILD_EXECUTABLE)
