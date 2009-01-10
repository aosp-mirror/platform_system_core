LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=        \
    AutoMount.c          \
    ProcessKiller.c      \
    Server.c             \
    mountd.c		 \
    ASEC.c		 \
    logwrapper.c

LOCAL_MODULE:= mountd

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := -DCREATE_MOUNT_POINTS=0

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)
