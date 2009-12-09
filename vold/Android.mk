BUILD_VOLD := true
ifeq ($(BUILD_VOLD),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                \
                  vold.c       \
                  cmd_dispatch.c \
                  uevent.c       \
                  mmc.c          \
		  misc.c         \
                  blkdev.c       \
                  ums.c          \
                  geom_mbr_enc.c \
                  volmgr.c       \
                  media.c        \
                  volmgr_vfat.c  \
                  volmgr_ext3.c  \
                  logwrapper.c   \
                  ProcessKiller.c\
                  switch.c       \
                  format.c       \
                  devmapper.c

LOCAL_MODULE:= vold

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_VOLD),true)
