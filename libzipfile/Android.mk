LOCAL_PATH:= $(call my-dir)

# build host static library
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	centraldir.c \
	zipfile.c

LOCAL_STATIC_LIBRARIES := libz

LOCAL_MODULE:= libzipfile

LOCAL_CFLAGS := -Werror

LOCAL_MULTILIB := both

include $(BUILD_HOST_STATIC_LIBRARY)

# build device static library
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	centraldir.c \
	zipfile.c

LOCAL_STATIC_LIBRARIES := libz

LOCAL_MODULE:= libzipfile

LOCAL_CFLAGS := -Werror

include $(BUILD_STATIC_LIBRARY)


# build test_zipfile
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	test_zipfile.c

LOCAL_STATIC_LIBRARIES := libzipfile libz

LOCAL_MODULE := test_zipfile

LOCAL_CFLAGS := -Werror

include $(BUILD_HOST_EXECUTABLE)
