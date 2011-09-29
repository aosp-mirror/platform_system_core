LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
        dhcpclient.c \
        dhcpmsg.c \
        dhcp_utils.c \
        ifc_utils.c \
        packet.c

LOCAL_SHARED_LIBRARIES := \
        libcutils

LOCAL_MODULE:= libnetutils

include $(BUILD_SHARED_LIBRARY)
