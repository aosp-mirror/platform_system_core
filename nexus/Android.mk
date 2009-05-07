BUILD_NEXUS := false
ifeq ($(BUILD_NEXUS),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                          \
                  main.cpp                 \
                  NetworkManager.cpp       \
                  CommandListener.cpp      \
                  Controller.cpp           \
                  WifiController.cpp       \
                  LoopController.cpp       \
                  NexusCommand.cpp         \
                  TiwlanWifiController.cpp \
                  Supplicant.cpp           \
                  SupplicantEvent.cpp      \
                  SupplicantListener.cpp   \
                  VpnController.cpp        \
                  ScanResult.cpp           \
                  WifiScanner.cpp          \

LOCAL_MODULE:= nexus

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libsysutils libwpa_client libutils

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  nexctl.c \

LOCAL_MODULE:= nexctl

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_NEXUS),true)
