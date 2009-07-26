BUILD_NEXUS := false
ifeq ($(BUILD_NEXUS),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
                  main.cpp                             \
                  NetworkManager.cpp                   \
                  CommandListener.cpp                  \
                  Controller.cpp                       \
                  WifiController.cpp                   \
                  LoopController.cpp                   \
                  NexusCommand.cpp                     \
                  TiwlanWifiController.cpp             \
                  Supplicant.cpp                       \
                  SupplicantEvent.cpp                  \
                  SupplicantListener.cpp               \
                  VpnController.cpp                    \
                  ScanResult.cpp                       \
                  WifiScanner.cpp                      \
                  WifiNetwork.cpp                      \
                  OpenVpnController.cpp                \
                  InterfaceConfig.cpp                  \
                  PropertyManager.cpp                  \
                  SupplicantState.cpp                  \
                  SupplicantEventFactory.cpp           \
                  SupplicantConnectedEvent.cpp         \
                  SupplicantAssociatingEvent.cpp       \
                  SupplicantAssociatedEvent.cpp        \
                  SupplicantStateChangeEvent.cpp       \
                  SupplicantScanResultsEvent.cpp       \
                  SupplicantConnectionTimeoutEvent.cpp \
                  SupplicantDisconnectedEvent.cpp      \
                  SupplicantStatus.cpp                 \
                  TiwlanEventListener.cpp              \
                  DhcpClient.cpp DhcpListener.cpp      \

LOCAL_MODULE:= nexus

LOCAL_C_INCLUDES := $(KERNEL_HEADERS) -I../../../frameworks/base/include/

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libsysutils libwpa_client

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:=          \
                  nexctl.c \

LOCAL_MODULE:= nexctl

LOCAL_C_INCLUDES := $(KERNEL_HEADERS)

LOCAL_CFLAGS := 

LOCAL_SHARED_LIBRARIES := libcutils

include $(BUILD_EXECUTABLE)

endif # ifeq ($(BUILD_NEXUS),true)
