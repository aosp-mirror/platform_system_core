BUILD_NEXUS := false
ifeq ($(BUILD_NEXUS),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES:=                                      \
                  main.cpp                             \
                  NexusCommand.cpp                     \
                  CommandListener.cpp                  \
                  Property.cpp                         \
                  PropertyManager.cpp                  \
                  InterfaceConfig.cpp                  \
                  NetworkManager.cpp                   \
                  Controller.cpp                       \
                  WifiController.cpp                   \
                  TiwlanWifiController.cpp             \
                  TiwlanEventListener.cpp              \
                  WifiNetwork.cpp                      \
                  WifiStatusPoller.cpp                 \
                  ScanResult.cpp                       \
                  Supplicant.cpp                       \
                  SupplicantEvent.cpp                  \
                  SupplicantListener.cpp               \
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
                  OpenVpnController.cpp                \
                  VpnController.cpp                    \
                  LoopController.cpp                   \
                  DhcpClient.cpp DhcpListener.cpp      \
                  DhcpState.cpp DhcpEvent.cpp          \

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
