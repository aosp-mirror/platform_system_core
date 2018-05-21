LOCAL_PATH := $(call my-dir)

# Archive adb, adb.exe.
$(call dist-for-goals,dist_files sdk win_sdk,$(HOST_OUT_EXECUTABLES)/adb)

ifdef HOST_CROSS_OS
$(call dist-for-goals,dist_files sdk win_sdk,$(ALL_MODULES.host_cross_adb.BUILT))
endif
