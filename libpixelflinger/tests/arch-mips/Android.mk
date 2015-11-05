ifeq ($(TARGET_ARCH),mips)
include $(all-subdir-makefiles)
endif
ifeq ($(TARGET_ARCH),mipsel)
include $(all-subdir-makefiles)
endif
