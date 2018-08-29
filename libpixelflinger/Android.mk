LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# C/C++ and ARMv5 objects
#

include $(CLEAR_VARS)
PIXELFLINGER_SRC_FILES:= \
	codeflinger/ARMAssemblerInterface.cpp \
	codeflinger/ARMAssemblerProxy.cpp \
	codeflinger/CodeCache.cpp \
	codeflinger/GGLAssembler.cpp \
	codeflinger/load_store.cpp \
	codeflinger/blending.cpp \
	codeflinger/texturing.cpp \
	fixed.cpp.arm \
	picker.cpp.arm \
	pixelflinger.cpp.arm \
	trap.cpp.arm \
	scanline.cpp.arm \
	format.cpp \
	clear.cpp \
	raster.cpp \
	buffer.cpp

PIXELFLINGER_CFLAGS := -fstrict-aliasing -fomit-frame-pointer
PIXELFLINGER_CFLAGS += -Wall -Werror
PIXELFLINGER_CFLAGS += -Wno-unused-function

PIXELFLINGER_SRC_FILES_arm := \
	codeflinger/ARMAssembler.cpp \
	codeflinger/disassem.c \
	col32cb16blend.S \
	t32cb16blend.S \

ifeq ($(ARCH_ARM_HAVE_NEON),true)
PIXELFLINGER_SRC_FILES_arm += col32cb16blend_neon.S
PIXELFLINGER_CFLAGS_arm += -D__ARM_HAVE_NEON
endif

PIXELFLINGER_SRC_FILES_arm64 := \
	codeflinger/Arm64Assembler.cpp \
	codeflinger/Arm64Disassembler.cpp \
	arch-arm64/col32cb16blend.S \
	arch-arm64/t32cb16blend.S \

ifndef ARCH_MIPS_REV6
PIXELFLINGER_SRC_FILES_mips := \
	codeflinger/MIPSAssembler.cpp \
	codeflinger/mips_disassem.c \
	arch-mips/t32cb16blend.S \

endif

PIXELFLINGER_SRC_FILES_mips64 := \
        codeflinger/MIPSAssembler.cpp \
	codeflinger/MIPS64Assembler.cpp \
	codeflinger/mips64_disassem.c \
	arch-mips64/col32cb16blend.S \
	arch-mips64/t32cb16blend.S \

#
# Shared library
#

LOCAL_MODULE:= libpixelflinger
LOCAL_SRC_FILES := $(PIXELFLINGER_SRC_FILES)
LOCAL_SRC_FILES_arm := $(PIXELFLINGER_SRC_FILES_arm)
LOCAL_SRC_FILES_arm64 := $(PIXELFLINGER_SRC_FILES_arm64)
LOCAL_SRC_FILES_mips := $(PIXELFLINGER_SRC_FILES_mips)
LOCAL_SRC_FILES_mips64 := $(PIXELFLINGER_SRC_FILES_mips64)
LOCAL_CFLAGS := $(PIXELFLINGER_CFLAGS)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_EXPORT_C_INCLUDE_DIRS)
LOCAL_SHARED_LIBRARIES := libcutils liblog libutils

include $(BUILD_SHARED_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
