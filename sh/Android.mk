LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	alias.c \
	arith.c \
	arith_lex.c \
	builtins.c \
	cd.c \
	error.c \
	eval.c \
	exec.c \
	expand.c \
	input.c \
	jobs.c \
	main.c \
	memalloc.c \
	miscbltin.c \
	mystring.c \
	nodes.c \
	options.c \
	parser.c \
	redir.c \
	show.c \
	syntax.c \
	trap.c \
	output.c \
	var.c \
	bltin/echo.c \
	init.c

LOCAL_MODULE:= ash
LOCAL_MODULE_TAGS:= shell_ash

LOCAL_CFLAGS += -DSHELL -DWITH_LINENOISE

LOCAL_STATIC_LIBRARIES := liblinenoise

LOCAL_C_INCLUDES += system/core/liblinenoise

make_ash_files: PRIVATE_SRC_FILES := $(SRC_FILES)
make_ash_files: PRIVATE_CFLAGS := $(LOCAL_CFLAGS)
make_ash_files:
	p4 edit arith.c arith_lex.c arith.h builtins.h builtins.c 
	p4 edit init.c nodes.c nodes.h token.h 
	sh ./mktokens
	bison -o arith.c arith.y
	flex -o arith_lex.c arith_lex.l
	perl -ne 'print if ( /^\#\s*define\s+ARITH/ );' < arith.c > arith.h
	sh ./mkbuiltins shell.h builtins.def . -Wall -O2
	sh ./mknodes.sh nodetypes nodes.c.pat .
	sh ./mkinit.sh $(PRIVATE_SRC_FILES) 

include $(BUILD_EXECUTABLE)


# create /system/bin/sh symlink to $(TARGET_SHELL)
# not the optimal place for this, but a fitting one

OUTSYSTEMBINSH := $(TARGET_OUT)/bin/sh
LOCAL_MODULE := systembinsh
$(OUTSYSTEMBINSH): | $(TARGET_SHELL)
$(OUTSYSTEMBINSH): LOCAL_MODULE := $(LOCAL_MODULE)
$(OUTSYSTEMBINSH):
	@echo "Symlink: $@ -> $(TARGET_SHELL)"
	@rm -rf $@
	$(hide) ln -sf $(TARGET_SHELL) $@

ALL_DEFAULT_INSTALLED_MODULES += $(OUTSYSTEMBINSH)
ALL_MODULES.$(LOCAL_MODULE).INSTALLED += $(OUTSYSTEMBINSH)
