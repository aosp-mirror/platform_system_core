# Create the /system/bin/sh symlink to $(TARGET_SHELL).
# Currently, Android's shell is external/mksh.

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
