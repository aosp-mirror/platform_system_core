#####################################################################
# Builds linker config file, ld.config.txt, from the specified template
# under $(LOCAL_PATH)/etc/*.
#
# Inputs:
#   (expected to follow an include of $(BUILD_SYSTEM)/base_rules.mk)
#   ld_config_template: template linker config file to use,
#                       e.g. $(LOCAL_PATH)/etc/ld.config.txt
#   vndk_version: version of the VNDK library lists used to update the
#                 template linker config file, e.g. 28
#   lib_list_from_prebuilts: should be set to 'true' if the VNDK library
#                            lists should be read from /prebuilts/vndk/*
#   libz_is_llndk: should be set to 'true' if libz must be included in
#                  llndk and not in vndk-sp
# Outputs:
#   Builds and installs ld.config.$VER.txt or ld.config.vndk_lite.txt
#####################################################################

# Read inputs
ld_config_template := $(strip $(ld_config_template))
vndk_version := $(strip $(vndk_version))
lib_list_from_prebuilts := $(strip $(lib_list_from_prebuilts))
libz_is_llndk := $(strip $(libz_is_llndk))

intermediates_dir := $(call intermediates-dir-for,ETC,$(LOCAL_MODULE))
library_lists_dir := $(intermediates_dir)
ifeq ($(lib_list_from_prebuilts),true)
  library_lists_dir := prebuilts/vndk/v$(vndk_version)/$(TARGET_ARCH)/configs
endif

llndk_libraries_file := $(library_lists_dir)/llndk.libraries.$(vndk_version).txt
vndksp_libraries_file := $(library_lists_dir)/vndksp.libraries.$(vndk_version).txt
vndkcore_libraries_file := $(library_lists_dir)/vndkcore.libraries.txt
vndkprivate_libraries_file := $(library_lists_dir)/vndkprivate.libraries.txt

sanitizer_runtime_libraries := $(call normalize-path-list,$(addsuffix .so,\
  $(ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(UBSAN_RUNTIME_LIBRARY) \
  $(TSAN_RUNTIME_LIBRARY) \
  $(2ND_ADDRESS_SANITIZER_RUNTIME_LIBRARY) \
  $(2ND_UBSAN_RUNTIME_LIBRARY) \
  $(2ND_TSAN_RUNTIME_LIBRARY)))
# If BOARD_VNDK_VERSION is not defined, VNDK version suffix will not be used.
vndk_version_suffix := $(if $(vndk_version),-$(vndk_version))

ifneq ($(lib_list_from_prebuilts),true)
ifeq ($(libz_is_llndk),true)
  llndk_libraries_list := $(LLNDK_LIBRARIES) libz
  vndksp_libraries_list := $(filter-out libz,$(VNDK_SAMEPROCESS_LIBRARIES))
else
  llndk_libraries_list := $(LLNDK_LIBRARIES)
  vndksp_libraries_list := $(VNDK_SAMEPROCESS_LIBRARIES)
endif

# $(1): list of libraries
# $(2): output file to write the list of libraries to
define write-libs-to-file
$(2): PRIVATE_LIBRARIES := $(1)
$(2):
	echo -n > $$@ && $$(foreach lib,$$(PRIVATE_LIBRARIES),echo $$(lib).so >> $$@;)
endef
$(eval $(call write-libs-to-file,$(llndk_libraries_list),$(llndk_libraries_file)))
$(eval $(call write-libs-to-file,$(vndksp_libraries_list),$(vndksp_libraries_file)))
$(eval $(call write-libs-to-file,$(VNDK_CORE_LIBRARIES),$(vndkcore_libraries_file)))
$(eval $(call write-libs-to-file,$(VNDK_PRIVATE_LIBRARIES),$(vndkprivate_libraries_file)))
endif # ifneq ($(lib_list_from_prebuilts),true)

# Given a file with a list of libs, filter-out the VNDK private libraries
# and write resulting list to a new file in "a:b:c" format
#
# $(1): libs file from which to filter-out VNDK private libraries
# $(2): output file with the filtered list of lib names
$(LOCAL_BUILT_MODULE): private-filter-out-private-libs = \
  paste -sd ":" $(1) > $(2) && \
  cat $(PRIVATE_VNDK_PRIVATE_LIBRARIES_FILE) | xargs -n 1 -I privatelib bash -c "sed -i.bak 's/privatelib//' $(2)" && \
  sed -i.bak -e 's/::\+/:/g ; s/^:\+// ; s/:\+$$//' $(2) && \
  rm -f $(2).bak
$(LOCAL_BUILT_MODULE): PRIVATE_LLNDK_LIBRARIES_FILE := $(llndk_libraries_file)
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_SP_LIBRARIES_FILE := $(vndksp_libraries_file)
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_CORE_LIBRARIES_FILE := $(vndkcore_libraries_file)
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_PRIVATE_LIBRARIES_FILE := $(vndkprivate_libraries_file)
$(LOCAL_BUILT_MODULE): PRIVATE_SANITIZER_RUNTIME_LIBRARIES := $(sanitizer_runtime_libraries)
$(LOCAL_BUILT_MODULE): PRIVATE_VNDK_VERSION_SUFFIX := $(vndk_version_suffix)
$(LOCAL_BUILT_MODULE): PRIVATE_INTERMEDIATES_DIR := $(intermediates_dir)
deps := $(llndk_libraries_file) $(vndksp_libraries_file) $(vndkcore_libraries_file) \
  $(vndkprivate_libraries_file)

$(LOCAL_BUILT_MODULE): $(ld_config_template) $(deps)
	@echo "Generate: $< -> $@"
	@mkdir -p $(dir $@)
	$(call private-filter-out-private-libs,$(PRIVATE_LLNDK_LIBRARIES_FILE),$(PRIVATE_INTERMEDIATES_DIR)/llndk_filtered)
	$(hide) sed -e "s?%LLNDK_LIBRARIES%?$$(cat $(PRIVATE_INTERMEDIATES_DIR)/llndk_filtered)?g" $< >$@
	$(call private-filter-out-private-libs,$(PRIVATE_VNDK_SP_LIBRARIES_FILE),$(PRIVATE_INTERMEDIATES_DIR)/vndksp_filtered)
	$(hide) sed -i.bak -e "s?%VNDK_SAMEPROCESS_LIBRARIES%?$$(cat $(PRIVATE_INTERMEDIATES_DIR)/vndksp_filtered)?g" $@
	$(call private-filter-out-private-libs,$(PRIVATE_VNDK_CORE_LIBRARIES_FILE),$(PRIVATE_INTERMEDIATES_DIR)/vndkcore_filtered)
	$(hide) sed -i.bak -e "s?%VNDK_CORE_LIBRARIES%?$$(cat $(PRIVATE_INTERMEDIATES_DIR)/vndkcore_filtered)?g" $@

	$(hide) echo -n > $(PRIVATE_INTERMEDIATES_DIR)/private_llndk && \
	cat $(PRIVATE_VNDK_PRIVATE_LIBRARIES_FILE) | \
	xargs -n 1 -I privatelib bash -c "(grep privatelib $(PRIVATE_LLNDK_LIBRARIES_FILE) || true) >> $(PRIVATE_INTERMEDIATES_DIR)/private_llndk" && \
	paste -sd ":" $(PRIVATE_INTERMEDIATES_DIR)/private_llndk | \
	sed -i.bak -e "s?%PRIVATE_LLNDK_LIBRARIES%?$$(cat -)?g" $@

	$(hide) sed -i.bak -e 's?%SANITIZER_RUNTIME_LIBRARIES%?$(PRIVATE_SANITIZER_RUNTIME_LIBRARIES)?g' $@
	$(hide) sed -i.bak -e 's?%VNDK_VER%?$(PRIVATE_VNDK_VERSION_SUFFIX)?g' $@
	$(hide) sed -i.bak -e 's?%PRODUCT%?$(TARGET_COPY_OUT_PRODUCT)?g' $@
	$(hide) sed -i.bak -e 's?%PRODUCT_SERVICES%?$(TARGET_COPY_OUT_PRODUCT_SERVICES)?g' $@
	$(hide) rm -f $@.bak

ld_config_template :=
vndk_version :=
lib_list_from_prebuilts :=
libz_is_llndk :=
intermediates_dir :=
library_lists_dir :=
llndk_libraries_file :=
vndksp_libraries_file :=
vndkcore_libraries_file :=
vndkprivate_libraries_file :=
deps :=
sanitizer_runtime_libraries :=
vndk_version_suffix :=
llndk_libraries_list :=
vndksp_libraries_list :=
write-libs-to-file :=
