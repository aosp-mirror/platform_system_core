#
# Copyright (C) 2016 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# This makefile should be included by devices that use Trusty TEE
# to pull in the baseline set of Trusty specific modules.
#

# For gatekeeper, we include the generic -service and -impl to use legacy
# HAL loading of gatekeeper.trusty.

# Allow the KeyMint HAL service implementation to be selected at build time.  This needs to be
# done in sync with the TA implementation included in Trusty.  Possible values are:
#
# - Rust implementation:   export TRUSTY_KEYMINT_IMPL=rust
# - C++ implementation:    (any other value of TRUSTY_KEYMINT_IMPL)

ifeq ($(TRUSTY_KEYMINT_IMPL),rust)
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty
else
    # Default to the C++ implementation
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.trusty
endif

# TODO(b/306364873): move this to be flag-controlled?
ifeq ($(SECRETKEEPER_ENABLED),)
    LOCAL_SECRETKEEPER_PRODUCT_PACKAGE :=
else
    LOCAL_SECRETKEEPER_PRODUCT_PACKAGE := android.hardware.security.secretkeeper.trusty
endif

PRODUCT_PACKAGES += \
	$(LOCAL_KEYMINT_PRODUCT_PACKAGE) \
	$(LOCAL_SECRETKEEPER_PRODUCT_PACKAGE) \
	android.hardware.gatekeeper-service.trusty \
	trusty_apploader \

PRODUCT_PROPERTY_OVERRIDES += \
	ro.hardware.keystore_desede=true \
	ro.hardware.keystore=trusty \
	ro.hardware.gatekeeper=trusty

PRODUCT_COPY_FILES += \
	frameworks/native/data/etc/android.hardware.keystore.app_attest_key.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.keystore.app_attest_key.xml
