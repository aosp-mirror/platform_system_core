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

PRODUCT_PACKAGES += \
	android.hardware.security.keymint-service.trusty \
	android.hardware.gatekeeper@1.0-service.trusty \
	trusty_apploader \
	RemoteProvisioner

PRODUCT_PROPERTY_OVERRIDES += \
	ro.hardware.keystore_desede=true \
	ro.hardware.keystore=trusty \
	ro.hardware.gatekeeper=trusty

PRODUCT_COPY_FILES += \
	frameworks/native/data/etc/android.hardware.keystore.app_attest_key.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.keystore.app_attest_key.xml
