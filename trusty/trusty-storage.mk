#
# Copyright (C) 2015 The Android Open-Source Project
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
# Trusty TEE packages
#

# below statement adds the singleton storage daemon in vendor,
# storageproxyd vendor interacts with the Secure Storage TA in the
# Trustzone Trusty TEE
PRODUCT_PACKAGES += \
	storageproxyd \

#
# Trusty VM packages
#
ifeq ($(TRUSTY_SYSTEM_VM),enabled_with_placeholder_trusted_hal)

# with placeholder Trusted HALs, the Trusty VMs are standalone (i.e. they don't access
# remote Trusted HAL services) and thus require their own secure storage.
# (one secure storage emulation for each Trusty VM - security VM, test VM and WV VM)
# in secure mode, the secure storage is the services by Trusty in Trustzone
# and requires a single storageproxyd in vendor.
PRODUCT_PACKAGES += \
	storageproxyd.system \
	rpmb_dev.test.system \
	rpmb_dev.system \
	# rpmb_dev.wv.system \

endif
