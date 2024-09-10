#
# Copyright (C) 2024 The Android Open-Source Project
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
# to pull in a set of Trusty KeyMint specific modules.
#
# Allow KeyMint HAL service implementation selection at build time. This must be
# synchronized with the TA implementation included in Trusty. Possible values:
#
# - Rust implementation for Trusty VM (requires Trusty VM support):
#   export TRUSTY_KEYMINT_IMPL=rust
#   export TRUSTY_SYSTEM_VM=nonsecure
# - Rust implementation for Trusty TEE (no Trusty VM support):
#   export TRUSTY_KEYMINT_IMPL=rust
# - C++ implementation (default): (any other value or unset TRUSTY_KEYMINT_IMPL)

ifeq ($(TRUSTY_KEYMINT_IMPL),rust)
    ifeq ($(TRUSTY_SYSTEM_VM),nonsecure)
        LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty.system.nonsecure
    else
        LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.rust.trusty
    endif
else
    # Default to the C++ implementation
    LOCAL_KEYMINT_PRODUCT_PACKAGE := android.hardware.security.keymint-service.trusty
endif

PRODUCT_PACKAGES += \
    $(LOCAL_KEYMINT_PRODUCT_PACKAGE) \
