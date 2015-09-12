/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <binderwrapper/binder_test_base.h>

#include <binderwrapper/binder_wrapper.h>
#include <binderwrapper/stub_binder_wrapper.h>

namespace android {

BinderTestBase::BinderTestBase() : binder_wrapper_(new StubBinderWrapper()) {
  // Pass ownership.
  BinderWrapper::InitForTesting(binder_wrapper_);
}

BinderTestBase::~BinderTestBase() {
  BinderWrapper::Destroy();
}

}  // namespace android
