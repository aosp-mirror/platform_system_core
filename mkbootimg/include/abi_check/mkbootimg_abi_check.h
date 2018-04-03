/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <bootimg/bootimg.h>

// This header has been created for the following reaons:
//    1) In order for a change in a user defined type to be classified as API /
//       ABI breaking, it needs to be referenced by an 'exported interface'
//       (in this case the function mkbootimg_dummy).
//    2) Since 'mkbootimg_dummy' needs to be exported, we need to have it
//       exposed through a public header.
//    3) It is desirable not to pollute bootimg.h with interfaces which are not
//       'used' in reality by on device binaries. Furthermore, bootimg.h might
//       be exported by a library in the future, so we must avoid polluting it.
void mkbootimg_dummy(boot_img_hdr*);
