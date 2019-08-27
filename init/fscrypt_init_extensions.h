/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef _FSCRYPT_INIT_EXTENSIONS_H_
#define _FSCRYPT_INIT_EXTENSIONS_H_

#include <sys/cdefs.h>
#include <stdbool.h>
#include <cutils/multiuser.h>

__BEGIN_DECLS

// These functions assume they are being called from init
// They will not operate properly outside of init
int fscrypt_install_keyring();
int fscrypt_set_directory_policy(const char* path);

__END_DECLS

#endif // _FSCRYPT_INIT_EXTENSIONS_H_
