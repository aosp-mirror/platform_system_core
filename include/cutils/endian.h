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

#ifndef __CUTILS_ENDIAN_H
#define __CUTILS_ENDIAN_H

#if defined(__linux__) && !defined(TEST_CUTILS_ENDIAN_H)
#include <endian.h>
#else

#if !defined(__BYTE_ORDER__)
/* gcc and clang predefine __BYTE_ORDER__, so this should never happen */
#error Compiler does not define __BYTE_ORDER__
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define htobe16(x)  (x)
#define htobe32(x)  (x)
#define htobe64(x)  (x)
#define htole16(x)  __builtin_bswap16(x)
#define htole32(x)  __builtin_bswap32(x)
#define htole64(x)  __builtin_bswap64(x)
#else
#define htobe16(x)  __builtin_bswap16(x)
#define htobe32(x)  __builtin_bswap32(x)
#define htobe64(x)  __builtin_bswap64(x)
#define htole16(x)  (x)
#define htole32(x)  (x)
#define htole64(x)  (x)
#endif /* __BYTE_ORDER__ */

#define be16toh(x)  htobe16(x)
#define le16toh(x)  htole16(x)
#define be32toh(x)  htobe32(x)
#define le32toh(x)  htole32(x)
#define be64toh(x)  htobe64(x)
#define le64toh(x)  htole64(x)

#endif /* defined(__linux__) */

#endif /* __CUTILS_ENDIAN_H */
