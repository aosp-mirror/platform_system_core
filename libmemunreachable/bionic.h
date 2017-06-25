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

#ifndef LIBMEMUNREACHABLE_BIONIC_H_
#define LIBMEMUNREACHABLE_BIONIC_H_

#include <stdint.h>
#include <stdlib.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/* Exported from bionic */
extern void malloc_disable();
extern void malloc_enable();
extern int malloc_iterate(uintptr_t base, size_t size,
                          void (*callback)(uintptr_t base, size_t size, void* arg), void* arg);
extern ssize_t malloc_backtrace(void* pointer, uintptr_t* frames, size_t frame_count);

__END_DECLS

#endif  // LIBMEMUNREACHABLE_BIONIC_H_
