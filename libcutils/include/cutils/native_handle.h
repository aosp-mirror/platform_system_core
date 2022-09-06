/*
 * Copyright (C) 2009 The Android Open Source Project
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

#ifndef NATIVE_HANDLE_H_
#define NATIVE_HANDLE_H_

#include <stdalign.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NATIVE_HANDLE_MAX_FDS 1024
#define NATIVE_HANDLE_MAX_INTS 1024

/* Declare a char array for use with native_handle_init */
#define NATIVE_HANDLE_DECLARE_STORAGE(name, maxFds, maxInts) \
    alignas(native_handle_t) char (name)[                            \
      sizeof(native_handle_t) + sizeof(int) * ((maxFds) + (maxInts))]

typedef struct native_handle
{
    int version;        /* sizeof(native_handle_t) */
    int numFds;         /* number of file-descriptors at &data[0] */
    int numInts;        /* number of ints at &data[numFds] */
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wzero-length-array"
#endif
    int data[0];        /* numFds + numInts ints */
#if defined(__clang__)
#pragma clang diagnostic pop
#endif
} native_handle_t;

typedef const native_handle_t* buffer_handle_t;

/*
 * Closes the file descriptors contained in this native_handle_t, which may
 * either be untagged or tagged for ownership by this native_handle_t via
 * native_handle_set_tag(). Mixing untagged and tagged fds in the same
 * native_handle_t is not permitted and triggers an fdsan exception, but
 * native_handle_set_fdsan_tag() can be used to bring consistency if this is
 * intentional.
 *
 * If it's known that fds are tagged, prefer native_handle_close_with_tag() for
 * better safety.
 *
 * return 0 on success, or a negative error code on failure
 */
int native_handle_close(const native_handle_t* h);

/*
 * Equivalent to native_handle_close(), but throws an fdsan exception if the fds
 * are untagged. Use if it's known that the fds in this native_handle_t were
 * previously tagged via native_handle_set_tag().
 */
int native_handle_close_with_tag(const native_handle_t* h);

/*
 * Initializes a native_handle_t from storage.  storage must be declared with
 * NATIVE_HANDLE_DECLARE_STORAGE.  numFds and numInts must not respectively
 * exceed maxFds and maxInts used to declare the storage.
 */
native_handle_t* native_handle_init(char* storage, int numFds, int numInts);

/*
 * Creates a native_handle_t and initializes it. Must be destroyed with
 * native_handle_delete(). Note that numFds must be <= NATIVE_HANDLE_MAX_FDS,
 * numInts must be <= NATIVE_HANDLE_MAX_INTS, and both must be >= 0.
 */
native_handle_t* native_handle_create(int numFds, int numInts);

/*
 * Updates the fdsan tag for any file descriptors contained in the supplied
 * handle to indicate that they are owned by this handle and should only be
 * closed via native_handle_close()/native_handle_close_with_tag(). Each fd in
 * the handle must have a tag of either 0 (unset) or the tag associated with
 * this handle, otherwise an fdsan exception will be triggered.
 */
void native_handle_set_fdsan_tag(const native_handle_t* handle);

/*
 * Clears the fdsan tag for any file descriptors contained in the supplied
 * native_handle_t. Use if this native_handle_t is giving up ownership of its
 * fds, but the fdsan tags were previously set. Each fd in the handle must have
 * a tag of either 0 (unset) or the tag associated with this handle, otherwise
 * an fdsan exception will be triggered.
 */
void native_handle_unset_fdsan_tag(const native_handle_t* handle);

/*
 * Creates a native_handle_t and initializes it from another native_handle_t.
 * Must be destroyed with native_handle_delete().
 */
native_handle_t* native_handle_clone(const native_handle_t* handle);

/*
 * Frees a native_handle_t allocated with native_handle_create().
 * This ONLY frees the memory allocated for the native_handle_t, but doesn't
 * close the file descriptors; which can be achieved with native_handle_close().
 *
 * return 0 on success, or a negative error code on failure
 */
int native_handle_delete(native_handle_t* h);


#ifdef __cplusplus
}
#endif

#endif /* NATIVE_HANDLE_H_ */
