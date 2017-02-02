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

#ifndef __ANDROID_DLEXT_NAMESPACES_H__
#define __ANDROID_DLEXT_NAMESPACES_H__

#include <android/dlext.h>

__BEGIN_DECLS

/*
 * Initializes public and anonymous namespaces. The public_ns_sonames is the list of sonames
 * to be included into public namespace separated by colon. Example: "libc.so:libm.so:libdl.so".
 * The libraries in this list should be loaded prior to this call.
 *
 * The anon_ns_library_path is the search path for anonymous namespace. The anonymous namespace
 * is used in the case when linker cannot identify the caller of dlopen/dlsym. This happens
 * for the code not loaded by dynamic linker; for example calls from the mono-compiled code.
 */
extern bool android_init_namespaces(const char* public_ns_sonames,
                                    const char* anon_ns_library_path);


enum {
  /* A regular namespace is the namespace with a custom search path that does
   * not impose any restrictions on the location of native libraries.
   */
  ANDROID_NAMESPACE_TYPE_REGULAR = 0,

  /* An isolated namespace requires all the libraries to be on the search path
   * or under permitted_when_isolated_path. The search path is the union of
   * ld_library_path and default_library_path.
   */
  ANDROID_NAMESPACE_TYPE_ISOLATED = 1,

  /* The shared namespace clones the list of libraries of the caller namespace upon creation
   * which means that they are shared between namespaces - the caller namespace and the new one
   * will use the same copy of a library if it was loaded prior to android_create_namespace call.
   *
   * Note that libraries loaded after the namespace is created will not be shared.
   *
   * Shared namespaces can be isolated or regular. Note that they do not inherit the search path nor
   * permitted_path from the caller's namespace.
   */
  ANDROID_NAMESPACE_TYPE_SHARED = 2,
  ANDROID_NAMESPACE_TYPE_SHARED_ISOLATED = ANDROID_NAMESPACE_TYPE_SHARED |
                                           ANDROID_NAMESPACE_TYPE_ISOLATED,
};

/*
 * Creates new linker namespace.
 * ld_library_path and default_library_path represent the search path
 * for the libraries in the namespace.
 *
 * The libraries in the namespace are searched by folowing order:
 * 1. ld_library_path (Think of this as namespace-local LD_LIBRARY_PATH)
 * 2. In directories specified by DT_RUNPATH of the "needed by" binary.
 * 3. deault_library_path (This of this as namespace-local default library path)
 *
 * When type is ANDROID_NAMESPACE_TYPE_ISOLATED the resulting namespace requires all of
 * the libraries to be on the search path or under the permitted_when_isolated_path;
 * the search_path is ld_library_path:default_library_path. Note that the
 * permitted_when_isolated_path path is not part of the search_path and
 * does not affect the search order. It is a way to allow loading libraries from specific
 * locations when using absolute path.
 * If a library or any of its dependencies are outside of the permitted_when_isolated_path
 * and search_path, and it is not part of the public namespace dlopen will fail.
 */
extern struct android_namespace_t* android_create_namespace(const char* name,
                                                            const char* ld_library_path,
                                                            const char* default_library_path,
                                                            uint64_t type,
                                                            const char* permitted_when_isolated_path,
                                                            android_namespace_t* parent);

/*
 * Get the default library search path.
 * The path will be copied into buffer, which must have space for at least
 * buffer_size chars. Elements are separated with ':', and the path will always
 * be null-terminated.
 *
 * If buffer_size is too small to hold the entire default search path and the
 * null terminator, this function will abort. There is currently no way to find
 * out what the required buffer size is. At the time of this writing, PATH_MAX
 * is sufficient and used by all callers of this function.
 */
extern void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size);

__END_DECLS

#endif /* __ANDROID_DLEXT_NAMESPACES_H__ */
