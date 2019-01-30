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

#ifndef __ANDROID_PSI_H__
#define __ANDROID_PSI_H__

#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

enum psi_stall_type {
    PSI_SOME,
    PSI_FULL,
    PSI_TYPE_COUNT
};

/*
 * Initializes psi monitor.
 * stall_type, threshold_us and window_us are monitor parameters
 * When successful, the function returns file descriptor that can
 * be used with poll/epoll syscalls to wait for EPOLLPRI events.
 * When unsuccessful, the function returns -1 and errno is set
 * appropriately.
 */
int init_psi_monitor(enum psi_stall_type stall_type,
        int threshold_us, int window_us);

/*
 * Registers psi monitor file descriptor fd on the epoll instance
 * referred to by the file descriptor epollfd.
 * data parameter will be associated with event's epoll_data.ptr
 * member.
 */
int register_psi_monitor(int epollfd, int fd, void* data);

/*
 * Unregisters psi monitor file descriptor fd from the epoll instance
 * referred to by the file descriptor epollfd.
 */
int unregister_psi_monitor(int epollfd, int fd);

/*
 * Destroys psi monitor.
 * fd is the file descriptor returned by psi monitor initialization
 * routine.
 * Note that if user process exits without calling this routine
 * kernel will destroy the monitor as its lifetime is linked to
 * the file descriptor.
 */
void destroy_psi_monitor(int fd);

__END_DECLS

#endif  // __ANDROID_PSI_H__
