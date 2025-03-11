/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <cutils/ashmem.h>

/*
 * Implementation of the user-space ashmem API for devices, which have our
 * ashmem-enabled kernel. See ashmem-sim.c for the "fake" tmp-based version,
 * used by the simulator.
 */
#define LOG_TAG "ashmem"

#include <errno.h>
#include <fcntl.h>
#include <linux/ashmem.h>
#include <linux/memfd.h>
#include <log/log.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "ashmem-internal.h"

/* ashmem identity */
static dev_t __ashmem_rdev;
/*
 * If we trigger a signal handler in the middle of locked activity and the
 * signal handler calls ashmem, we could get into a deadlock state.
 */
static pthread_mutex_t __ashmem_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * has_memfd_support() determines if the device can use memfd. memfd support
 * has been there for long time, but certain things in it may be missing.  We
 * check for needed support in it. Also we check if the VNDK version of
 * libcutils being used is new enough, if its not, then we cannot use memfd
 * since the older copies may be using ashmem so we just use ashmem. Once all
 * Android devices that are getting updates are new enough (ex, they were
 * originally shipped with Android release > P), then we can just use memfd and
 * delete all ashmem code from libcutils (while preserving the interface).
 *
 * NOTE:
 * The sys.use_memfd property is set by default to false in Android
 * to temporarily disable memfd, till vendor and apps are ready for it.
 * The main issue: either apps or vendor processes can directly make ashmem
 * IOCTLs on FDs they receive by assuming they are ashmem, without going
 * through libcutils. Such fds could have very well be originally created with
 * libcutils hence they could be memfd. Thus the IOCTLs will break.
 *
 * Set default value of sys.use_memfd property to true once the issue is
 * resolved, so that the code can then self-detect if kernel support is present
 * on the device. The property can also set to true from adb shell, for
 * debugging.
 */

/* set to true for verbose logging and other debug  */
static bool debug_log = false;

/* Determine if vendor processes would be ok with memfd in the system:
 *
 * Previously this function checked if memfd is supported by checking if
 * vendor VNDK version is greater than Q. As we can assume all treblelized
 * device using this code is up to date enough to use memfd, memfd is allowed
 * if the device is treblelized.
 */
static bool check_vendor_memfd_allowed() {
    static bool is_treblelized = android::base::GetBoolProperty("ro.treble.enabled", false);

    return is_treblelized;
}

/* Determine if memfd can be supported. This is just one-time hardwork
 * which will be cached by the caller.
 */
static bool __has_memfd_support() {
    if (check_vendor_memfd_allowed() == false) {
        return false;
    }

    /* Used to turn on/off the detection at runtime, in the future this
     * property will be removed once we switch everything over to ashmem.
     * Currently it is used only for debugging to switch the system over.
     */
    if (!android::base::GetBoolProperty("sys.use_memfd", false)) {
        if (debug_log) {
            ALOGD("sys.use_memfd=false so memfd disabled");
        }
        return false;
    }

    // Check if kernel support exists, otherwise fall back to ashmem.
    // This code needs to build on old API levels, so we can't use the libc
    // wrapper.
    android::base::unique_fd fd(
            syscall(__NR_memfd_create, "test_android_memfd", MFD_CLOEXEC | MFD_ALLOW_SEALING));
    if (fd == -1) {
        ALOGE("memfd_create failed: %m, no memfd support");
        return false;
    }

    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == -1) {
        ALOGE("fcntl(F_ADD_SEALS) failed: %m, no memfd support");
        return false;
    }

    size_t buf_size = getpagesize();
    if (ftruncate(fd, buf_size) == -1) {
        ALOGE("ftruncate(%zd) failed to set memfd buffer size: %m, no memfd support", buf_size);
        return false;
    }

    /*
     * Ensure that the kernel supports ashmem ioctl commands on memfds. If not,
     * fall back to using ashmem.
     */
    int ashmem_size = TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, 0));
    if (ashmem_size != static_cast<int>(buf_size)) {
        ALOGE("ioctl(ASHMEM_GET_SIZE): %d != buf_size: %zd , no ashmem-memfd compat support",
              ashmem_size, buf_size);
        return false;
    }

    if (debug_log) {
        ALOGD("memfd: device has memfd support, using it");
    }
    return true;
}

bool has_memfd_support() {
    static bool memfd_supported = __has_memfd_support();
    return memfd_supported;
}

static std::string get_ashmem_device_path() {
    static const std::string boot_id_path = "/proc/sys/kernel/random/boot_id";
    std::string boot_id;
    if (!android::base::ReadFileToString(boot_id_path, &boot_id)) {
        ALOGE("Failed to read %s: %m", boot_id_path.c_str());
        return "";
    }
    boot_id = android::base::Trim(boot_id);

    return "/dev/ashmem" + boot_id;
}

/* logistics of getting file descriptor for ashmem */
static int __ashmem_open_locked() {
    static const std::string ashmem_device_path = get_ashmem_device_path();

    if (ashmem_device_path.empty()) {
        return -1;
    }

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(ashmem_device_path.c_str(), O_RDWR | O_CLOEXEC)));
    if (!fd.ok()) {
        ALOGE("Unable to open ashmem device: %m");
        return -1;
    }

    struct stat st;
    if (TEMP_FAILURE_RETRY(fstat(fd, &st)) == -1) {
        return -1;
    }
    if (!S_ISCHR(st.st_mode) || !st.st_rdev) {
        errno = ENOTTY;
        return -1;
    }

    __ashmem_rdev = st.st_rdev;
    return fd.release();
}

static int __ashmem_open() {
    pthread_mutex_lock(&__ashmem_lock);
    int fd = __ashmem_open_locked();
    pthread_mutex_unlock(&__ashmem_lock);
    return fd;
}

/* Make sure file descriptor references ashmem, negative number means false */
static int __ashmem_is_ashmem(int fd, bool fatal) {
    struct stat st;
    if (fstat(fd, &st) < 0) {
        return -1;
    }

    dev_t rdev = 0; /* Too much complexity to sniff __ashmem_rdev */
    if (S_ISCHR(st.st_mode) && st.st_rdev) {
        pthread_mutex_lock(&__ashmem_lock);
        rdev = __ashmem_rdev;
        if (rdev) {
            pthread_mutex_unlock(&__ashmem_lock);
        } else {
            int fd = __ashmem_open_locked();
            if (fd < 0) {
                pthread_mutex_unlock(&__ashmem_lock);
                return -1;
            }
            rdev = __ashmem_rdev;
            pthread_mutex_unlock(&__ashmem_lock);

            close(fd);
        }

        if (st.st_rdev == rdev) {
            return 0;
        }
    }

    if (fatal) {
        if (rdev) {
            LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o %d:%d",
              fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
              S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP,
              major(rdev), minor(rdev));
        } else {
            LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o",
              fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
              S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP);
        }
        /* NOTREACHED */
    }

    errno = ENOTTY;
    return -1;
}

static int __ashmem_check_failure(int fd, int result) {
    if (result == -1 && errno == ENOTTY) __ashmem_is_ashmem(fd, true);
    return result;
}

static bool is_ashmem_fd(int fd) {
    static bool fd_check_error_once = false;

    if (__ashmem_is_ashmem(fd, false) == 0) {
        if (!fd_check_error_once) {
            ALOGE("memfd: memfd expected but ashmem fd used - please use libcutils");
            fd_check_error_once = true;
        }

        return true;
    }

    return false;
}

static bool is_memfd_fd(int fd) {
    return has_memfd_support() && !is_ashmem_fd(fd);
}

int ashmem_valid(int fd) {
    if (is_memfd_fd(fd)) {
        return 1;
    }

    return __ashmem_is_ashmem(fd, false) >= 0;
}

static int memfd_create_region(const char* name, size_t size) {
    // This code needs to build on old API levels, so we can't use the libc
    // wrapper.
    android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING));

    if (fd == -1) {
        ALOGE("memfd_create(%s, %zd) failed: %m", name, size);
        return -1;
    }

    if (ftruncate(fd, size) == -1) {
        ALOGE("ftruncate(%s, %zd) failed for memfd creation: %m", name, size);
        return -1;
    }

    // forbid size changes to match ashmem behaviour
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) == -1) {
        ALOGE("memfd_create(%s, %zd) F_ADD_SEALS failed: %m", name, size);
        return -1;
    }

    if (debug_log) {
        ALOGE("memfd_create(%s, %zd) success. fd=%d", name, size, fd.get());
    }
    return fd.release();
}

/*
 * ashmem_create_region - creates a new ashmem region and returns the file
 * descriptor, or <0 on error
 *
 * `name' is an optional label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
int ashmem_create_region(const char* name, size_t size) {
    if (name == NULL) name = "none";

    if (has_memfd_support()) {
        return memfd_create_region(name, size);
    }

    android::base::unique_fd fd(__ashmem_open());
    if (!fd.ok() ||
        TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, name) < 0) ||
        TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size) < 0)) {
        return -1;
    }
    return fd.release();
}

static int memfd_set_prot_region(int fd, int prot) {
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals == -1) {
        ALOGE("memfd_set_prot_region(%d, %d): F_GET_SEALS failed: %m", fd, prot);
        return -1;
    }

    if (prot & PROT_WRITE) {
        /* Now we want the buffer to be read-write, let's check if the buffer
         * has been previously marked as read-only before, if so return error
         */
        if (seals & F_SEAL_FUTURE_WRITE) {
            ALOGE("memfd_set_prot_region(%d, %d): region is write protected", fd, prot);
            errno = EINVAL;  // inline with ashmem error code, if already in
                             // read-only mode
            return -1;
        }
        return 0;
    }

    /* We would only allow read-only for any future file operations */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == -1) {
        ALOGE("memfd_set_prot_region(%d, %d): F_SEAL_FUTURE_WRITE seal failed: %m", fd, prot);
        return -1;
    }

    return 0;
}

int ashmem_set_prot_region(int fd, int prot) {
    if (is_memfd_fd(fd)) {
        return memfd_set_prot_region(fd, prot);
    }

    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot)));
}

static int do_pin(int op, int fd, size_t offset, size_t length) {
    static bool already_warned_about_pin_deprecation = false;
    if (!already_warned_about_pin_deprecation || debug_log) {
        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.");
        already_warned_about_pin_deprecation = true;
    }

    if (is_memfd_fd(fd)) {
        return 0;
    }

    // TODO: should LP64 reject too-large offset/len?
    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(length) };
    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, op, &pin)));
}

int ashmem_pin_region(int fd, size_t offset, size_t length) {
    return do_pin(ASHMEM_PIN, fd, offset, length);
}

int ashmem_unpin_region(int fd, size_t offset, size_t length) {
    return do_pin(ASHMEM_UNPIN, fd, offset, length);
}

int ashmem_get_size_region(int fd) {
    if (is_memfd_fd(fd)) {
        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            ALOGE("ashmem_get_size_region(%d): fstat failed: %m", fd);
            return -1;
        }
        return sb.st_size;
    }

    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL)));
}
