// Copyright (C) 2016 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "capabilities.h"

#include <sys/prctl.h>

#include <map>
#include <memory>

#include <android-base/logging.h>
#include <android-base/macros.h>

#define CAP_MAP_ENTRY(cap) { #cap, CAP_##cap }

namespace android {
namespace init {

static const std::map<std::string, int> cap_map = {
        CAP_MAP_ENTRY(CHOWN),
        CAP_MAP_ENTRY(DAC_OVERRIDE),
        CAP_MAP_ENTRY(DAC_READ_SEARCH),
        CAP_MAP_ENTRY(FOWNER),
        CAP_MAP_ENTRY(FSETID),
        CAP_MAP_ENTRY(KILL),
        CAP_MAP_ENTRY(SETGID),
        CAP_MAP_ENTRY(SETUID),
        CAP_MAP_ENTRY(SETPCAP),
        CAP_MAP_ENTRY(LINUX_IMMUTABLE),
        CAP_MAP_ENTRY(NET_BIND_SERVICE),
        CAP_MAP_ENTRY(NET_BROADCAST),
        CAP_MAP_ENTRY(NET_ADMIN),
        CAP_MAP_ENTRY(NET_RAW),
        CAP_MAP_ENTRY(IPC_LOCK),
        CAP_MAP_ENTRY(IPC_OWNER),
        CAP_MAP_ENTRY(SYS_MODULE),
        CAP_MAP_ENTRY(SYS_RAWIO),
        CAP_MAP_ENTRY(SYS_CHROOT),
        CAP_MAP_ENTRY(SYS_PTRACE),
        CAP_MAP_ENTRY(SYS_PACCT),
        CAP_MAP_ENTRY(SYS_ADMIN),
        CAP_MAP_ENTRY(SYS_BOOT),
        CAP_MAP_ENTRY(SYS_NICE),
        CAP_MAP_ENTRY(SYS_RESOURCE),
        CAP_MAP_ENTRY(SYS_TIME),
        CAP_MAP_ENTRY(SYS_TTY_CONFIG),
        CAP_MAP_ENTRY(MKNOD),
        CAP_MAP_ENTRY(LEASE),
        CAP_MAP_ENTRY(AUDIT_WRITE),
        CAP_MAP_ENTRY(AUDIT_CONTROL),
        CAP_MAP_ENTRY(SETFCAP),
        CAP_MAP_ENTRY(MAC_OVERRIDE),
        CAP_MAP_ENTRY(MAC_ADMIN),
        CAP_MAP_ENTRY(SYSLOG),
        CAP_MAP_ENTRY(WAKE_ALARM),
        CAP_MAP_ENTRY(BLOCK_SUSPEND),
        CAP_MAP_ENTRY(AUDIT_READ),
        CAP_MAP_ENTRY(PERFMON),
        CAP_MAP_ENTRY(BPF),
        CAP_MAP_ENTRY(CHECKPOINT_RESTORE),
};

static_assert(CAP_LAST_CAP == CAP_CHECKPOINT_RESTORE, "CAP_LAST_CAP is not CAP_CHECKPOINT_RESTORE");

static bool ComputeCapAmbientSupported() {
#if defined(__ANDROID__)
    return prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) >= 0;
#else
    return true;
#endif
}

static unsigned int ComputeLastValidCap() {
#if defined(__ANDROID__)
    // Android does not support kernels < 3.8. 'CAP_WAKE_ALARM' has been present since 3.0, see
    // http://lxr.free-electrons.com/source/include/linux/capability.h?v=3.0#L360.
    unsigned int last_valid_cap = CAP_WAKE_ALARM;
    for (; prctl(PR_CAPBSET_READ, last_valid_cap, 0, 0, 0) >= 0; ++last_valid_cap);

    // |last_valid_cap| will be the first failing value.
    return last_valid_cap - 1;
#else
    return CAP_LAST_CAP;
#endif
}

static bool DropBoundingSet(const CapSet& to_keep) {
    unsigned int last_valid_cap = GetLastValidCap();
    // When dropping the bounding set, attempt to drop capabilities reported at
    // run-time, not at compile-time.
    // If the run-time kernel is older than the compile-time headers, this
    // avoids dropping an invalid capability. If the run-time kernel is newer
    // than the headers, this guarantees all capabilities (even those unknown at
    // compile time) will be dropped.
    for (size_t cap = 0; cap <= last_valid_cap; ++cap) {
        if (cap < to_keep.size() && to_keep.test(cap)) {
            // No need to drop this capability.
            continue;
        }
        if (cap_drop_bound(cap) == -1) {
            PLOG(ERROR) << "cap_drop_bound(" << cap << ") failed";
            return false;
        }
    }
    return true;
}

static bool SetProcCaps(const CapSet& to_keep, bool add_setpcap) {
    ScopedCaps caps(cap_init());

    cap_clear(caps.get());
    cap_value_t value[1];
    for (size_t cap = 0; cap < to_keep.size(); ++cap) {
        if (to_keep.test(cap)) {
            value[0] = cap;
            if (cap_set_flag(caps.get(), CAP_INHERITABLE, arraysize(value), value, CAP_SET) != 0 ||
                cap_set_flag(caps.get(), CAP_PERMITTED, arraysize(value), value, CAP_SET) != 0) {
                PLOG(ERROR) << "cap_set_flag(INHERITABLE|PERMITTED, " << cap << ") failed";
                return false;
            }
        }
    }

    if (add_setpcap) {
        value[0] = CAP_SETPCAP;
        if (cap_set_flag(caps.get(), CAP_PERMITTED, arraysize(value), value, CAP_SET) != 0 ||
            cap_set_flag(caps.get(), CAP_EFFECTIVE, arraysize(value), value, CAP_SET) != 0) {
            PLOG(ERROR) << "cap_set_flag(PERMITTED|EFFECTIVE, " << CAP_SETPCAP << ") failed";
            return false;
        }
    }

    if (cap_set_proc(caps.get()) != 0) {
        PLOG(ERROR) << "cap_set_proc(" << to_keep.to_ulong() << ") failed";
        return false;
    }
    return true;
}

static bool SetAmbientCaps(const CapSet& to_raise) {
#if defined(__ANDROID__)
    for (size_t cap = 0; cap < to_raise.size(); ++cap) {
        if (to_raise.test(cap)) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) != 0) {
                PLOG(ERROR) << "prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, " << cap << ") failed";
                return false;
            }
        }
    }
#endif
    return true;
}

int LookupCap(const std::string& cap_name) {
    auto e = cap_map.find(cap_name);
    if (e != cap_map.end()) {
        return e->second;
    } else {
        return -1;
    }
}

bool CapAmbientSupported() {
    static bool cap_ambient_supported = ComputeCapAmbientSupported();
    return cap_ambient_supported;
}

unsigned int GetLastValidCap() {
    static unsigned int last_valid_cap = ComputeLastValidCap();
    return last_valid_cap;
}

bool SetCapsForExec(const CapSet& to_keep) {
    // Need to keep SETPCAP to drop bounding set below.
    bool add_setpcap = true;
    if (!SetProcCaps(to_keep, add_setpcap)) {
        LOG(ERROR) << "failed to apply initial capset";
        return false;
    }

    if (!DropBoundingSet(to_keep)) {
        return false;
    }

    // If SETPCAP wasn't specifically requested, drop it now.
    add_setpcap = false;
    if (!SetProcCaps(to_keep, add_setpcap)) {
        LOG(ERROR) << "failed to apply final capset";
        return false;
    }

    // Add the capabilities to the ambient set so that they are preserved across
    // execve(2).
    // See http://man7.org/linux/man-pages/man7/capabilities.7.html.
    return SetAmbientCaps(to_keep);
}

bool DropInheritableCaps() {
    ScopedCaps caps(cap_get_proc());
    if (cap_clear_flag(caps.get(), CAP_INHERITABLE) == -1) {
        PLOG(ERROR) << "cap_clear_flag(INHERITABLE) failed";
        return false;
    }
    if (cap_set_proc(caps.get()) != 0) {
        PLOG(ERROR) << "cap_set_proc() failed";
        return false;
    }
    return true;
}

}  // namespace init
}  // namespace android
