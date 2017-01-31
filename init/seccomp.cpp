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

#include "seccomp.h"

#include <vector>

#include <sys/prctl.h>

#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "log.h"
#include "seccomp_policy.h"

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if   defined __arm__
#define AUDIT_ARCH_NR AUDIT_ARCH_ARM
#elif defined __aarch64__
#define AUDIT_ARCH_NR AUDIT_ARCH_AARCH64
#define AUDIT_ARCH_NR32 AUDIT_ARCH_ARM
#elif defined __i386__
#define AUDIT_ARCH_NR AUDIT_ARCH_I386
#elif defined __x86_64__
#define AUDIT_ARCH_NR AUDIT_ARCH_X86_64
#define AUDIT_ARCH_NR32 AUDIT_ARCH_I386
#elif defined __mips64__
#define AUDIT_ARCH_NR AUDIT_ARCH_MIPS64
#define AUDIT_ARCH_NR32 AUDIT_ARCH_MIPS
#elif defined __mips__ && !defined __mips64__
#define AUDIT_ARCH_NR AUDIT_ARCH_MIPS
#else
#error "Could not determine AUDIT_ARCH_NR for this architecture"
#endif

typedef std::vector<sock_filter> filter;

// We want to keep the below inline functions for debugging and future
// development even though they are not used currently.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

static inline void Kill(filter& f) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL));
}

static inline void Trap(filter& f) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRAP));
}

static inline void Error(filter& f, __u16 retcode) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO + retcode));
}

inline static void Trace(filter& f) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_TRACE));
}

inline static void Allow(filter& f) {
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW));
}

inline static void AllowSyscall(filter& f, __u32 num) {
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, num, 0, 1));
    f.push_back(BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW));
}

inline static void ExamineSyscall(filter& f) {
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, syscall_nr));
}

#ifdef AUDIT_ARCH_NR32
inline static int SetValidateArchitectureJumpTarget(size_t offset, filter& f) {
    auto jump_length = f.size() - offset - 1;
    auto u8_jump_length = (__u8) jump_length;
    if (u8_jump_length != jump_length) {
        LOG(ERROR) << "Can't set jump greater than 255 - actual jump is " << jump_length;
        return -1;
    }
    f[offset] = BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_NR32, u8_jump_length, 0);
    return 0;
}
#endif

inline static size_t ValidateArchitectureAndJumpIfNeeded(filter& f) {
    f.push_back(BPF_STMT(BPF_LD|BPF_W|BPF_ABS, arch_nr));

#ifdef AUDIT_ARCH_NR32
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_NR, 2, 0));
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_NR32, 1, 0));
    Kill(f);
    return f.size() - 2;
#else
    f.push_back(BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_NR, 1, 0));
    Kill(f);
    return 0;
#endif
}

#pragma clang diagnostic pop

static bool install_filter(filter const& f) {
    struct sock_fprog prog = {
        (unsigned short) f.size(),
        (struct sock_filter*) &f[0],
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        PLOG(ERROR) << "SECCOMP: Could not set seccomp filter";
        return false;
    }

    LOG(INFO) << "SECCOMP: Global filter installed";
    return true;
}

bool set_seccomp_filter() {
    filter f;

    // Note that for mixed 64/32 bit architectures, ValidateArchitecture inserts a
    // jump that must be changed to point to the start of the 32-bit policy
    // 32 bit syscalls will not hit the policy between here and the call to SetJump
#ifdef AUDIT_ARCH_NR32
    auto offset_to_32bit_filter =
#endif
        ValidateArchitectureAndJumpIfNeeded(f);

    // Native filter
    ExamineSyscall(f);

#ifdef __aarch64__
    // Syscalls needed to boot Android
    AllowSyscall(f, __NR_pivot_root);
    AllowSyscall(f, __NR_ioprio_get);
    AllowSyscall(f, __NR_ioprio_set);
    AllowSyscall(f, __NR_gettid);
    AllowSyscall(f, __NR_futex);
    AllowSyscall(f, __NR_clone);
    AllowSyscall(f, __NR_rt_sigreturn);
    AllowSyscall(f, __NR_rt_tgsigqueueinfo);
    AllowSyscall(f, __NR_add_key);
    AllowSyscall(f, __NR_request_key);
    AllowSyscall(f, __NR_keyctl);
    AllowSyscall(f, __NR_restart_syscall);
    AllowSyscall(f, __NR_getrandom);

    // Needed for performance tools
    AllowSyscall(f, __NR_perf_event_open);

    // Needed for treble
    AllowSyscall(f, __NR_finit_module);

    // Needed for trusty
    AllowSyscall(f, __NR_syncfs);

    // Needed for strace
    AllowSyscall(f, __NR_tkill);  // __NR_tkill

    // Needed for kernel to restart syscalls
    AllowSyscall(f, __NR_restart_syscall);

     // arm64-only filter - autogenerated from bionic syscall usage
    for (size_t i = 0; i < arm64_filter_size; ++i)
        f.push_back(arm64_filter[i]);
#else
    // Generic policy
    Allow(f);
#endif

#ifdef AUDIT_ARCH_NR32
    if (SetValidateArchitectureJumpTarget(offset_to_32bit_filter, f) != 0)
        return -1;

    // 32-bit filter for 64-bit platforms
    ExamineSyscall(f);

#ifdef __aarch64__
    // Syscalls needed to boot android
    AllowSyscall(f, 120); // __NR_clone
    AllowSyscall(f, 240); // __NR_futex
    AllowSyscall(f, 119); // __NR_sigreturn
    AllowSyscall(f, 173); // __NR_rt_sigreturn
    AllowSyscall(f, 363); // __NR_rt_tgsigqueueinfo
    AllowSyscall(f, 224); // __NR_gettid

    // Syscalls needed to run Chrome
    AllowSyscall(f, 383); // __NR_seccomp - needed to start Chrome
    AllowSyscall(f, 384); // __NR_getrandom - needed to start Chrome

    // Syscalls needed to run GFXBenchmark
    AllowSyscall(f, 190); // __NR_vfork

    // Needed for strace
    AllowSyscall(f, 238); // __NR_tkill

    // Needed for kernel to restart syscalls
    AllowSyscall(f, 0);   // __NR_restart_syscall

    // Needed for debugging 32-bit Chrome
    AllowSyscall(f, 42);  // __NR_pipe

    // b/34732712
    AllowSyscall(f, 364); // __NR_perf_event_open

    // b/34651972
    AllowSyscall(f, 33);  // __NR_access
    AllowSyscall(f, 195); // __NR_stat64

    // b/34813887
    AllowSyscall(f, 5);   // __NR_open
    AllowSyscall(f, 141); // __NR_getdents
    AllowSyscall(f, 217); // __NR_getdents64

    // b/34719286
    AllowSyscall(f, 351); // __NR_eventfd

    // arm32-on-arm64 only filter - autogenerated from bionic syscall usage
    for (size_t i = 0; i < arm_filter_size; ++i)
        f.push_back(arm_filter[i]);
#else
    // Generic policy
    Allow(f);
#endif
#endif
    return install_filter(f);
}
