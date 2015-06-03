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

#ifndef _DEBUGGERD_TEST_HOST_SIGNAL_FIXUP_H
#define _DEBUGGERD_TEST_HOST_SIGNAL_FIXUP_H

#include <signal.h>

#if !defined(__BIONIC__)

// In order to compile parts of debuggerd for the host, we need to
// define these values.

#if !defined(NSIGILL)
#define NSIGILL ILL_BADSTK
#endif

#if !defined(BUS_MCEERR_AR)
#define BUS_MCEERR_AR 4
#endif
#if !defined(BUS_MCEERR_AO)
#define BUS_MCEERR_AO 5
#endif
#if !defined(NSIGBUS)
#define NSIGBUS BUS_MCEERR_AO
#endif

#if !defined(NSIGFPE)
#define NSIGFPE FPE_FLTSUB
#endif

#if !defined(NSIGSEGV)
#define NSIGSEGV SEGV_ACCERR
#endif

#if !defined(TRAP_BRANCH)
#define TRAP_BRANCH 3
#endif
#if !defined(TRAP_HWBKPT)
#define TRAP_HWBKPT 4
#endif
#if !defined(NSIGTRAP)
#define NSIGTRAP TRAP_HWBKPT
#endif

#if !defined(SI_DETHREAD)
#define SI_DETHREAD -7
#endif

#endif

#endif // _DEBUGGERD_TEST_HOST_SIGNAL_FIXUP_H
