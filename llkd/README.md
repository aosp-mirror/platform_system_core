<!--
Project: /_project.yaml
Book: /_book.yaml

{% include "_versions.html" %}
-->

<!--
  Copyright 2020 The Android Open Source Project

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->

# Android Live-LocK Daemon (llkd)

Android 10 <!-- {{ androidQVersionNumber }} --> includes the Android Live-LocK Daemon
(`llkd`), which is designed to catch and mitigate kernel deadlocks. The `llkd`
component provides a default standalone implementation, but you can
alternatively integrate the `llkd` code into another service, either as part of
the main loop or as a separate thread.

## Detection scenarios <!-- {:#detection-scenarios} -->

The `llkd` has two detection scenarios: Persistent D or Z state, and persistent
stack signature.

### Persistent D or Z state <!-- {:#persistent-d-or-z-state} -->

If a thread is in D (uninterruptible sleep) or Z (zombie) state with no forward
progress for longer than `ro.llk.timeout_ms or ro.llk.[D|Z].timeout_ms`, the
`llkd` kills the process (or parent process). If a subsequent scan shows the
same process continues to exist, the `llkd` confirms a live-lock condition and
panics the kernel in a manner that provides the most detailed bug report for the
condition.

The `llkd` includes a self watchdog that alarms if `llkd` locks up; watchdog is
double the expected time to flow through the mainloop and sampling is every
`ro.llk_sample_ms`.

### Persistent stack signature <!-- {:#persistent-stack-signature} -->

For userdebug releases, the `llkd` can detect kernel live-locks using persistent
stack signature checking. If a thread in any state except Z has a persistent
listed `ro.llk.stack` kernel symbol that is reported for longer than
`ro.llk.timeout_ms` or `ro.llk.stack.timeout_ms`, the `llkd` kills the process
(even if there is forward scheduling progress). If a subsequent scan shows the
same process continues to exist, the `llkd` confirms a live-lock condition and
panics the kernel in a manner that provides the most detailed bug report for the
condition.

Note: Because forward scheduling progress is allowed, the `llkd` does not
perform [ABA detection](https://en.wikipedia.org/wiki/ABA_problem){:.external}.

The `lldk` check persists continuously when the live lock condition exists and
looks for the composed strings `" symbol+0x"` or `" symbol.cfi+0x"` in the
`/proc/pid/stack` file on Linux. The list of symbols is in `ro.llk.stack` and
defaults to the comma-separated list of
"`cma_alloc,__get_user_pages,bit_wait_io,wait_on_page_bit_killable`".

Symbols should be rare and short-lived enough that on a typical system the
function is seen only once in a sample over the timeout period of
`ro.llk.stack.timeout_ms` (samples occur every `ro.llk.check_ms`). Due to lack
of ABA protection, this is the only way to prevent a false trigger. The symbol
function must appear below the function calling the lock that could contend. If
the lock is below or in the symbol function, the symbol appears in all affected
processes, not just the one that caused the lockup.

## Coverage <!-- {:#coverage} -->

The default implementation of `llkd` does not monitor `init`, `[kthreadd]`, or
`[kthreadd]` spawns. For the `llkd` to cover `[kthreadd]`-spawned threads:

* Drivers must not remain in a persistent D state,

OR

* Drivers must have mechanisms to recover the thread should it be killed
  externally. For example, use `wait_event_interruptible()` instead of
  `wait_event()`.

If one of the above conditions is met, the `llkd` ignorelist can be adjusted to
cover kernel components.  Stack symbol checking involves an additional process
ignore list to prevent sepolicy violations on services that block `ptrace`
operations.

## Android properties <!-- {:#android-properties} -->

The `llkd` responds to several Android properties (listed below).

* Properties named `prop_ms` are in milliseconds.
* Properties that use comma (,) separator for lists use a leading separator to
  preserve the default entry, then add or subtract entries with optional plus
  (+) and minus (-) prefixes respectively. For these lists, the string "false"
  is synonymous with an empty list, and blank or missing entries resort to the
  specified default value.

### ro.config.low_ram <!-- {:#ro-config-low-ram} -->

Device is configured with limited memory.

### ro.debuggable <!-- {:#ro-debuggable} -->

Device is configured for userdebug or eng build.

### ro.llk.sysrq_t <!-- {:#ro-llk-sysrq-t} -->

If property is "eng", the default is not `ro.config.low_ram` or `ro.debuggable`.
If true, dump all threads (`sysrq t`).

### ro.llk.enable <!-- {:#ro-llk-enable} -->

Allow live-lock daemon to be enabled. Default is false.

### llk.enable <!-- {:#llk-enable} -->

Evaluated for eng builds. Default is `ro.llk.enable`.

### ro.khungtask.enable <!-- {:#ro-khungtask-enable} -->

Allow `[khungtask]` daemon to be enabled. Default is false.

### khungtask.enable <!-- {:#khungtask-enable} -->

Evaluated for eng builds. Default is `ro.khungtask.enable`.

### ro.llk.mlockall <!-- {:#ro-llk-mlockall} -->

Enable call to `mlockall()`. Default is false.

### ro.khungtask.timeout <!-- {:#ro-khungtask-timeout} -->

`[khungtask]` maximum time limit. Default is 12 minutes.

### ro.llk.timeout_ms <!-- {:#ro-llk-timeout-ms} -->

D or Z maximum time limit. Default is 10 minutes. Double this value to set the
alarm watchdog for `llkd`.

### ro.llk.D.timeout_ms <!-- {:#ro-llk-D-timeout-ms} -->

D maximum time limit. Default is `ro.llk.timeout_ms`.

### ro.llk.Z.timeout_ms <!-- {:#ro-llk-Z-timeout-ms} -->

Z maximum time limit. Default is `ro.llk.timeout_ms`.

### ro.llk.stack.timeout_ms <!-- {:#ro-llk-stack-timeout-ms} -->

Checks for persistent stack symbols maximum time limit. Default is
`ro.llk.timeout_ms`. **Active only on userdebug or eng builds**.

### ro.llk.check_ms <!-- {:#ro-llk-check-ms} -->

Samples of threads for D or Z. Default is two minutes.

### ro.llk.stack <!-- {:#ro-llk-stack} -->

Checks for kernel stack symbols that if persistently present can indicate a
subsystem is locked up. Default is
`cma_alloc,__get_user_pages,bit_wait_io,wait_on_page_bit_killable`
comma-separated list of kernel symbols. The check doesn't do forward scheduling
ABA except by polling every `ro.llk_check_ms` over the period
`ro.llk.stack.timeout_ms`, so stack symbols should be exceptionally rare and
fleeting (it is highly unlikely for a symbol to show up persistently in all
samples of the stack). Checks for a match for `" symbol+0x"` or
`" symbol.cfi+0x"` in stack expansion. **Available only on userdebug or eng
builds**; security concerns on user builds result in limited privileges that
prevent this check.

### ro.llk.ignorelist.process <!-- {:#ro-llk-ignorelist-process} -->

The `llkd` does not watch the specified processes. Default is `0,1,2` (`kernel`,
`init`, and `[kthreadd]`) plus process names
`init,[kthreadd],[khungtaskd],lmkd,llkd,watchdogd, [watchdogd],[watchdogd/0],...,[watchdogd/get_nprocs-1]`.
A process can be a `comm`, `cmdline`, or `pid` reference. An automated default
can be larger than the current maximum property size of 92.

Note: `false` is an extremely unlikely process to want to ignore.

### ro.llk.ignorelist.parent <!-- {:#ro-llk-ignorelist-parent} -->

The `llkd` does not watch processes that have the specified parent(s). Default
is `0,2,adbd&[setsid]` (`kernel`, `[kthreadd]`, and `adbd` only for zombie
`setsid`). An ampersand (&) separator specifies that the parent is ignored only
in combination with the target child process. Ampersand was selected because it
is never part of a process name; however, a `setprop` in the shell requires the
ampersand to be escaped or quoted, although the `init rc` file where this is
normally specified does not have this issue. A parent or target process can be a
`comm`, `cmdline`, or `pid` reference.

### ro.llk.ignorelist.uid <!-- {:#ro-llk-ignorelist-uid} -->

The `llkd` does not watch processes that match the specified uid(s).
Comma-separated list of uid numbers or names. Default is empty or false.

### ro.llk.ignorelist.process.stack <!-- {:#ro-llk-ignorelist-process-stack} -->

The `llkd` does not monitor the specified subset of processes for live lock stack
signatures. Default is process names
`init,lmkd.llkd,llkd,keystore,ueventd,apexd,logd`. Prevents the sepolicy
violation associated with processes that block `ptrace` (as these can't be
checked). **Active only on userdebug and eng builds**. For details on build
types, refer to [Building Android](/setup/build/building#choose-a-target).

## Architectural concerns <!-- {:#architectural-concerns} -->

* Properties are limited to 92 characters.  However, this is not limited for
  defaults defined in the `include/llkd.h` file in the sources.
* The built-in `[khungtask]` daemon is too generic and trips on driver code that
  sits around in D state too much. Switching drivers to sleep, or S state,
  would make task(s) killable, and need to be resurrectable by drivers on an
  as-need basis.

## Library interface (optional) <!-- {:#library-interface-optional} -->

You can optionally incorporate the `llkd` into another privileged daemon using
the following C interface from the `libllkd` component:

```
#include "llkd.h"
bool llkInit(const char* threadname) /* return true if enabled */
unsigned llkCheckMillseconds(void)   /* ms to sleep for next check */
```

If a threadname is provided, a thread automatically spawns, otherwise the caller
must call `llkCheckMilliseconds` in its main loop. The function returns the
period of time before the next expected call to this handler.
