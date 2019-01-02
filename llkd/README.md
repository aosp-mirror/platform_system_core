Android Live-LocK Daemon
========================

Introduction
------------

Android Live-LocK Daemon (llkd) is used to catch kernel deadlocks and mitigate.

Code is structured to allow integration into another service as either as part
of the main loop, or spun off as a thread should that be necessary.  A default
standalone implementation is provided by llkd component.

The 'C' interface from libllkd component is thus:

    #include "llkd.h"
    bool llkInit(const char* threadname) /* return true if enabled */
    unsigned llkCheckMillseconds(void)   /* ms to sleep for next check */

If a threadname is provided, a thread will be automatically spawned, otherwise
caller must call llkCheckMilliseconds in its main loop.  Function will return
the period of time before the next expected call to this handler.

Operations
----------

There are two detection scenarios. Persistent D or Z state, and persistent
stack signature.

If a thread is in D or Z state with no forward progress for longer than
ro.llk.timeout_ms, or ro.llk.[D|Z].timeout_ms, kill the process or parent
process respectively.  If another scan shows the same process continues to
exist, then have a confirmed live-lock condition and need to panic.  Panic
the kernel in a manner to provide the greatest bugreporting details as to the
condition.  Add a alarm self watchdog should llkd ever get locked up that is
double the expected time to flow through the mainloop.  Sampling is every
ro.llk_sample_ms.

For usedebug releases only, persistent stack signature checking is enabled.
If a thread in any state but Z, has a persistent listed ro.llk.stack kernel
symbol always being reported, even if there is forward scheduling progress, for
longer than ro.llk.timeout_ms, or ro.llk.stack.timeout_ms, then issue a kill
to the process.  If another scan shows the same process continues to exist,
then have a confirmed live-lock condition and need to panic.  There is no
ABA detection since forward scheduling progress is allowed, thus the condition
for the symbols are:

- Check is looking for " __symbol__+0x" or " __symbol__.cfi+0x" in
  /proc/__pid__/stack.
- The __symbol__ should be rare and short lived enough that on a typical
  system the function is seen at most only once in a sample over the timeout
  period of ro.llk.stack.timeout_ms, samples occur every ro.llk.check_ms. This
  can be the only way to prevent a false trigger as there is no ABA protection.
- Persistent continuously when the live lock condition exists.
- Should be just below the function that is calling the lock that could
  contend, because if the lock is below or in the symbol function, the
  symbol will show in all affected processes, not just the one that
  caused the lockup.

Default will not monitor init, or [kthreadd] and all that [kthreadd] spawns.
This reduces the effectiveness of llkd by limiting its coverage.  If there is
value in covering [kthreadd] spawned threads, the requirement will be that
the drivers not remain in a persistent 'D' state, or that they have mechanisms
to recover the thread should it be killed externally (this is good driver
coding hygiene, a common request to add such to publicly reviewed kernel.org
maintained drivers).  For instance use wait_event_interruptible() instead of
wait_event().  The blacklists can be adjusted accordingly if these
conditions are met to cover kernel components.  For the stack symbol checking,
there is an additional process blacklist so that we do not incide sepolicy
violations on services that block ptrace operations.

An accompanying gTest set have been added, and will setup a persistent D or Z
process, with and without forward progress, but not in a live-lock state
because that would require a buggy kernel, or a module or kernel modification
to stimulate.  The test will check that llkd will mitigate first by killing
the appropriate process.  D state is setup by vfork() waiting for exec() in
child process.  Z state is setup by fork() and an un-waited for child process.
Should be noted that both of these conditions should never happen on Android
on purpose, and llkd effectively sweeps up processes that create these
conditions.  If the test can, it will reconfigure llkd to expedite the test
duration by adjusting the ro.llk.* Android properties.  Tests run the D state
with some scheduling progress to ensure that ABA checking prevents false
triggers. If 100% reliable ABA on platform, then ro.llk.killtest can be
set to false; however this will result in some of the unit tests to panic
kernel instead of deal with more graceful kill operation.

Android Properties
------------------

The following are the Android Properties llkd respond to.
*prop*_ms named properties are in milliseconds.
Properties that use comma (*,*) separator for lists, use a leading separator to
preserve default and add or subtract entries with (*optional*) plus (*+*) and
minus (*-*) prefixes respectively.
For these lists, the string "*false*" is synonymous with an *empty* list,
and *blank* or *missing* resorts to the specified *default* value.

#### ro.config.low_ram
device is configured with limited memory.

#### ro.debuggable
device is configured for userdebug or eng build.

#### ro.llk.sysrq_t
default not ro.config.low_ram, or ro.debuggable if property is "eng".
if true do sysrq t (dump all threads).

#### ro.llk.enable
default false, allow live-lock daemon to be enabled.

#### llk.enable
default ro.llk.enable, and evaluated for eng.

#### ro.khungtask.enable
default false, allow [khungtask] daemon to be enabled.

#### khungtask.enable
default ro.khungtask.enable and evaluated for eng.

#### ro.llk.mlockall
default false, enable call to mlockall().

#### ro.khungtask.timeout
default value 12 minutes, [khungtask] maximum timelimit.

#### ro.llk.timeout_ms
default 10 minutes, D or Z maximum timelimit, double this value and it sets
the alarm watchdog for llkd.

#### ro.llk.D.timeout_ms
default ro.llk.timeout_ms, D maximum timelimit.

#### ro.llk.Z.timeout_ms
default ro.llk.timeout_ms, Z maximum timelimit.

#### ro.llk.stack.timeout_ms
default ro.llk.timeout_ms,
checking for persistent stack symbols maximum timelimit.
Only active on userdebug or eng builds.

#### ro.llk.check_ms
default 2 minutes samples of threads for D or Z.

#### ro.llk.stack
default cma_alloc,__get_user_pages,bit_wait_io,wait_on_page_bit_killable
comma separated list of kernel symbols.
Look for kernel stack symbols that if ever persistently present can
indicate a subsystem is locked up.
Beware, check does not on purpose do forward scheduling ABA except by polling
every ro.llk_check_ms over the period ro.llk.stack.timeout_ms, so stack symbol
should be exceptionally rare and fleeting.
One must be convinced that it is virtually *impossible* for symbol to show up
persistently in all samples of the stack.
Again, looks for a match for either " **symbol**+0x" or " **symbol**.cfi+0x"
in stack expansion.
Only available on userdebug or eng builds, limited privileges due to security
concerns on user builds prevents this checking.

#### ro.llk.blacklist.process
default 0,1,2 (kernel, init and [kthreadd]) plus process names
init,[kthreadd],[khungtaskd],lmkd,llkd,watchdogd,
[watchdogd],[watchdogd/0],...,[watchdogd/***get_nprocs**-1*].
Do not watch these processes.  A process can be comm, cmdline or pid reference.
NB: automated default here can be larger than the current maximum property
size of 92.
NB: false is a very very very unlikely process to want to blacklist.

#### ro.llk.blacklist.parent
default 0,2,adbd&[setsid] (kernel, [kthreadd] and adbd *only for zombie setsid*).
Do not watch processes that have this parent.
An ampersand (*&*) separator is used to specify that the parent is ignored
only in combination with the target child process.
Ampersand was selected because it is never part of a process name,
however a setprop in the shell requires it to be escaped or quoted;
init rc file where this is normally specified does not have this issue.
A parent or target processes can be specified as comm, cmdline or pid reference.

#### ro.llk.blacklist.uid
default *empty* or false, comma separated list of uid numbers or names.
Do not watch processes that match this uid.

#### ro.llk.blacklist.process.stack
default process names init,lmkd.llkd,llkd,keystore,ueventd,apexd,logd.
This subset of processes are not monitored for live lock stack signatures.
Also prevents the sepolicy violation associated with processes that block
ptrace, as these can not be checked anyways.
Only active on userdebug and eng builds.

Architectural Concerns
----------------------

- built-in [khungtask] daemon is too generic and trips on driver code that
  sits around in D state too much.  To switch to S instead makes the task(s)
  killable, so the drivers should be able to resurrect them if needed.
- Properties are limited to 92 characters.
- Create kernel module and associated gTest to actually test panic.
- Create gTest to test out blacklist (ro.llk.blacklist.*properties* generally
  not be inputs).  Could require more test-only interfaces to libllkd.
- Speed up gTest using something else than ro.llk.*properties*, which should
  not be inputs as they should be baked into the product.
