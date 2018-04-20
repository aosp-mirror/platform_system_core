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

If a thread is in D or Z state with no forward progress for longer than
ro.llk.timeout_ms, or ro.llk.[D|Z].timeout_ms, kill the process or parent
process respectively.  If another scan shows the same process continues to
exist, then have a confirmed live-lock condition and need to panic.  Panic
the kernel in a manner to provide the greatest bugreporting details as to the
condition.  Add a alarm self watchdog should llkd ever get locked up that is
double the expected time to flow through the mainloop.  Sampling is every
ro.llk_sample_ms.

Default will not monitor init, or [kthreadd] and all that [kthreadd] spawns.
This reduces the effectiveness of llkd by limiting its coverage.  If there is
value in covering [kthreadd] spawned threads, the requirement will be that
the drivers not remain in a persistent 'D' state, or that they have mechanisms
to recover the thread should it be killed externally (this is good driver
coding hygiene, a common request to add such to publicly reviewed kernel.org
maintained drivers).  For instance use wait_event_interruptible() instead of
wait_event().  The blacklists can be adjusted accordingly if these
conditions are met to cover kernel components.

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
triggers.

Android Properties
------------------

Android Properties llkd respond to (<prop>_ms parms are in milliseconds):

#### ro.config.low_ram
default false, if true do not sysrq t (dump all threads).

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

#### ro.llk.check_ms
default 2 minutes samples of threads for D or Z.

#### ro.llk.blacklist.process
default 0,1,2 (kernel, init and [kthreadd]) plus process names
init,[kthreadd],[khungtaskd],lmkd,lmkd.llkd,llkd,watchdogd,
[watchdogd],[watchdogd/0],...,[watchdogd/<get_nprocs-1>].

#### ro.llk.blacklist.parent
default 0,2 (kernel and [kthreadd]).

#### ro.llk.blacklist.uid
default <empty>, comma separated list of uid numbers or names.

Architectural Concerns
----------------------

- Figure out how to communicate the kernel panic better to bootstat canonical
  boot reason determination.  This may require an alteration to bootstat, or
  some logging from llkd.  Would like to see boot reason to be
  watchdog,livelock as a minimum requirement.  Or more specifically would want
  watchdog,livelock,device or watchdog,livelock,zombie be reported.
  Currently reports panic,sysrq (user requested panic) or panic depending on
  system support of pstore.
- Create kernel module and associated gTest to actually test panic.
- Create gTest to test out blacklist (ro.llk.blacklist.<properties> generally
  not be inputs).  Could require more test-only interfaces to libllkd.
- Speed up gTest using something else than ro.llk.<properties>, which should
  not be inputs.
