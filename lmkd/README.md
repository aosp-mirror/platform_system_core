Android Low Memory Killer Daemon
================================


Introduction
------------

Android Low Memory Killer Daemon (lmkd) is a process monitoring memory
state of a running Android system and reacting to high memory pressure
by killing the least essential process(es) to keep system performing
at acceptable levels.


Background
----------

Historically on Android systems memory monitoring and killing of
non-essential processes was handled by a kernel lowmemorykiller driver.
Since Linux Kernel 4.12 the lowmemorykiller driver has been removed and
instead userspace lmkd daemon performs these tasks.


Android Properties
------------------

lmkd can be configured on a particular system using the following Android
properties:

  ro.config.low_ram:         choose between low-memory vs high-performance
                             device. Default = false.

  ro.lmk.use_minfree_levels: use free memory and file cache thresholds for
                             making decisions when to kill. This mode works
                             the same way kernel lowmemorykiller driver used
                             to work. Default = false

  ro.lmk.low:                min oom_adj score for processes eligible to be
                             killed at low vmpressure level. Default = 1001
                             (disabled)

  ro.lmk.medium:             min oom_adj score for processes eligible to be
                             killed at medium vmpressure level. Default = 800
                             (non-essential processes)

  ro.lmk.critical:           min oom_adj score for processes eligible to be
                             killed at critical vmpressure level. Default = 0
                             (all processes)

  ro.lmk.critical_upgrade:   enables upgrade to critical level. Default = false

  ro.lmk.upgrade_pressure:   max mem_pressure at which level will be upgraded
                             because system is swapping too much. Default = 100
                             (disabled)

  ro.lmk.downgrade_pressure: min mem_pressure at which vmpressure event will
                             be ignored because enough free memory is still
                             available. Default = 100 (disabled)

  ro.lmk.kill_heaviest_task: kill heaviest eligible task (best decision) vs.
                             any eligible task (fast decision). Default = false

  ro.lmk.kill_timeout_ms:    duration in ms after a kill when no additional
                             kill will be done, Default = 0 (disabled)

  ro.lmk.debug:              enable lmkd debug logs, Default = false
