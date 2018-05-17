libmemunreachable
================

Introduction
--------------
libmemunreachable is a zero-overhead native memory leak detector.  It uses an imprecise mark-and-sweep garbage collector pass over all native memory, reporting any unreachable blocks as leaks.  It is similar to the [Heap Checker from tcmalloc](http://htmlpreview.github.io/?https://github.com/gperftools/gperftools/blob/master/doc/heap_checker.html), but with a few key differences to remove the overhead.  Instead of instrumenting every call to malloc and free, it queries the allocator (jemalloc) for active allocations when leak detection is requested.  In addition, it performs a very short stop-the-world data collection on the main process, and then forks a copy of the process to perform the mark-and-sweep, minimizing disruption to the original process.

In the default (zero-overhead) mode, the returned data on leaks is limited to the address, approximate (upper bound) size, and the the first 32 bytes of the contents of the leaked allocation.  If malloc_debug backtraces are enabled they will be included in the leak information, but backtracing allocations requires significant overhead.

----------

Usage
-------

### In Android apps ###

libmemunreachble is loaded by zygote and can be triggered with `dumpsys -t 600 meminfo --unreachable [process]`.

To enable malloc\_debug backtraces on allocations for a single app process on a userdebug device, use:
```
adb root
adb shell setprop libc.debug.malloc.program app_process
adb shell setprop wrap.[process] "\$\@"
adb shell setprop libc.debug.malloc.options backtrace=4
```

Kill and restart the app, trigger the leak, and then run `dumpsys -t 600 meminfo --unreachable [process]`.

To disable malloc\_debug:
```
adb shell setprop libc.debug.malloc.options "''"
adb shell setprop libc.debug.malloc.program "''"
adb shell setprop wrap.[process]  "''"
```

### C interface ###

#### `bool LogUnreachableMemory(bool log_contents, size_t limit)` ####
Writes a description of leaked memory to the log.  A summary is always written, followed by details of up to `limit` leaks.  If `log_contents` is `true`, details include up to 32 bytes of the contents of each leaked allocation.
Returns true if leak detection succeeded.

#### `bool NoLeaks()` ####
Returns `true` if no unreachable memory was found.

### C++ interface ###

####`bool GetUnreachableMemory(UnreachableMemoryInfo& info, size_t limit = 100)`####
Updates an `UnreachableMemoryInfo` object with information on leaks, including details on up to `limit` leaks.  Returns true if leak detection succeeded.

#### `std::string GetUnreachableMemoryString(bool log_contents = false, size_t limit = 100)` ####
Returns a description of leaked memory.  A summary is always written, followed by details of up to `limit` leaks.  If `log_contents` is `true`, details include up to 32 bytes of the contents of each leaked allocation.
Returns true if leak detection succeeded.

Implementation
-------------------
The sequence of steps required to perform a leak detection pass is divided into three processes - the original process, the collection process, and the sweeper process.

 1. *Original process*: Leak detection is requested by calling `GetUnreachableMemory()`
 2. Allocations are disabled using `malloc_disable()`
 3. The collection process is spawned.  The collection process, created using clone, is similar to a normal `fork()` child process, except that it shares the address space of the parent - any writes by the original process are visible to the collection process, and vice-versa. If we forked instead of using clone, the address space might get out of sync with observed post-ptrace thread state, since it takes some time to pause the parent.
 4. *Collection process*: All threads in the original process are paused with `ptrace()`.
 5. Registers contents, active stack areas, and memory mapping information are collected.
 6. *Original process*: Allocations are re-enabled using `malloc_enable()`, but all threads are still paused with `ptrace()`.
 7. *Collection process*: The sweeper process is spawned using a normal `fork()`.  The sweeper process has a copy of all memory from the original process, including all the data collected by the collection process.
 8. Collection process releases all threads from `ptrace` and exits
 9. *Original process*: All threads continue, the thread that called `GetUnreachableMemory()` blocks waiting for leak data over a pipe.
 10. *Sweeper process*: A list of all active allocations is produced by examining the memory mappings and calling `malloc_iterate()` on any heap mappings.
 11. A list of all roots is produced from globals (.data and .bss sections of binaries), and registers and stacks from each thread.
 12. The mark-and-sweep pass is performed starting from roots.
 13. Unmarked allocations are sent over the pipe back to the original process.

----------


Components
---------------
- `MemUnreachable.cpp`: Entry points, implements the sequencing described above.
- `PtracerThread.cpp`: Used to clone the collection process with shared address space.
- `ThreadCapture.cpp`: Pauses threads in the main process and collects register contents.
- `ProcessMappings.cpp`: Collects snapshots of `/proc/pid/maps`.
- `HeapWalker.cpp`: Performs the mark-and-sweep pass over active allocations.
- `LeakPipe.cpp`: transfers data describing leaks from the sweeper process to the original process.


Heap allocator requirements
----------------------------------
libmemunreachable requires a small interface to the allocator in order to collect information about active allocations.

 - `malloc_disable()`: prevent any thread from mutating internal allocator state.
 - `malloc enable()`: re-enable allocations in all threads.
 - `malloc_iterate()`: call a callback on each active allocation in a given heap region.
 - `malloc_backtrace()`: return the backtrace from when the allocation at the given address was allocated, if it was collected.
