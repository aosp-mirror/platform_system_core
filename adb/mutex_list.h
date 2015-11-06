/* the list of mutexes used by adb */
/* #ifndef __MUTEX_LIST_H
 * Do not use an include-guard. This file is included once to declare the locks
 * and once in win32 to actually do the runtime initialization.
 */
#ifndef ADB_MUTEX
#error ADB_MUTEX not defined when including this file
#endif
ADB_MUTEX(basename_lock)
ADB_MUTEX(dirname_lock)
ADB_MUTEX(socket_list_lock)
ADB_MUTEX(transport_lock)
#if ADB_HOST
ADB_MUTEX(local_transports_lock)
#endif
ADB_MUTEX(usb_lock)

#undef ADB_MUTEX
