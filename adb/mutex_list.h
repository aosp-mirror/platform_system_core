/* the list of mutexes used by addb */
#ifndef ADB_MUTEX
#error ADB_MUTEX not defined when including this file
#endif

ADB_MUTEX(dns_lock)
ADB_MUTEX(socket_list_lock)
ADB_MUTEX(transport_lock)
#if ADB_HOST
ADB_MUTEX(local_transports_lock)
#endif
ADB_MUTEX(usb_lock)

#undef ADB_MUTEX
