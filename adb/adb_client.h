#ifndef _ADB_CLIENT_H_
#define _ADB_CLIENT_H_

#include "adb.h"

#include <string>

/* connect to adb, connect to the named service, and return
** a valid fd for interacting with that service upon success
** or a negative number on failure
*/
int adb_connect(const std::string& service, std::string* error);
int _adb_connect(const std::string& service, std::string* error);

/* connect to adb, connect to the named service, return 0 if
** the connection succeeded AND the service returned OKAY
*/
int adb_command(const std::string& service, std::string* error);

// Connects to the named adb service and fills 'result' with the response.
// Returns true on success; returns false and fills 'error' on failure.
bool adb_query(const std::string& service, std::string* result, std::string* error);

/* Set the preferred transport to connect to.
*/
void adb_set_transport(transport_type type, const char* serial);

/* Set TCP specifics of the transport to use
*/
void adb_set_tcp_specifics(int server_port);

/* Set TCP Hostname of the transport to use
*/
void adb_set_tcp_name(const char* hostname);

/* Return the console port of the currently connected emulator (if any)
 * of -1 if there is no emulator, and -2 if there is more than one.
 * assumes adb_set_transport() was alled previously...
 */
int  adb_get_emulator_console_port(void);

/* send commands to the current emulator instance. will fail if there
 * is zero, or more than one emulator connected (or if you use -s <serial>
 * with a <serial> that does not designate an emulator)
 */
int  adb_send_emulator_command(int  argc, const char**  argv);

// Reads a standard adb status response (OKAY|FAIL) and
// returns true in the event of OKAY, false in the event of FAIL
// or protocol error.
bool adb_status(int fd, std::string* error);

#endif
