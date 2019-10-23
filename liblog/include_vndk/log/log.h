/*Special log.h file for VNDK linking modules*/

#pragma once

#include <android/log.h>
#include <log/log_id.h>
#include <log/log_main.h>
#include <log/log_radio.h>
#include <log/log_safetynet.h>
#include <log/log_system.h>
#include <log/log_time.h>

/*
 * LOG_TAG is the local tag used for the following simplified
 * logging macros.  You can change this preprocessor definition
 * before using the other macros to change the tag.
 */

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

// Legacy dependencies...
/* deal with possible sys/cdefs.h conflict with fcntl.h */
#ifdef __unused
#define __unused_defined __unused
#undef __unused
#endif

#include <fcntl.h> /* Pick up O_* macros */

/* restore definitions from above */
#ifdef __unused_defined
#define __unused __attribute__((__unused__))
#endif
