/*Special log.h file for VNDK linking modules*/

#ifndef _LIBS_LOG_LOG_H
#define _LIBS_LOG_LOG_H

#include <android/log.h>

/*The following files will be included once they are available*/
/*#include <log/log_id.h>*/
/*#include <log/log_radio.h>*/

/*
 * LOG_TAG is the local tag used for the following simplified
 * logging macros.  You can change this preprocessor definition
 * before using the other macros to change the tag.
 */

#ifndef LOG_TAG
#define LOG_TAG NULL
#endif

#endif /*_LIBS_LOG_LOG_H*/
