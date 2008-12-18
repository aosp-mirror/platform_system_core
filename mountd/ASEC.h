#ifndef _ASEC_H
#define _ASEC_H

#define ASEC_STORES_MAX 4
#define MAX_LOOP 8

typedef enum AsecState {
    // Feature disabled
    ASEC_DISABLED,

    // Feature enabled and operational
    ASEC_AVAILABLE,

    // Busy
    ASEC_BUSY,

    // Internal Error
    ASEC_FAILED_INTERR,

    // No media available
    ASEC_FAILED_NOMEDIA,

    // Media is corrupt
    ASEC_FAILED_BADMEDIA,

    // Key mismatch
    ASEC_FAILED_BADKEY,
} AsecState;

/*
 * ASEC commands
 */
#define ASEC_CMD_SEND_STATUS		"asec_send_status"
#define ASEC_CMD_ENABLE			"asec_enable"
#define ASEC_CMD_DISABLE		"asec_disable"

/*
 * ASEC events
 */

// These events correspond to the states in the AsecState enum.
// A path to the ASEC mount point follows the colon
#define ASEC_EVENT_DISABLED		"asec_disabled:"
#define ASEC_EVENT_AVAILABLE		"asec_available:"
#define ASEC_EVENT_BUSY			"asec_busy:"
#define ASEC_EVENT_FAILED_INTERR	"asec_failed_interror:"
#define ASEC_EVENT_FAILED_NOMEDIA	"asec_failed_nomedia"
#define ASEC_EVENT_FAILED_BADMEDIA	"asec_failed_badmedia:"
#define ASEC_EVENT_FAILED_BADKEY	"asec_failed_badkey:"

/*
 * System Properties
 */

#define ASEC_ENABLED			"asec.enabled"

#define ASEC_STATUS			"ro.asec.status"
#define ASEC_STATUS_DISABLED		"disabled"
#define ASEC_STATUS_AVAILABLE		"available"
#define ASEC_STATUS_BUSY			"busy"
#define ASEC_STATUS_FAILED_INTERR	"internal_error"
#define ASEC_STATUS_FAILED_NOMEDIA	"no_media"
#define ASEC_STATUS_FAILED_BADMEDIA	"bad_media"
#define ASEC_STATUS_FAILED_BADKEY	"bad_key"

#endif
