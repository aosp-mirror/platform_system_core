#include "netlink/netlink.h"
#include <android/log.h>

void libnl_printf(int level, char *format, ...)
{
	va_list ap;

	level = ANDROID_LOG_ERROR;
	va_start(ap, format);
	__android_log_vprint(level, "libnl_2", format, ap);
	va_end(ap);
}
