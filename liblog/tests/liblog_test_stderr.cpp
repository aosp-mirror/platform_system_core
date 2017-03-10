#include <log/log_transport.h>
#define liblog liblog_stderr
#define TEST_PREFIX android_set_log_transport(LOGGER_STDERR);
#define USING_LOGGER_STDERR
#include "liblog_test.cpp"
