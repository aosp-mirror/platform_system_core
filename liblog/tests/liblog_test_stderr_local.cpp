#include <log/log_transport.h>
#define liblog liblog_stderr_local
#define TEST_PREFIX android_set_log_transport(LOGGER_LOCAL | LOGGER_STDERR);
#include "liblog_test.cpp"
