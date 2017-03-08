#include <log/log_frontend.h>
#define liblog liblog_stderr_local
#define TEST_PREFIX android_set_log_frontend(LOGGER_LOCAL | LOGGER_STDERR);
#include "liblog_test.cpp"
