#include <log/log_frontend.h>
#define liblog liblog_stderr
#define TEST_PREFIX android_set_log_frontend(LOGGER_STDERR);
#define USING_LOGGER_STDERR
#include "liblog_test.cpp"
