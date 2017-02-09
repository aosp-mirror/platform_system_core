#include <log/log_frontend.h>
#define liblog liblog_local
#define TEST_PREFIX android_set_log_frontend(LOGGER_LOCAL);
#include "liblog_test.cpp"
