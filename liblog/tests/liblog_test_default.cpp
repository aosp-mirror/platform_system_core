#ifdef __ANDROID__
#include <log/log_frontend.h>
#define TEST_PREFIX android_set_log_frontend(LOGGER_DEFAULT);
#endif
#include "liblog_test.cpp"
