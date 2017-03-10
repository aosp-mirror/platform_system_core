#ifdef __ANDROID__
#include <log/log_transport.h>
#define TEST_PREFIX android_set_log_transport(LOGGER_DEFAULT);
#endif
#include "liblog_test.cpp"
