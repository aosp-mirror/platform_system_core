#ifdef __ANDROID__
#include <log/log_transport.h>
#define TEST_LOGGER LOGGER_DEFAULT
#endif
#define USING_LOGGER_DEFAULT
#include "liblog_test.cpp"
