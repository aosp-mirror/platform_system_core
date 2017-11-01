#include <log/log_transport.h>
#define liblog liblog_stderr_local
#define TEST_LOGGER (LOGGER_LOCAL | LOGGER_STDERR)
#include "liblog_test.cpp"
