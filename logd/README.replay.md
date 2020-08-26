logd can record and replay log messages for offline analysis.

Recording Messages
------------------

logd has a `RecordingLogBuffer` buffer that records messages to /data/misc/logd/recorded-messages.
It stores messages in memory until that file is accessible, in order to capture all messages since
the beginning of boot.  It is only meant for logging developers to use and must be manually enabled
in by adding `RecordingLogBuffer.cpp` to `Android.bp` and setting
`log_buffer = new SimpleLogBuffer(&reader_list, &log_tags, &log_statistics);` in `main.cpp`.

Recording messages may delay the Log() function from completing and it is highly recommended to make
the logd socket in `liblog` blocking, by removing `SOCK_NONBLOCK` from the `socket()` call in
`liblog/logd_writer.cpp`.

Replaying Messages
------------------

Recorded messages can be replayed offline with the `replay_messages` tool.  It runs on host and
device and supports the following options:

1. `interesting` - this prints 'interesting' statistics for each of the log buffer types (simple,
   chatty, serialized).  The statistics are:
    1. Log Entry Count
    2. Size (the uncompressed size of the log messages in bytes)
    3. Overhead (the total cost of the log messages in memory in bytes)
    4. Range (the range of time that the logs cover in seconds)
2. `memory_usage BUFFER_TYPE` - this prints the memory usage (sum of private dirty pages of the
  `replay_messages` process).  Note that the input file is mmap()'ed as RO/Shared so it does not
  appear in these dirty pages, and a baseline is taken before allocating the log buffers, so only
  their contributions are measured.  The tool outputs the memory usage every 100,000 messages.
3. `latency BUFFER_TYPE` - this prints statistics of the latency of the Log() function for the given
  buffer type.  It specifically prints the 1st, 2nd, and 3rd quartiles; the 95th, 99th, and 99.99th
  percentiles; and the maximum latency.
4. `print_logs BUFFER_TYPE [buffers] [print_point]` - this prints the logs as processed by the given
  buffer_type from the buffers specified by `buffers` starting after the number of logs specified by
  `print_point` have been logged.  This acts as if a user called `logcat` immediately after the
  specified logs have been logged, which is particularly useful since it will show the chatty
  pruning messages at that point.  It additionally prints the statistics from `logcat -S` after the
  logs.
  `buffers` is a comma separated list of the numeric buffer id values from `<android/log.h>`.  For
  example, `0,1,3` represents the main, radio, and system buffers.  It can can also be `all`.
  `print_point` is an positive integer.  If it is unspecified, logs are printed after the entire
  input file is consumed.
5. `nothing BUFFER_TYPE` - this does nothing other than read the input file and call Log() for the
  given buffer type.  This is used for profiling CPU usage of strictly the log buffer.
