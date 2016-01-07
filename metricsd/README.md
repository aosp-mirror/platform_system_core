Metricsd
========

The metricsd daemon is used to gather metrics from the platform and application,
aggregate them and upload them periodically to a server.
The metrics will then be available in their aggregated form to the developer
for analysis.

Three components are provided to interact with `metricsd`: `libmetrics`,
`metrics_collector` and `metrics_client`.

The Metrics Library: libmetrics
-------------------------------

`libmetrics` is a small library that implements the basic C++ API for
metrics collection. All metrics collection is funneled through this library. The
easiest and recommended way for a client-side module to collect user metrics is
to link `libmetrics` and use its APIs to send metrics to `metricsd` for transport to
UMA. In order to use the library in a module, you need to do the following:

- Add a dependency on the shared library in your Android.mk file:
  `LOCAL_SHARED_LIBRARIES += libmetrics`

- To access the metrics library API in the module, include the
  <metrics/metrics_library.h> header file.

- The API is documented in `metrics_library.h`. Before using the API methods, a
  MetricsLibrary object needs to be constructed and initialized through its
  Init method.

- Samples are uploaded only if the `/data/misc/metrics/enabled` file exists.


Server Side
-----------

You will be able to see all uploaded metrics on the metrics dashboard,
accessible via the developer console.

*** note
It usually takes a day for metrics to be available on the dashboard.
***


The Metrics Client: metrics_client
----------------------------------

`metrics_client` is a simple shell command-line utility for sending histogram
samples and querying `metricsd`. It's installed under `/system/bin` on the target
platform and uses `libmetrics`.

For usage information and command-line options, run `metrics_client` on the
target platform or look for "Usage:" in `metrics_client.cc`.


The Metrics Daemon: metricsd
----------------------------

`metricsd` is the daemon that listens for metrics logging calls (via Binder),
aggregates the metrics and uploads them periodically. This daemon should start as
early as possible so that depending daemons can log at any time.

`metricsd` is made of two threads that work as follows:

* The binder thread listens for one-way Binder calls, aggregates the metrics in
  memory (via `base::StatisticsRecorder`) and increments the crash counters when a
  crash is reported. This thread is kept as simple as possible to ensure the
  maximum throughput possible.
* The uploader thread takes care of backing up the metrics to disk periodically
  (to avoid losing metrics on crashes), collecting metadata about the client
  (version number, channel, etc..) and uploading the metrics periodically to the
  server.


The Metrics Collector: metrics_collector
----------------------------------------

metrics_collector is a daemon that runs in the background on the target platform,
gathers health information about the system and maintains long running counters
(ex: number of crashes per week).

The recommended way to generate metrics data from a module is to link and use
libmetrics directly. However, we may not want to add a dependency on libmetrics
to some modules (ex: kernel). In this case, we can add a collector to
metrics_collector that will, for example, take measurements and report them
periodically to metricsd (this is the case for the disk utilization histogram).


FAQ
---

### What should my histogram's |min| and |max| values be set at?

You should set the values to a range that covers the vast majority of samples
that would appear in the field. Note that samples below the |min| will still
be collected in the underflow bucket and samples above the |max| will end up
in the overflow bucket. Also, the reported mean of the data will be correct
regardless of the range.

### How many buckets should I use in my histogram?

You should allocate as many buckets as necessary to perform proper analysis
on the collected data. Note, however, that the memory allocated in metricsd
for each histogram is proportional to the number of buckets. Therefore, it is
strongly recommended to keep this number low (e.g., 50 is normal, while 100
is probably high).

### When should I use an enumeration (linear) histogram vs. a regular (exponential) histogram?

Enumeration histograms should really be used only for sampling enumerated
events and, in some cases, percentages. Normally, you should use a regular
histogram with exponential bucket layout that provides higher resolution at
the low end of the range and lower resolution at the high end. Regular
histograms are generally used for collecting performance data (e.g., timing,
memory usage, power) as well as aggregated event counts.

### How can I test that my histogram was reported correctly?

* Make sure no error messages appear in logcat when you log a sample.
* Run `metrics_client -d` to dump the currently aggregated metrics. Your
  histogram should appear in the list.
* Make sure that the aggregated metrics were uploaded to the server successfully
  (check for an OK message from `metricsd` in logcat).
* After a day, your histogram should be available on the dashboard.
