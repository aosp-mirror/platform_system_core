# crash_reporter

`crash_reporter` is a deamon running on the device that saves the call stack of
crashing programs. It makes use of the
[Breakpad](https://chromium.googlesource.com/breakpad/breakpad/) library.

During a build, Breakpad symbol files are generated for all binaries.  They are
packaged into a zip file when running `m dist`, so that a developer can upload
them to the crash server.

On a device, if the user has opted in to metrics and crash reporting, a
Breakpad minidump is generated when an executable crashes, which is then
uploaded to the crash server.

On the crash server, it compares the minidump's signature to the symbol files
that the developer has uploaded, and extracts and symbolizes the stack trace
from the minidump.

## SELinux policies

In order to correctly generate a minidump, `crash_reporter` needs to be given
the proper SELinux permissions for accessing the domain of the crashing
executable.  By default, `crash_reporter` has only been given access to a select
number of system domains, such as `metricsd`, `weave`, and `update_engine`.  If
a developer wants their executable's crashes to be caught by `crash_reporter`,
they will have to set their SELinux policies in their .te file to allow
`crash_reporter` access to their domain.  This can be done through a simple
[macro](https://android.googlesource.com/device/generic/brillo/+/master/sepolicy/te_macros):

    allow_crash_reporter(domain_name)

Replace *domain_name* with whatever domain is assigned to the executable in
the `file_contexts` file.

## Configuration

`crash_reporter` has a few different configuration options that have to be set.

- Crashes are only handled and uploaded if analytics reporting is enabled,
  either via the weave call to set `_metrics.enableAnalyticsReporting` or by
  manually creating the file `/data/misc/metrics/enabled` (for testing only).
- The `BRILLO_CRASH_SERVER` make variable should be set in the `product.mk`
  file to the URL of the crash server.  For Brillo builds, it is set
  automatically through the product configuration.  Setting this variable will
  populate the `/etc/os-release.d/crash_server` file on the device, which is
  read by `crash_sender`.
- The `BRILLO_PRODUCT_ID` make variable should be set in the `product.mk` file
  to the product's ID.  For Brillo builds, it is set automatically through the
  product configuration.  Setting this variable will populate the
  `/etc/os-release.d/product_id`, which is read by `crash_sender`.

## Uploading crash reports in *eng* builds

By default, crash reports are only uploaded to the server for production
*user* and *userdebug* images.  In *eng* builds, with crash reporting enabled
the device will generate minidumps for any crashing executables but will not
send them to the crash server.  If a developer does want to force an upload,
they can do so by issuing the command `SECONDS_SEND_SPREAD=5 FORCE_OFFICIAL=1
crash_sender` from an ADB shell.  This will send the report to the server, with
the *image_type* field set to *force-official* so that these reports can be
differentiated from normal reports.
