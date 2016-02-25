#!/usr/bin/env python
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Record the event logs during boot and output them to a file.

This script repeats the record of each event log during Android boot specified
times. By default, interval between measurements is adjusted in such a way that
CPUs are cooled down sufficiently to avoid boot time slowdown caused by CPU
thermal throttling. The result is output in a tab-separated value format.

Examples:

Repeat measurements 10 times. Interval between iterations is adjusted based on
CPU temperature of the device.

$ ./perfboot.py --iterations=10

Repeat measurements 20 times. 60 seconds interval is taken between each
iteration.

$ ./perfboot.py --iterations=20 --interval=60

Repeat measurements 20 times, show verbose output, output the result to
data.tsv, and read event tags from eventtags.txt.

$ ./perfboot.py --iterations=30 -v --output=data.tsv --tags=eventtags.txt
"""

import argparse
import atexit
import cStringIO
import glob
import inspect
import logging
import math
import os
import re
import subprocess
import sys
import threading
import time

sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import adb

# The default event tags to record.
_DEFAULT_EVENT_TAGS = [
    'boot_progress_start',
    'boot_progress_preload_start',
    'boot_progress_preload_end',
    'boot_progress_system_run',
    'boot_progress_pms_start',
    'boot_progress_pms_system_scan_start',
    'boot_progress_pms_data_scan_start',
    'boot_progress_pms_scan_end',
    'boot_progress_pms_ready',
    'boot_progress_ams_ready',
    'boot_progress_enable_screen',
    'sf_stop_bootanim',
    'wm_boot_animation_done',
]


class IntervalAdjuster(object):
    """A helper class to take suffficient interval between iterations."""

    # CPU temperature values per product used to decide interval
    _CPU_COOL_DOWN_THRESHOLDS = {
        'flo': 40,
        'flounder': 40000,
        'razor': 40,
        'volantis': 40000,
    }
    # The interval between CPU temperature checks
    _CPU_COOL_DOWN_WAIT_INTERVAL = 10
    # The wait time used when the value of _CPU_COOL_DOWN_THRESHOLDS for
    # the product is not defined.
    _CPU_COOL_DOWN_WAIT_TIME_DEFAULT = 120

    def __init__(self, interval, device):
        self._interval = interval
        self._device = device
        self._temp_paths = device.shell(
            ['ls', '/sys/class/thermal/thermal_zone*/temp'])[0].splitlines()
        self._product = device.get_prop('ro.build.product')
        self._waited = False

    def wait(self):
        """Waits certain amount of time for CPUs cool-down."""
        if self._interval is None:
            self._wait_cpu_cool_down(self._product, self._temp_paths)
        else:
            if self._waited:
                print 'Waiting for %d seconds' % self._interval
                time.sleep(self._interval)
        self._waited = True

    def _get_cpu_temp(self, threshold):
        max_temp = 0
        for temp_path in self._temp_paths:
            temp = int(self._device.shell(['cat', temp_path])[0].rstrip())
            max_temp = max(max_temp, temp)
            if temp >= threshold:
                return temp
        return max_temp

    def _wait_cpu_cool_down(self, product, temp_paths):
        threshold = IntervalAdjuster._CPU_COOL_DOWN_THRESHOLDS.get(
            self._product)
        if threshold is None:
            print 'No CPU temperature threshold is set for ' + self._product
            print ('Just wait %d seconds' %
                   IntervalAdjuster._CPU_COOL_DOWN_WAIT_TIME_DEFAULT)
            time.sleep(IntervalAdjuster._CPU_COOL_DOWN_WAIT_TIME_DEFAULT)
            return
        while True:
            temp = self._get_cpu_temp(threshold)
            if temp < threshold:
                logging.info('Current CPU temperature %s' % temp)
                return
            print 'Waiting until CPU temperature (%d) falls below %d' % (
                temp, threshold)
            time.sleep(IntervalAdjuster._CPU_COOL_DOWN_WAIT_INTERVAL)


class WatchdogTimer(object):
    """A timer that makes is_timedout() return true in |timeout| seconds."""
    def __init__(self, timeout):
        self._timedout = False

        def notify_timeout():
            self._timedout = True
        self._timer = threading.Timer(timeout, notify_timeout)
        self._timer.daemon = True
        self._timer.start()

    def is_timedout(self):
        return self._timedout

    def cancel(self):
        self._timer.cancel()


def readlines_unbuffered(proc):
    """Read lines from |proc|'s standard out without buffering."""
    while True:
        buf = []
        c = proc.stdout.read(1)
        if c == '' and proc.poll() is not None:
            break
        while c != '\n':
            if c == '' and proc.poll() is not None:
                break
            buf.append(c)
            c = proc.stdout.read(1)
        yield ''.join(buf)


def disable_dropbox(device):
    """Removes the files created by Dropbox and avoids creating the files."""
    device.root()
    device.wait()
    device.shell(['rm', '-rf', '/system/data/dropbox'])
    original_dropbox_max_files = device.shell(
        ['settings', 'get', 'global', 'dropbox_max_files'])[0].rstrip()
    device.shell(['settings', 'put', 'global', 'dropbox_max_files', '0'])
    return original_dropbox_max_files


def restore_dropbox(device, original_dropbox_max_files):
    """Restores the dropbox_max_files setting."""
    device.root()
    device.wait()
    if original_dropbox_max_files == 'null':
        device.shell(['settings', 'delete', 'global', 'dropbox_max_files'])
    else:
        device.shell(['settings', 'put', 'global', 'dropbox_max_files',
                      original_dropbox_max_files])


def init_perf(device, output, record_list, tags):
    device.wait()
    debuggable = device.get_prop('ro.debuggable')
    original_dropbox_max_files = None
    if debuggable == '1':
        # Workaround for Dropbox issue (http://b/20890386).
        original_dropbox_max_files = disable_dropbox(device)

    def cleanup():
        try:
            if record_list:
                print_summary(record_list, tags[-1])
                output_results(output, record_list, tags)
            if original_dropbox_max_files is not None:
                restore_dropbox(device, original_dropbox_max_files)
        except (subprocess.CalledProcessError, RuntimeError):
            pass
    atexit.register(cleanup)


def check_dm_verity_settings(device):
    device.wait()
    for partition in ['system', 'vendor']:
        verity_mode = device.get_prop('partition.%s.verified' % partition)
        if verity_mode is None:
            logging.warning('dm-verity is not enabled for /%s. Did you run '
                            'adb disable-verity? That may skew the result.',
                            partition)


def read_event_tags(tags_file):
    """Reads event tags from |tags_file|."""
    if not tags_file:
        return _DEFAULT_EVENT_TAGS
    tags = []
    with open(tags_file) as f:
        for line in f:
            if '#' in line:
                line = line[:line.find('#')]
            line = line.strip()
            if line:
                tags.append(line)
    return tags


def make_event_tags_re(tags):
    """Makes a regular expression object that matches event logs of |tags|."""
    return re.compile(r'(?P<pid>[0-9]+) +[0-9]+ I (?P<tag>%s): (?P<time>\d+)' %
                      '|'.join(tags))


def filter_event_tags(tags, device):
    """Drop unknown tags not listed in device's event-log-tags file."""
    device.wait()
    supported_tags = set()
    for l in device.shell(
        ['cat', '/system/etc/event-log-tags'])[0].splitlines():
        tokens = l.split(' ')
        if len(tokens) >= 2:
            supported_tags.add(tokens[1])
    filtered = []
    for tag in tags:
        if tag in supported_tags:
            filtered.append(tag)
        else:
            logging.warning('Unknown tag \'%s\'. Ignoring...', tag)
    return filtered


def get_values(record, tag):
    """Gets values that matches |tag| from |record|."""
    keys = [key for key in record.keys() if key[0] == tag]
    return [record[k] for k in sorted(keys)]


def get_last_value(record, tag):
    """Gets the last value that matches |tag| from |record|."""
    values = get_values(record, tag)
    if not values:
        return 0
    return values[-1]


def output_results(filename, record_list, tags):
    """Outputs |record_list| into |filename| in a TSV format."""
    # First, count the number of the values of each tag.
    # This is for dealing with events that occur multiple times.
    # For instance, boot_progress_preload_start and boot_progress_preload_end
    # are recorded twice on 64-bit system. One is for 64-bit zygote process
    # and the other is for 32-bit zygote process.
    values_counter = {}
    for record in record_list:
        for tag in tags:
            # Some record might lack values for some tags due to unanticipated
            # problems (e.g. timeout), so take the maximum count among all the
            # record.
            values_counter[tag] = max(values_counter.get(tag, 1),
                                      len(get_values(record, tag)))

    # Then creates labels for the data. If there are multiple values for one
    # tag, labels for these values are numbered except the first one as
    # follows:
    #
    # event_tag event_tag2 event_tag3
    #
    # The corresponding values are sorted in an ascending order of PID.
    labels = []
    for tag in tags:
        for i in range(1, values_counter[tag] + 1):
            labels.append('%s%s' % (tag, '' if i == 1 else str(i)))

    # Finally write the data into the file.
    with open(filename, 'w') as f:
        f.write('\t'.join(labels) + '\n')
        for record in record_list:
            line = cStringIO.StringIO()
            invalid_line = False
            for i, tag in enumerate(tags):
                if i != 0:
                    line.write('\t')
                values = get_values(record, tag)
                if len(values) < values_counter[tag]:
                    invalid_line = True
                    # Fill invalid record with 0
                    values += [0] * (values_counter[tag] - len(values))
                line.write('\t'.join(str(t) for t in values))
            if invalid_line:
                logging.error('Invalid record found: ' + line.getvalue())
            line.write('\n')
            f.write(line.getvalue())
    print 'Wrote: ' + filename


def median(data):
    """Calculates the median value from |data|."""
    data = sorted(data)
    n = len(data)
    if n % 2 == 1:
        return data[n / 2]
    else:
        n2 = n / 2
        return (data[n2 - 1] + data[n2]) / 2.0


def mean(data):
    """Calculates the mean value from |data|."""
    return float(sum(data)) / len(data)


def stddev(data):
    """Calculates the standard deviation value from |value|."""
    m = mean(data)
    return math.sqrt(sum((x - m) ** 2 for x in data) / len(data))


def print_summary(record_list, end_tag):
    """Prints the summary of |record_list|."""
    # Filter out invalid data.
    end_times = [get_last_value(record, end_tag) for record in record_list
                 if get_last_value(record, end_tag) != 0]
    print 'mean: ', mean(end_times)
    print 'median:', median(end_times)
    print 'standard deviation:', stddev(end_times)


def do_iteration(device, interval_adjuster, event_tags_re, end_tag):
    """Measures the boot time once."""
    device.wait()
    interval_adjuster.wait()
    device.reboot()
    print 'Rebooted the device'
    record = {}
    booted = False
    while not booted:
        device.wait()
        # Stop the iteration if it does not finish within 120 seconds.
        timeout = 120
        t = WatchdogTimer(timeout)
        p = subprocess.Popen(
                ['adb', 'logcat', '-b', 'events', '-v', 'threadtime'],
                stdout=subprocess.PIPE)
        for line in readlines_unbuffered(p):
            if t.is_timedout():
                print '*** Timed out ***'
                return record
            m = event_tags_re.search(line)
            if not m:
                continue
            tag = m.group('tag')
            event_time = int(m.group('time'))
            pid = m.group('pid')
            record[(tag, pid)] = event_time
            print 'Event log recorded: %s (%s) - %d ms' % (
                tag, pid, event_time)
            if tag == end_tag:
                booted = True
                t.cancel()
                break
    return record


def parse_args():
    """Parses the command line arguments."""
    parser = argparse.ArgumentParser(
        description=inspect.getdoc(sys.modules[__name__]),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--iterations', type=int, default=5,
                        help='Number of times to repeat boot measurements.')
    parser.add_argument('--interval', type=int,
                        help=('Duration between iterations. If this is not '
                              'set explicitly, durations are determined '
                              'adaptively based on CPUs temperature.'))
    parser.add_argument('-o', '--output', help='File name of output data.')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show verbose output.')
    parser.add_argument('-s', '--serial', default=os.getenv('ANDROID_SERIAL'),
                        help='Adb device serial number.')
    parser.add_argument('-t', '--tags', help='Specify the filename from which '
                        'event tags are read. Every line contains one event '
                        'tag and the last event tag is used to detect that '
                        'the device has finished booting unless --end-tag is '
                        'specified.')
    parser.add_argument('--end-tag', help='An event tag on which the script '
                        'stops measuring the boot time.')
    parser.add_argument('--apk-dir', help='Specify the directory which contains '
                        'APK files to be installed before measuring boot time.')
    return parser.parse_args()


def install_apks(device, apk_dir):
    for apk in glob.glob(os.path.join(apk_dir, '*.apk')):
        print 'Installing: ' + apk
        device.install(apk, replace=True)


def main():
    args = parse_args()
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    device = adb.get_device(args.serial)

    if not args.output:
        device.wait()
        args.output = 'perf-%s-%s.tsv' % (
            device.get_prop('ro.build.flavor'),
            device.get_prop('ro.build.version.incremental'))
    check_dm_verity_settings(device)

    if args.apk_dir:
        install_apks(device, args.apk_dir)

    record_list = []
    event_tags = filter_event_tags(read_event_tags(args.tags), device)
    end_tag = args.end_tag or event_tags[-1]
    if end_tag not in event_tags:
        sys.exit('%s is not a valid tag.' % end_tag)
    event_tags = event_tags[0 : event_tags.index(end_tag) + 1]
    init_perf(device, args.output, record_list, event_tags)
    interval_adjuster = IntervalAdjuster(args.interval, device)
    event_tags_re = make_event_tags_re(event_tags)

    for i in range(args.iterations):
        print 'Run #%d ' % i
        record = do_iteration(
            device, interval_adjuster, event_tags_re, end_tag)
        record_list.append(record)


if __name__ == '__main__':
    main()
