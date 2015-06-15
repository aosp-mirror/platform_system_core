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

"""Compare two bootcharts and list start/end timestamps on key processes.

This script extracts two bootchart.tgz files and compares the timestamps
in proc_ps.log for selected processes. The proc_ps.log file consists of
repetitive blocks of the following format:

timestamp1 (jiffies)
dumps of /proc/<pid>/stat

timestamp2
dumps of /proc/<pid>/stat

The timestamps are 200ms apart, and the creation time of selected processes
are listed. The termination time of the boot animation process is also listed
as a coarse indication about when the boot process is complete as perceived by
the user.
"""

import sys
import tarfile

# The bootchart timestamps are 200ms apart, but the USER_HZ value is not
# reported in the bootchart, so we use the first two timestamps to calculate
# the wall clock time of a jiffy.
jiffy_to_wallclock = {
   '1st_timestamp': -1,
   '2nd_timestamp': -1,
   'jiffy_to_wallclock': -1
}

def analyze_process_maps(process_map1, process_map2, jiffy_record):
    # List interesting processes here
    processes_of_interest = [
        '/init',
        '/system/bin/surfaceflinger',
        '/system/bin/bootanimation',
        'zygote64',
        'zygote',
        'system_server'
    ]

    jw = jiffy_record['jiffy_to_wallclock']
    print "process: baseline experiment (delta)"
    print " - Unit is ms (a jiffy is %d ms on the system)" % jw
    print "------------------------------------"
    for p in processes_of_interest:
        # e.g., 32-bit system doesn't have zygote64
        if p in process_map1 and p in process_map2:
            print "%s: %d %d (%+d)" % (
                p, process_map1[p]['start_time'] * jw,
                process_map2[p]['start_time'] * jw,
                (process_map2[p]['start_time'] -
                 process_map1[p]['start_time']) * jw)

    # Print the last tick for the bootanimation process
    print "bootanimation ends at: %d %d (%+d)" % (
        process_map1['/system/bin/bootanimation']['last_tick'] * jw,
        process_map2['/system/bin/bootanimation']['last_tick'] * jw,
        (process_map2['/system/bin/bootanimation']['last_tick'] -
            process_map1['/system/bin/bootanimation']['last_tick']) * jw)

def parse_proc_file(pathname, process_map, jiffy_record=None):
    # Uncompress bootchart.tgz
    with tarfile.open(pathname + '/bootchart.tgz', 'r:*') as tf:
        try:
            # Read proc_ps.log
            f = tf.extractfile('proc_ps.log')

            # Break proc_ps into chunks based on timestamps
            blocks = f.read().split('\n\n')
            for b in blocks:
                lines = b.split('\n')
                if not lines[0]:
                    break

                # 200ms apart in jiffies
                timestamp = int(lines[0]);

                # Figure out the wall clock time of a jiffy
                if jiffy_record is not None:
                    if jiffy_record['1st_timestamp'] == -1:
                        jiffy_record['1st_timestamp'] = timestamp
                    elif jiffy_record['jiffy_to_wallclock'] == -1:
                        # Not really needed but for debugging purposes
                        jiffy_record['2nd_timestamp'] = timestamp
                        value = 200 / (timestamp -
                                       jiffy_record['1st_timestamp'])
                        # Fix the rounding error
                        # e.g., 201 jiffies in 200ms when USER_HZ is 1000
                        if value == 0:
                            value = 1
                        # e.g., 21 jiffies in 200ms when USER_HZ is 100
                        elif value == 9:
                            value = 10
                        jiffy_record['jiffy_to_wallclock'] = value

                # Populate the process_map table
                for line in lines[1:]:
                    segs = line.split(' ')

                    #  0: pid
                    #  1: process name
                    # 17: priority
                    # 18: nice
                    # 21: creation time

                    proc_name = segs[1].strip('()')
                    if proc_name in process_map:
                        process = process_map[proc_name]
                    else:
                        process = {'start_time': int(segs[21])}
                        process_map[proc_name] = process

                    process['last_tick'] = timestamp
        finally:
            f.close()

def main():
    if len(sys.argv) != 3:
        print "Usage: %s base_bootchart_dir exp_bootchart_dir" % sys.argv[0]
        sys.exit(1)

    process_map1 = {}
    process_map2 = {}
    parse_proc_file(sys.argv[1], process_map1, jiffy_to_wallclock)
    parse_proc_file(sys.argv[2], process_map2)
    analyze_process_maps(process_map1, process_map2, jiffy_to_wallclock)

if __name__ == "__main__":
    main()
