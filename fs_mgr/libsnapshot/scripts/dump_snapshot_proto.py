# Copyright (C) 2021 The Android Open Source Project
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

import argparse

from android.snapshot import snapshot_pb2

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('type', type = str, help = 'Type (snapshot or update)')
    parser.add_argument('file', type = str, help = 'Input file')
    args = parser.parse_args()

    with open(args.file, 'rb') as fp:
        data = fp.read()

    if args.type == 'snapshot':
        msg = snapshot_pb2.SnapshotStatus()
    elif args.type == 'update':
        msg = snapshot_pb2.SnapshotUpdateStatus()
    else:
        raise Exception('Unknown proto type')

    msg.ParseFromString(data)
    print(msg)

if __name__ == '__main__':
    main()
