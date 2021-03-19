#!/usr/bin/env python3

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

"""
Write given number of random bytes, generated with optional seed.
"""

import random, argparse

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description=__doc__)
  parser.add_argument('--seed', help='Seed to random generator')
  parser.add_argument('--length', type=int, required=True, help='Length of output')
  args = parser.parse_args()

  if args.seed:
    random.seed(args.seed)

  print(''.join(chr(random.randrange(0,0xff)) for _ in range(args.length)))
