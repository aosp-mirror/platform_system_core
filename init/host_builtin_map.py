#!/usr/bin/env python
"""Generates the builtins map to be used by host_init_verifier.

It copies the builtin function map from builtins.cpp, then replaces do_xxx() functions with the
equivalent check_xxx() if found in check_builtins.cpp.

"""

import re
import argparse

parser = argparse.ArgumentParser('host_builtin_map.py')
parser.add_argument('--builtins', required=True, help='Path to builtins.cpp')
parser.add_argument('--check_builtins', required=True, help='Path to check_builtins.cpp')
args = parser.parse_args()

CHECK_REGEX = re.compile(r'.+check_(\S+)\(.+')
check_functions = []
with open(args.check_builtins) as check_file:
  for line in check_file:
    match = CHECK_REGEX.match(line)
    if match:
      check_functions.append(match.group(1))

function_map = []
with open(args.builtins) as builtins_file:
  in_function_map = False
  for line in builtins_file:
    if '// Builtin-function-map start' in line:
      in_function_map = True
    elif '// Builtin-function-map end' in line:
      in_function_map = False
    elif in_function_map:
      function_map.append(line)

DO_REGEX = re.compile(r'.+do_([^\}]+).+')
FUNCTION_REGEX = re.compile(r'(do_[^\}]+)')
for line in function_map:
  match = DO_REGEX.match(line)
  if match:
    if match.group(1) in check_functions:
      print line.replace('do_', 'check_'),
    else:
      print FUNCTION_REGEX.sub('check_stub', line),
  else:
    print line,
