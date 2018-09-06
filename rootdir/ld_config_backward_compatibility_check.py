#!/usr/bin/env python3
#
# Copyright (C) 2018 The Android Open Source Project
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
#

import glob
import os.path
import re
import sys

PREBUILTS_VNDK_DIR = "prebuilts/vndk"
VENDOR_DIRECTORIES = ('/vendor', '/odm')

def find_latest_vndk_snapshot_version():
  """Returns latest vndk snapshot version in current source tree.
  It will skip the test if the snapshot directories are not found.

  Returns:
    latest_version: string
  """
  vndk_dir_list = glob.glob(PREBUILTS_VNDK_DIR + "/v*")
  if not vndk_dir_list:
    """Exit without error because we may have source trees that do not include
    VNDK snapshot directories in it.
    """
    sys.exit(0)
  vndk_ver_list = [re.match(r".*/v(\d+)", vndk_dir).group(1)
                                          for vndk_dir in vndk_dir_list]
  latest_version = max(vndk_ver_list)
  if latest_version == '27':
    """Exit without error because VNDK v27 is not using ld.config.txt template
    """
    sys.exit(0)
  return latest_version

def get_vendor_configuration(ld_config_file):
  """Reads the ld.config.txt file to parse the namespace configurations.
  It finds the configurations that include vendor directories.

  Args:
    ld_config_file: string, path (relative to build top) of the ld.config.txt
                    file.
  Returns:
    configs: dict{string:[string]}, dictionary of namespace configurations.
             it has 'section + property' names as keys and the directory list
             as values.
  """
  try:
    conf_file = open(ld_config_file)
  except IOError:
    print("error: could not read %s" % ld_config_file)
    sys.exit(1)

  configs = dict()
  current_section = None

  with conf_file:
    for line in conf_file:
      # ignore comments
      found = line.find('#')
      if found != -1:
        line = line[:found]
      line = line.strip()
      if not line:
        continue

      if line[0] == '[' and line[-1] == ']':
        # new section started
        current_section = line[1:-1]
        continue

      if current_section == None:
        continue

      found = line.find('+=')
      opr_len = 2
      if found == -1:
        found = line.find('=')
        opr_len = 1
      if found == -1:
        continue

      namespace = line[:found].strip()
      if not namespace.endswith(".paths"):
        # check ".paths" only
        continue
      namespace = '[' + current_section + ']' + namespace
      values = line[found + opr_len:].strip()
      directories = values.split(':')

      for directory in directories:
        if any(vendor_dir in directory for vendor_dir in VENDOR_DIRECTORIES):
          if namespace in configs:
            configs[namespace].append(directory)
          else:
            configs[namespace] = [directory]

  return configs

def get_snapshot_config(version):
  """Finds the ld.config.{version}.txt file from the VNDK snapshot directory.
  In the vndk prebuilt directory (prebuilts/vndk/v{version}), it searches
  {arch}/configs/ld.config.{version}.txt file, where {arch} is one of ('arm64',
  'arm', 'x86_64', 'x86').

  Args:
    version: string, the VNDK snapshot version to search.
  Returns:
    ld_config_file: string, relative path to ld.config.{version}.txt
  """
  arch_list = ('arm64', 'arm', 'x86_64', 'x86')
  for arch in arch_list:
    ld_config_file = (PREBUILTS_VNDK_DIR
                + "/v{0}/{1}/configs/ld.config.{0}.txt".format(version, arch))
    if os.path.isfile(ld_config_file):
      return ld_config_file
  print("error: cannot find ld.config.{0}.txt file in snapshot v{0}"
                                                        .format(version))
  sys.exit(1)

def check_backward_compatibility(ld_config, vndk_snapshot_version):
  """Checks backward compatibility for current ld.config.txt file with the
  old ld.config.txt file. If any of the vendor directories in the old namespace
  configurations are missing, the test will fail. It is allowed to have new
  vendor directories in current ld.config.txt file.

  Args:
    ld_config: string, relative path to current ld.config.txt file.
    vndk_snapshot_version: string, the VNDK snapshot version that has an old
                           ld.config.txt file to compare.
  Returns:
    result: bool, True if the current configuration is backward compatible.
  """
  current_config = get_vendor_configuration(ld_config)
  old_config = get_vendor_configuration(
                                get_snapshot_config(vndk_snapshot_version))
  for namespace in old_config:
    if namespace not in current_config:
      print("error: cannot find %s which was provided in ld.config.%s.txt"
                                        % (namespace, vndk_snapshot_version))
      return False
    for path in old_config[namespace]:
      if not path in current_config[namespace]:
        print("error: %s for %s in ld.config.%s.txt are missing in %s"
                % (path, namespace, vndk_snapshot_version, ld_config))
        return False
  return True

def main():
  if len(sys.argv) != 2:
    print ("Usage: %s target_ld_config_txt_file_name" % sys.argv[0])
    sys.exit(1)

  latest_vndk_snapshot_version = find_latest_vndk_snapshot_version()
  if not check_backward_compatibility(sys.argv[1],
                                          latest_vndk_snapshot_version):
    print("error: %s has backward incompatible changes to old "
          "vendor partition." % sys.argv[1])
    sys.exit(1)

  # Current ld.config.txt file is backward compatible
  sys.exit(0)

if __name__ == '__main__':
  main()
