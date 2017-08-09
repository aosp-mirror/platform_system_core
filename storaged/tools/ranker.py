# Copyright 2017 The Android Open Source Project
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

"""Parser and ranker for dumpsys storaged output.

This module parses output from dumpsys storaged by ranking uids based on
their io usage measured in 8 different stats. It must be provided the input
file through command line argument -i/--input.

For more details, see:
    $ python ranker.py -h

Example:
    $ python ranker.py -i io.txt -o output.txt -u 20 -cnt
"""

import argparse
import sys

IO_NAMES = ["[READ][FOREGROUND][CHARGER_OFF]",
            "[WRITE][FOREGROUND][CHARGER_OFF]",
            "[READ][BACKGROUND][CHARGER_OFF]",
            "[WRITE][BACKGROUND][CHARGER_OFF]",
            "[READ][FOREGROUND][CHARGER_ON]",
            "[WRITE][FOREGROUND][CHARGER_ON]",
            "[READ][BACKGROUND][CHARGER_ON]",
            "[WRITE][BACKGROUND][CHARGER_ON]"]


def get_args():
  """Get arguments from command line.

  The only required argument is input file.

  Returns:
    Args containing cmdline arguments
  """

  parser = argparse.ArgumentParser()
  parser.add_argument("-i", "--input", dest="input", required="true",
                      help="input io FILE, must provide", metavar="FILE")
  parser.add_argument("-o", "--output", dest="output", default="stdout",
                      help="output FILE, default to stdout", metavar="FILE")
  parser.add_argument("-u", "--uidcnt", dest="uidcnt", type=int, default=10,
                      help="set number of uids to display for each rank, "
                      "default 10")
  parser.add_argument("-c", "--combine", dest="combine", default=False,
                      action="store_true", help="add io stats for same uids, "
                      "default to take io stats of last appearing uids")
  parser.add_argument("-n", "--native", dest="native", default=False,
                      action="store_true", help="only include native apps in "
                      "ranking, default to include all apps")
  parser.add_argument("-t", "--task", dest="task", default=False,
                      action="store_true", help="display task io under uids, "
                      "default to not display tasks")
  return parser.parse_args()


def is_number(word):
  try:
    int(word)
    return True
  except ValueError:
    return False


def combine_or_filter(args):
  """Parser for io input.

  Either args.combine io stats for the same uids
  or take the io stats for the last uid and ignore
  the same uids before it.

  If task is required, store task ios along with uid
  for later display.

  Returns:
    The structure for the return value uids is as follows:
    uids: {uid -> [UID_STATS, TASK_STATS(optional)]}
    UID_STATS: [io1, io2, ..., io8]
    TASK_STATS: {task_name -> [io1, io2, ..., io8]}
  """
  fin = open(args.input, "r")
  uids = {}
  cur_uid = 0
  task_enabled = args.task
  for line in fin:
    words = line.split()
    if words[0] == "->":
      # task io
      if not task_enabled:
        continue
      # get task command line
      i = len(words) - 8
      task = " ".join(words[1:i])
      if task in uids[cur_uid][1]:
        task_io = uids[cur_uid][1][task]
        for j in range(8):
          task_io[j] += long(words[i+j])
      else:
        task_io = []
        for j in range(8):
          task_io.append(long(words[i+j]))
      uids[cur_uid][1][task] = task_io

    elif len(words) > 8:
      if not is_number(words[0]) and args.native:
        # uid not requested, ignore its tasks as well
        task_enabled = False
        continue
      task_enabled = args.task
      i = len(words) - 8
      uid = " ".join(words[:i])
      if uid in uids and args.combine:
        uid_io = uids[uid][0]
        for j in range(8):
          uid_io[j] += long(words[i+j])
        uids[uid][0] = uid_io
      else:
        uid_io = [long(words[i+j]) for j in range(8)]
        uids[uid] = [uid_io]
        if task_enabled:
          uids[uid].append({})
      cur_uid = uid

  return uids


def rank_uids(uids):
  """Sort uids based on eight different io stats.

  Returns:
    uid_rank is a 2d list of tuples:
    The first dimension represent the 8 different io stats.
    The second dimension is a sorted list of tuples by tup[0],
    each tuple is a uid's perticular stat at the first dimension and the uid.
  """
  uid_rank = [[(uids[uid][0][i], uid) for uid in uids] for i in range(8)]
  for i in range(8):
    uid_rank[i].sort(key=lambda tup: tup[0], reverse=True)
  return uid_rank


def display_uids(uid_rank, uids, args):
  """Display ranked uid io, along with task io if specified."""
  fout = sys.stdout
  if args.output != "stdout":
    fout = open(args.output, "w")

  for i in range(8):
    fout.write("RANKING BY " + IO_NAMES[i] + "\n")
    for j in range(min(args.uidcnt, len(uid_rank[0]))):
      uid = uid_rank[i][j][1]
      uid_stat = " ".join([str(uid_io) for uid_io in uids[uid][0]])
      fout.write(uid + " " + uid_stat + "\n")
      if args.task:
        for task in uids[uid][1]:
          task_stat = " ".join([str(task_io) for task_io in uids[uid][1][task]])
          fout.write("-> " + task + " " + task_stat + "\n")
      fout.write("\n")


def main():
  args = get_args()
  uids = combine_or_filter(args)
  uid_rank = rank_uids(uids)
  display_uids(uid_rank, uids, args)

if __name__ == "__main__":
  main()
