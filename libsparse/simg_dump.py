#! /usr/bin/env python

# Copyright (C) 2012 The Android Open Source Project
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

from __future__ import print_function
import getopt, posixpath, signal, struct, sys

def usage(argv0):
  print("""
Usage: %s [-v] sparse_image_file ...
 -v             verbose output
""" % ( argv0 ))
  sys.exit(2)

def main():

  signal.signal(signal.SIGPIPE, signal.SIG_DFL)

  me = posixpath.basename(sys.argv[0])

  # Parse the command line
  verbose = 0			# -v
  try:
    opts, args = getopt.getopt(sys.argv[1:],
                               "v",
                               ["verbose"])
  except getopt.GetoptError, e:
    print(e)
    usage(me)
  for o, a in opts:
    if o in ("-v", "--verbose"):
      verbose += 1
    else:
      print("Unrecognized option \"%s\"" % (o))
      usage(me)

  if len(args) == 0:
    print("No sparse_image_file specified")
    usage(me)

  for path in args:
    FH = open(path, 'rb')
    header_bin = FH.read(28)
    header = struct.unpack("<I4H4I", header_bin)

    magic = header[0]
    major_version = header[1]
    minor_version = header[2]
    file_hdr_sz = header[3]
    chunk_hdr_sz = header[4]
    blk_sz = header[5]
    total_blks = header[6]
    total_chunks = header[7]
    image_checksum = header[8]

    if magic != 0xED26FF3A:
      print("%s: %s: Magic should be 0xED26FF3A but is 0x%08X"
            % (me, path, magic))
      continue
    if major_version != 1 or minor_version != 0:
      print("%s: %s: I only know about version 1.0, but this is version %u.%u"
            % (me, path, major_version, minor_version))
      continue
    if file_hdr_sz != 28:
      print("%s: %s: The file header size was expected to be 28, but is %u."
            % (me, path, file_hdr_sz))
      continue
    if chunk_hdr_sz != 12:
      print("%s: %s: The chunk header size was expected to be 12, but is %u."
            % (me, path, chunk_hdr_sz))
      continue

    print("%s: Total of %u %u-byte output blocks in %u input chunks."
          % (path, total_blks, blk_sz, total_chunks))

    if image_checksum != 0:
      print("checksum=0x%08X" % (image_checksum))

    if not verbose:
      continue
    print("            input_bytes      output_blocks")
    print("chunk    offset     number  offset  number")
    offset = 0
    for i in xrange(1,total_chunks+1):
      header_bin = FH.read(12)
      header = struct.unpack("<2H2I", header_bin)
      chunk_type = header[0]
      reserved1 = header[1]
      chunk_sz = header[2]
      total_sz = header[3]
      data_sz = total_sz - 12

      print("%4u %10u %10u %7u %7u" % (i, FH.tell(), data_sz, offset, chunk_sz),
            end=" ")

      if chunk_type == 0xCAC1:
        if data_sz != (chunk_sz * blk_sz):
          print("Raw chunk input size (%u) does not match output size (%u)"
                % (data_sz, chunk_sz * blk_sz))
          break;
        else:
          print("Raw data", end="")
          FH.read(data_sz)
      elif chunk_type == 0xCAC2:
        if data_sz != 4:
          print("Fill chunk should have 4 bytes of fill, but this has %u"
                % (data_sz), end="")
          break;
        else:
          fill_bin = FH.read(4)
          fill = struct.unpack("<I", fill_bin)
          print("Fill with 0x%08X" % (fill))
      elif chunk_type == 0xCAC3:
        if data_sz != 0:
          print("Don't care chunk input size is non-zero (%u)" % (data_sz))
          break;
        else:
          print("Don't care", end="")
      elif chunk_type == 0xCAC4:
        if data_sz != 4:
          print("CRC32 chunk should have 4 bytes of CRC, but this has %u"
                % (data_sz), end="")
          break;
        else:
          crc_bin = FH.read(4)
          crc = struct.unpack("<I", crc)
          print("Unverified CRC32 0x%08X" % (crc))
      else:
          print("Unknown chunk type 0x%04X" % (chunk_type), end="")
          break;

      if verbose > 1:
        header = struct.unpack("<12B", header_bin)
        print(" (%02X%02X %02X%02X %02X%02X%02X%02X %02X%02X%02X%02X)"
              % (header[0], header[1], header[2], header[3],
                 header[4], header[5], header[6], header[7],
                 header[8], header[9], header[10], header[11]))
      else:
        print()

      offset += chunk_sz

    print("     %10u            %7u         End" % (FH.tell(), offset))

    if total_blks != offset:
      print("The header said we should have %u output blocks, but we saw %u"
            % (total_blks, offset))

    junk_len = len(FH.read())
    if junk_len:
      print("There were %u bytes of extra data at the end of the file."
            % (junk_len))

  sys.exit(0)

if __name__ == "__main__":
  main()
