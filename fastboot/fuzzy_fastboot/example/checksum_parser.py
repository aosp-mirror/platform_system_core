'''
Some bootloader's support hashing partitions. This is a great feature for testing
correctness. However, the format for the way the hash is returned depends on the
implementation. The hash could be send through an INFO response, or be as part
of the OKAY response itself. This script is called with the first argument
as the string mesage from the okay response. The second argument is each
info response joined by newlines into one argument.
'''

import sys


def main():
  '''
  Data is sent back to the parent fuzzy_fastboot process through the stderr pipe.
  There are two interpretations of this data by FF.

  0 return code:
    Anything written to STDERR will be interpreted as part of the hash.

  non-zero return code:
    Anything written to STDERR is part of the error message that will logged by FF
    to explain why hash extraction failed.

  Feel free to print to to STDOUT with print() as usual to print info to console
  '''
  script, response, info = sys.argv
  # the info responses are concated by newlines
  infos = [s.strip() for s in info.splitlines()]
  sys.stderr.write(infos[-1])
  print("Extracted checksum: '%s'" % infos[-1])
  # non-zero return code signals error
  return 0


if __name__ == "__main__":
  sys.exit(main())
