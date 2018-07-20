'''
This is an example validator to be used with oem commands that allow you to
upload data afterwards that you wish to validate locally.
'''
import sys

def eprint(msg):
  '''
  A helper function for logging error messages to fuzzy_fastboot
  Use this function as you would "print()"
  '''
  sys.stderr.write(msg + '\n')


def main():
  '''
  Data is sent back to the parent fuzzy_fastboot process through the stderr pipe.

  If this script has a non-zero return code, anything written to STDERR is part of
  the error message that will logged by FF to explain why this validation failed.

  Feel free to print to to STDOUT with print() as usual to print info to console
  '''
  script, command, fname = sys.argv
  eprint("Messages here will go to the parent testers logs")
  eprint("Hello world")
  print("This goes to stdout as expected")
  with open(fname, "rb") as fd:
    # Do some validation on the buffer
    pass

  # non-zero return code signals error
  return -1


if __name__ == "__main__":
  sys.exit(main())
