# cli-test

## What?

`cli-test` makes integration testing of command-line tools easier.

## Goals

* Readable syntax. Common cases should be concise, and pretty much anyone
  should be able to read tests even if they've never seen this tool before.

* Minimal issues with quoting. The toybox tests -- being shell scripts --
  quickly become a nightmare of quoting. Using a non ad hoc format (such as
  JSON) would have introduced similar but different quoting issues. A custom
  format, while annoying, side-steps this.

* Sensible defaults. We expect your exit status to be 0 unless you say
  otherwise. We expect nothing on stderr unless you say otherwise. And so on.

* Convention over configuration. Related to sensible defaults, we don't let you
  configure things that aren't absolutely necessary. So you can't keep your test
  data anywhere except in the `files/` subdirectory of the directory containing
  your test, for example.

## Non Goals

* Portability. Just being able to run on Linux (host and device) is sufficient
  for our needs. macOS is probably easy enough if we ever need it, but Windows
  probably doesn't make sense.

## Syntax

Any all-whitespace line, or line starting with `#` is ignored.

A test looks like this:
```
name: unzip -l
command: unzip -l $FILES/example.zip d1/d2/x.txt
after: [ ! -f d1/d2/x.txt ]
expected-stdout:
	Archive:  $FILES/example.zip
	  Length      Date    Time    Name
	---------  ---------- -----   ----
	     1024  2017-06-04 08:45   d1/d2/x.txt
	---------                     -------
	     1024                     1 file
---
```

The `name:` line names the test, and is only for human consumption.

The `command:` line is the command to be run. Additional commands can be
supplied as zero or more `before:` lines (run before `command:`) and zero or
more `after:` lines (run after `command:`). These are useful for both
setup/teardown but also for testing post conditions (as in the example above).

Any `command:`, `before:`, or `after:` line is expected to exit with status 0.
Anything else is considered a test failure.

The `expected-stdout:` line is followed by zero or more tab-prefixed lines that
are otherwise the exact output expected from the command. (There's magic behind
the scenes to rewrite the test files directory to `$FILES` because otherwise any
path in the output would depend on the temporary directory used to run the test.)

There is currently no `expected-stderr:` line. Standard error is implicitly
expected to be empty, and any output will cause a test failure. (The support is
there, but not wired up because we haven't needed it yet.)

The fields can appear in any order, but every test must contain at least a
`name:` line and a `command:` line.

## Output

The output is intended to resemble gtest.

## Future Directions

* It's often useful to be able to *match* against stdout/stderr/a file rather
  than give exact expected output. We might want to add explicit support for
  this. In the meantime, it's possible to use an `after:` with `grep -q` if
  you redirect in your `command:`.

* In addition to using a `before:` (which will fail a test), it can be useful
  to be able to specify tests that would cause us to *skip* a test. An example
  would be "am I running as root?".

* It might be useful to be able to make exit status assertions other than 0?

* There's currently no way (other than the `files/` directory) to share repeated
  setup between tests.
