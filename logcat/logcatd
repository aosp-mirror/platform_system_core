#! /system/bin/sh

# This is primarily meant to be used by logpersist.  This script is run as an init service, which
# first reads the 'last' logcat to persistent storage with `-L` then run logcat again without
# `-L` to read the current logcat buffers to persistent storage.

# init sets the umask to 077 for forked processes. logpersist needs to create files that are group
# readable. So relax the umask to only disallow group wx and world rwx.
umask 037

has_last="false"
for arg in "$@"; do
  if [ "$arg" == "-L" -o "$arg" == "--last" ]; then
    has_last="true"
  fi
done

if [ "$has_last" == "true" ]; then
  logcat "$@"
fi

args_without_last=()
for arg in "$@"; do
  if [ "$arg" != "-L" -a "$arg" != "--last" ]; then
    ARGS+=("$arg")
  fi
done

exec logcat "${ARGS[@]}"
