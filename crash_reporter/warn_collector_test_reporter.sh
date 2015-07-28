#! /bin/sh
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Replacement for the crash reporter, for testing.  Log the first line of the
# "warning" file, which by convention contains the warning hash, and remove the
# file.

set -e

exec 1>> warn-test-log
exec 2>> warn-test-log

head -1 warning
rm warning
