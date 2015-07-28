#!/bin/bash

# Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Builds tests.

set -e
make tests
mkdir -p "${OUT_DIR}"
cp *_test "${OUT_DIR}"
