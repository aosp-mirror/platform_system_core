/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * Test driver for the warn_collector daemon.
 */
#include <stdlib.h>

int main(int ac, char **av)
{
  return system("$SRC/warn_collector_test.sh");
}
