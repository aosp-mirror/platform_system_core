/*
 * Copyright 2015, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <error.h>
#include <stdbool.h>
#include <stdlib.h>

#include <netutils/dhcp.h>
#include <netutils/ifc.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    error(EXIT_FAILURE, 0, "usage: %s INTERFACE", argv[0]);
  }

  char* interface = argv[1];
  if (ifc_init()) {
    error(EXIT_FAILURE, errno, "dhcptool %s: ifc_init failed", interface);
  }

  int rc = do_dhcp(interface);
  if (rc) {
    error(0, errno, "dhcptool %s: do_dhcp failed", interface);
  }

  ifc_close();

  return rc ? EXIT_FAILURE : EXIT_SUCCESS;
}
