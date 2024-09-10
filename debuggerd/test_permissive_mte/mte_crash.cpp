/*
 * Copyright (C) 2022 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>

int main(int, char**) {
  volatile char* f = (char*)malloc(1);
  printf("%c\n", f[17]);
#ifdef __aarch64__
  if (getenv("MTE_PERMISSIVE_REENABLE_TIME_CPUMS")) {
    // Burn some cycles because the MTE_PERMISSIVE_REENABLE_TIME_CPUMS is based on CPU clock.
    for (int i = 0; i < 1000000000; ++i) {
      asm("isb");
    }
    printf("%c\n", f[17]);
  }
#endif
  return 0;
}
