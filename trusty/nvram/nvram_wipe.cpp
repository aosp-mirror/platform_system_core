/*
 * Copyright (C) 2016 The Android Open Source Project
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
#include <string.h>

#include <nvram/messages/nvram_messages.h>

#include "trusty_nvram_implementation.h"

void usage(const char* program_name) {
  fprintf(stderr, "Usage: %s [status|disable|wipe]\n", program_name);
  exit(-1);
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    usage(argv[0]);
  }

  nvram::TrustyNvramImplementation nvram_proxy;
  nvram::Request request;
  nvram::Response response;

  if (!strcmp(argv[1], "status")) {
    request.payload.Activate<nvram::COMMAND_GET_INFO>();
    nvram_proxy.Execute(request, &response);
    const nvram::GetInfoResponse* get_info_response =
        response.payload.get<nvram::COMMAND_GET_INFO>();
    if (response.result == NV_RESULT_SUCCESS) {
      int status = get_info_response && get_info_response->wipe_disabled;
      printf("Wiping disabled: %d\n", status);
      return status;
    }
  } else if (!strcmp(argv[1], "disable")) {
    request.payload.Activate<nvram::COMMAND_DISABLE_WIPE>();
    nvram_proxy.Execute(request, &response);
  } else if (!strcmp(argv[1], "wipe")) {
    request.payload.Activate<nvram::COMMAND_WIPE_STORAGE>();
    nvram_proxy.Execute(request, &response);
  } else {
    usage(argv[0]);
  }

  if (response.result != NV_RESULT_SUCCESS) {
    fprintf(stderr, "Command execution failure: %u\n", response.result);
    return -1;
  }

  return 0;
}

