/*
 * Copyright (C) 2010 The Android Open Source Project
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
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#include "ueventd_parser.h"
#include "parser.h"
#include "log.h"
#include "util.h"

static void parse_line_device(struct parse_state *state, int nargs, char **args);

static void parse_config(const char *fn, char *s)
{
    struct parse_state state;
    char *args[UEVENTD_PARSER_MAXARGS];
    int nargs;
    nargs = 0;
    state.filename = fn;
    state.line = 1;
    state.ptr = s;
    state.nexttoken = 0;
    state.parse_line = parse_line_device;
    for (;;) {
        int token = next_token(&state);
        switch (token) {
        case T_EOF:
            state.parse_line(&state, 0, 0);
            return;
        case T_NEWLINE:
            if (nargs) {
                state.parse_line(&state, nargs, args);
                nargs = 0;
            }
            break;
        case T_TEXT:
            if (nargs < UEVENTD_PARSER_MAXARGS) {
                args[nargs++] = state.text;
            }
            break;
        }
    }
}

int ueventd_parse_config_file(const char *fn)
{
    char *data;
    data = read_file(fn, 0);
    if (!data) return -1;

    parse_config(fn, data);
    DUMP();
    return 0;
}

static void parse_line_device(struct parse_state* state, int nargs, char **args)
{
    set_device_permission(nargs, args);
}
