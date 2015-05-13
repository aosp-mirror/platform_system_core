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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ueventd.h"
#include "ueventd_parser.h"
#include "parser.h"
#include "log.h"
#include "util.h"

static list_declare(subsystem_list);

static void parse_line_device(struct parse_state *state, int nargs, char **args);

#define SECTION 0x01
#define OPTION  0x02

#include "ueventd_keywords.h"

#define KEYWORD(symbol, flags, nargs) \
    [ K_##symbol ] = { #symbol, nargs + 1, flags, },

static struct {
    const char *name;
    unsigned char nargs;
    unsigned char flags;
} keyword_info[KEYWORD_COUNT] = {
    [ K_UNKNOWN ] = { "unknown", 0, 0 },
#include "ueventd_keywords.h"
};
#undef KEYWORD

#define kw_is(kw, type) (keyword_info[kw].flags & (type))
#define kw_nargs(kw) (keyword_info[kw].nargs)

static int lookup_keyword(const char *s)
{
    switch (*s++) {
    case 'd':
        if (!strcmp(s, "evname")) return K_devname;
        if (!strcmp(s, "irname")) return K_dirname;
        break;
    case 's':
        if (!strcmp(s, "ubsystem")) return K_subsystem;
        break;
    }
    return K_UNKNOWN;
}

static void parse_line_no_op(struct parse_state*, int, char**) {
}

static int valid_name(const char *name)
{
    while (*name) {
        if (!isalnum(*name) && (*name != '_') && (*name != '-')) {
            return 0;
        }
        name++;
    }
    return 1;
}

struct ueventd_subsystem *ueventd_subsystem_find_by_name(const char *name)
{
    struct listnode *node;
    struct ueventd_subsystem *s;

    list_for_each(node, &subsystem_list) {
        s = node_to_item(node, struct ueventd_subsystem, slist);
        if (!strcmp(s->name, name)) {
            return s;
        }
    }
    return 0;
}

static void *parse_subsystem(parse_state* state, int /*nargs*/, char** args) {
    if (!valid_name(args[1])) {
        parse_error(state, "invalid subsystem name '%s'\n", args[1]);
        return 0;
    }

    ueventd_subsystem* s = ueventd_subsystem_find_by_name(args[1]);
    if (s) {
        parse_error(state, "ignored duplicate definition of subsystem '%s'\n",
                args[1]);
        return 0;
    }

    s = (ueventd_subsystem*) calloc(1, sizeof(*s));
    if (!s) {
        parse_error(state, "out of memory\n");
        return 0;
    }
    s->name = args[1];
    s->dirname = "/dev";
    list_add_tail(&subsystem_list, &s->slist);
    return s;
}

static void parse_line_subsystem(struct parse_state *state, int nargs,
        char **args)
{
    struct ueventd_subsystem *s = (ueventd_subsystem*) state->context;
    int kw;

    if (nargs == 0) {
        return;
    }

    kw = lookup_keyword(args[0]);
    switch (kw) {
    case K_devname:
        if (!strcmp(args[1], "uevent_devname"))
            s->devname_src = DEVNAME_UEVENT_DEVNAME;
        else if (!strcmp(args[1], "uevent_devpath"))
            s->devname_src = DEVNAME_UEVENT_DEVPATH;
        else
            parse_error(state, "invalid devname '%s'\n", args[1]);
        break;

    case K_dirname:
        if (args[1][0] == '/')
            s->dirname = args[1];
        else
            parse_error(state, "dirname '%s' does not start with '/'\n",
                    args[1]);
        break;

    default:
        parse_error(state, "invalid option '%s'\n", args[0]);
    }
}

static void parse_new_section(struct parse_state *state, int kw,
                       int nargs, char **args)
{
    printf("[ %s %s ]\n", args[0],
           nargs > 1 ? args[1] : "");

    switch(kw) {
    case K_subsystem:
        state->context = parse_subsystem(state, nargs, args);
        if (state->context) {
            state->parse_line = parse_line_subsystem;
            return;
        }
        break;
    }
    state->parse_line = parse_line_no_op;
}

static void parse_line(struct parse_state *state, char **args, int nargs)
{
    int kw = lookup_keyword(args[0]);
    int kw_nargs = kw_nargs(kw);

    if (nargs < kw_nargs) {
        parse_error(state, "%s requires %d %s\n", args[0], kw_nargs - 1,
            kw_nargs > 2 ? "arguments" : "argument");
        return;
    }

    if (kw_is(kw, SECTION)) {
        parse_new_section(state, kw, nargs, args);
    } else if (kw_is(kw, OPTION)) {
        state->parse_line(state, nargs, args);
    } else {
        parse_line_device(state, nargs, args);
    }
}

static void parse_config(const char *fn, const std::string& data)
{
    char *args[UEVENTD_PARSER_MAXARGS];

    int nargs = 0;
    parse_state state;
    state.filename = fn;
    state.line = 1;
    state.ptr = strdup(data.c_str());  // TODO: fix this code!
    state.nexttoken = 0;
    state.parse_line = parse_line_no_op;
    for (;;) {
        int token = next_token(&state);
        switch (token) {
        case T_EOF:
            parse_line(&state, args, nargs);
            return;
        case T_NEWLINE:
            if (nargs) {
                parse_line(&state, args, nargs);
                nargs = 0;
            }
            state.line++;
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
    std::string data;
    if (!read_file(fn, &data)) {
        return -1;
    }

    data.push_back('\n'); // TODO: fix parse_config.
    parse_config(fn, data);
    dump_parser_state();
    return 0;
}

static void parse_line_device(parse_state*, int nargs, char** args) {
    set_device_permission(nargs, args);
}
