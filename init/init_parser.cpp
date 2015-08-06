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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "action.h"
#include "init.h"
#include "init_parser.h"
#include "log.h"
#include "parser.h"
#include "property_service.h"
#include "service.h"
#include "util.h"

#include <base/stringprintf.h>
#include <cutils/iosched_policy.h>
#include <cutils/list.h>

static list_declare(service_list);

struct import {
    struct listnode list;
    const char *filename;
};

static void *parse_service(struct parse_state *state, int nargs, char **args);
static void parse_line_service(struct parse_state *state, int nargs, char **args);

static void *parse_action(struct parse_state *state, int nargs, char **args);
static void parse_line_action(struct parse_state *state, int nargs, char **args);

#define SECTION 0x01
#define COMMAND 0x02
#define OPTION  0x04

#include "keywords.h"

#define KEYWORD(symbol, flags, nargs, func) \
    [ K_##symbol ] = { #symbol, func, nargs + 1, flags, },

static struct {
    const char *name;
    int (*func)(const std::vector<std::string>& args);
    size_t nargs;
    unsigned char flags;
} keyword_info[KEYWORD_COUNT] = {
    [ K_UNKNOWN ] = { "unknown", 0, 0, 0 },
#include "keywords.h"
};
#undef KEYWORD

#define kw_is(kw, type) (keyword_info[kw].flags & (type))
#define kw_name(kw) (keyword_info[kw].name)
#define kw_func(kw) (keyword_info[kw].func)
#define kw_nargs(kw) (keyword_info[kw].nargs)

void dump_parser_state() {
    ServiceManager::GetInstance().DumpState();
    ActionManager::GetInstance().DumpState();
}

static int lookup_keyword(const char *s)
{
    switch (*s++) {
    case 'b':
        if (!strcmp(s, "ootchart_init")) return K_bootchart_init;
        break;
    case 'c':
        if (!strcmp(s, "opy")) return K_copy;
        if (!strcmp(s, "lass")) return K_class;
        if (!strcmp(s, "lass_start")) return K_class_start;
        if (!strcmp(s, "lass_stop")) return K_class_stop;
        if (!strcmp(s, "lass_reset")) return K_class_reset;
        if (!strcmp(s, "onsole")) return K_console;
        if (!strcmp(s, "hown")) return K_chown;
        if (!strcmp(s, "hmod")) return K_chmod;
        if (!strcmp(s, "ritical")) return K_critical;
        break;
    case 'd':
        if (!strcmp(s, "isabled")) return K_disabled;
        if (!strcmp(s, "omainname")) return K_domainname;
        break;
    case 'e':
        if (!strcmp(s, "nable")) return K_enable;
        if (!strcmp(s, "xec")) return K_exec;
        if (!strcmp(s, "xport")) return K_export;
        break;
    case 'g':
        if (!strcmp(s, "roup")) return K_group;
        break;
    case 'h':
        if (!strcmp(s, "ostname")) return K_hostname;
        break;
    case 'i':
        if (!strcmp(s, "oprio")) return K_ioprio;
        if (!strcmp(s, "fup")) return K_ifup;
        if (!strcmp(s, "nsmod")) return K_insmod;
        if (!strcmp(s, "mport")) return K_import;
        if (!strcmp(s, "nstallkey")) return K_installkey;
        break;
    case 'k':
        if (!strcmp(s, "eycodes")) return K_keycodes;
        break;
    case 'l':
        if (!strcmp(s, "oglevel")) return K_loglevel;
        if (!strcmp(s, "oad_persist_props")) return K_load_persist_props;
        if (!strcmp(s, "oad_all_props")) return K_load_all_props;
        break;
    case 'm':
        if (!strcmp(s, "kdir")) return K_mkdir;
        if (!strcmp(s, "ount_all")) return K_mount_all;
        if (!strcmp(s, "ount")) return K_mount;
        break;
    case 'o':
        if (!strcmp(s, "n")) return K_on;
        if (!strcmp(s, "neshot")) return K_oneshot;
        if (!strcmp(s, "nrestart")) return K_onrestart;
        break;
    case 'p':
        if (!strcmp(s, "owerctl")) return K_powerctl;
        break;
    case 'r':
        if (!strcmp(s, "estart")) return K_restart;
        if (!strcmp(s, "estorecon")) return K_restorecon;
        if (!strcmp(s, "estorecon_recursive")) return K_restorecon_recursive;
        if (!strcmp(s, "mdir")) return K_rmdir;
        if (!strcmp(s, "m")) return K_rm;
        break;
    case 's':
        if (!strcmp(s, "eclabel")) return K_seclabel;
        if (!strcmp(s, "ervice")) return K_service;
        if (!strcmp(s, "etenv")) return K_setenv;
        if (!strcmp(s, "etprop")) return K_setprop;
        if (!strcmp(s, "etrlimit")) return K_setrlimit;
        if (!strcmp(s, "ocket")) return K_socket;
        if (!strcmp(s, "tart")) return K_start;
        if (!strcmp(s, "top")) return K_stop;
        if (!strcmp(s, "wapon_all")) return K_swapon_all;
        if (!strcmp(s, "ymlink")) return K_symlink;
        if (!strcmp(s, "ysclktz")) return K_sysclktz;
        break;
    case 't':
        if (!strcmp(s, "rigger")) return K_trigger;
        break;
    case 'u':
        if (!strcmp(s, "ser")) return K_user;
        break;
    case 'v':
        if (!strcmp(s, "erity_load_state")) return K_verity_load_state;
        if (!strcmp(s, "erity_update_state")) return K_verity_update_state;
        break;
    case 'w':
        if (!strcmp(s, "rite")) return K_write;
        if (!strcmp(s, "ritepid")) return K_writepid;
        if (!strcmp(s, "ait")) return K_wait;
        break;
    }
    return K_UNKNOWN;
}

static void parse_line_no_op(struct parse_state*, int, char**) {
}

int expand_props(const std::string& src, std::string* dst) {
    const char *src_ptr = src.c_str();

    if (!dst) {
        return -1;
    }

    /* - variables can either be $x.y or ${x.y}, in case they are only part
     *   of the string.
     * - will accept $$ as a literal $.
     * - no nested property expansion, i.e. ${foo.${bar}} is not supported,
     *   bad things will happen
     */
    while (*src_ptr) {
        const char *c;

        c = strchr(src_ptr, '$');
        if (!c) {
            dst->append(src_ptr);
            break;
        }

        dst->append(src_ptr, c);
        c++;

        if (*c == '$') {
            dst->push_back(*(c++));
            src_ptr = c;
            continue;
        } else if (*c == '\0') {
            break;
        }

        std::string prop_name;
        if (*c == '{') {
            c++;
            const char* end = strchr(c, '}');
            if (!end) {
                // failed to find closing brace, abort.
                ERROR("unexpected end of string in '%s', looking for }\n", src.c_str());
                goto err;
            }
            prop_name = std::string(c, end);
            c = end + 1;
        } else {
            prop_name = c;
            ERROR("using deprecated syntax for specifying property '%s', use ${name} instead\n",
                  c);
            c += prop_name.size();
        }

        if (prop_name.empty()) {
            ERROR("invalid zero-length prop name in '%s'\n", src.c_str());
            goto err;
        }

        std::string prop_val = property_get(prop_name.c_str());
        if (prop_val.empty()) {
            ERROR("property '%s' doesn't exist while expanding '%s'\n",
                  prop_name.c_str(), src.c_str());
            goto err;
        }

        dst->append(prop_val);
        src_ptr = c;
        continue;
    }

    return 0;
err:
    return -1;
}

static void parse_import(struct parse_state *state, int nargs, char **args)
{
    if (nargs != 2) {
        ERROR("single argument needed for import\n");
        return;
    }

    std::string conf_file;
    int ret = expand_props(args[1], &conf_file);
    if (ret) {
        ERROR("error while handling import on line '%d' in '%s'\n",
              state->line, state->filename);
        return;
    }

    struct import* import = (struct import*) calloc(1, sizeof(struct import));
    import->filename = strdup(conf_file.c_str());

    struct listnode *import_list = (listnode*) state->priv;
    list_add_tail(import_list, &import->list);
    INFO("Added '%s' to import list\n", import->filename);
}

static void parse_new_section(struct parse_state *state, int kw,
                       int nargs, char **args)
{
    printf("[ %s %s ]\n", args[0],
           nargs > 1 ? args[1] : "");
    switch(kw) {
    case K_service:
        state->context = parse_service(state, nargs, args);
        if (state->context) {
            state->parse_line = parse_line_service;
            return;
        }
        break;
    case K_on:
        state->context = parse_action(state, nargs, args);
        if (state->context) {
            state->parse_line = parse_line_action;
            return;
        }
        break;
    case K_import:
        parse_import(state, nargs, args);
        break;
    }
    state->parse_line = parse_line_no_op;
}

static void parse_config(const char *fn, const std::string& data)
{
    struct listnode import_list;
    struct listnode *node;
    char *args[INIT_PARSER_MAXARGS];

    int nargs = 0;

    //TODO: Use a parser with const input and remove this copy
    std::vector<char> data_copy(data.begin(), data.end());
    data_copy.push_back('\0');

    parse_state state;
    state.filename = fn;
    state.line = 0;
    state.ptr = &data_copy[0];
    state.nexttoken = 0;
    state.parse_line = parse_line_no_op;

    list_init(&import_list);
    state.priv = &import_list;

    for (;;) {
        switch (next_token(&state)) {
        case T_EOF:
            state.parse_line(&state, 0, 0);
            goto parser_done;
        case T_NEWLINE:
            state.line++;
            if (nargs) {
                int kw = lookup_keyword(args[0]);
                if (kw_is(kw, SECTION)) {
                    state.parse_line(&state, 0, 0);
                    parse_new_section(&state, kw, nargs, args);
                } else {
                    state.parse_line(&state, nargs, args);
                }
                nargs = 0;
            }
            break;
        case T_TEXT:
            if (nargs < INIT_PARSER_MAXARGS) {
                args[nargs++] = state.text;
            }
            break;
        }
    }

parser_done:
    list_for_each(node, &import_list) {
         struct import* import = node_to_item(node, struct import, list);
         if (!init_parse_config(import->filename)) {
             ERROR("could not import file '%s' from '%s': %s\n",
                   import->filename, fn, strerror(errno));
         }
    }
}

static bool init_parse_config_file(const char* path) {
    INFO("Parsing file %s...\n", path);
    Timer t;
    std::string data;
    if (!read_file(path, &data)) {
        return false;
    }

    data.push_back('\n'); // TODO: fix parse_config.
    parse_config(path, data);
    dump_parser_state();

    NOTICE("(Parsing %s took %.2fs.)\n", path, t.duration());
    return true;
}

static bool init_parse_config_dir(const char* path) {
    INFO("Parsing directory %s...\n", path);
    std::unique_ptr<DIR, int(*)(DIR*)> config_dir(opendir(path), closedir);
    if (!config_dir) {
        ERROR("Could not import directory '%s'\n", path);
        return false;
    }
    dirent* current_file;
    while ((current_file = readdir(config_dir.get()))) {
        std::string current_path =
            android::base::StringPrintf("%s/%s", path, current_file->d_name);
        // Ignore directories and only process regular files.
        if (current_file->d_type == DT_REG) {
            if (!init_parse_config_file(current_path.c_str())) {
                ERROR("could not import file '%s'\n", current_path.c_str());
            }
        }
    }
    return true;
}

bool init_parse_config(const char* path) {
    if (is_dir(path)) {
        return init_parse_config_dir(path);
    }
    return init_parse_config_file(path);
}

static void *parse_service(struct parse_state *state, int nargs, char **args)
{
    if (nargs < 3) {
        parse_error(state, "services must have a name and a program\n");
        return nullptr;
    }
    std::vector<std::string> str_args(args + 2, args + nargs);
    std::string ret_err;
    Service* svc = ServiceManager::GetInstance().AddNewService(args[1], "default",
                                                               str_args, &ret_err);

    if (!svc) {
        parse_error(state, "%s\n", ret_err.c_str());
    }

    return svc;
}

static void parse_line_service(struct parse_state *state, int nargs, char **args)
{
    if (nargs == 0) {
        return;
    }

    Service* svc = static_cast<Service*>(state->context);
    int kw = lookup_keyword(args[0]);
    std::vector<std::string> str_args(args, args + nargs);
    std::string ret_err;
    bool ret = svc->HandleLine(kw, str_args, &ret_err);

    if (!ret) {
        parse_error(state, "%s\n", ret_err.c_str());
    }
}

static void *parse_action(struct parse_state* state, int nargs, char **args)
{
    std::string ret_err;
    std::vector<std::string> triggers(args + 1, args + nargs);
    Action* ret = ActionManager::GetInstance().AddNewAction(triggers, &ret_err);

    if (!ret) {
        parse_error(state, "%s\n", ret_err.c_str());
    }

    return ret;
}

bool add_command_to_action(Action* action, const std::vector<std::string>& args,
                           const std::string& filename, int line, std::string* err)
{
    int kw;
    size_t n;

    kw = lookup_keyword(args[0].c_str());
    if (!kw_is(kw, COMMAND)) {
        *err = android::base::StringPrintf("invalid command '%s'\n", args[0].c_str());
        return false;
    }

    n = kw_nargs(kw);
    if (args.size() < n) {
        *err = android::base::StringPrintf("%s requires %zu %s\n",
                                           args[0].c_str(), n - 1,
                                           n > 2 ? "arguments" : "argument");
        return false;
    }

    action->AddCommand(kw_func(kw), args, filename, line);
    return true;
}

static void parse_line_action(struct parse_state* state, int nargs, char **args)
{
    if (nargs == 0) {
        return;
    }

    Action* action = static_cast<Action*>(state->context);
    std::vector<std::string> str_args(args, args + nargs);
    std::string ret_err;
    bool ret = add_command_to_action(action, str_args, state->filename,
                                     state->line, &ret_err);
    if (!ret) {
        parse_error(state, "%s\n", ret_err.c_str());
    }
}
