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

#ifndef _INIT_INIT_PARSER_H_
#define _INIT_INIT_PARSER_H_

#define INIT_PARSER_MAXARGS 64

struct action;

struct action *action_remove_queue_head(void);
void action_add_queue_tail(struct action *act);
void action_for_each_trigger(const char *trigger,
                             void (*func)(struct action *act));
int action_queue_empty(void);
void queue_property_triggers(const char *name, const char *value);
void queue_all_property_triggers();
void queue_builtin_action(int (*func)(int nargs, char **args), char *name);

int init_parse_config_file(const char *fn);

#endif
