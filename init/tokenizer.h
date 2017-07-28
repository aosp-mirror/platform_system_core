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

#ifndef _INIT_TOKENIZER_H_
#define _INIT_TOKENIZER_H_

#define T_EOF 0
#define T_TEXT 1
#define T_NEWLINE 2

namespace android {
namespace init {

struct parse_state
{
    char *ptr;
    char *text;
    int line;
    int nexttoken;
};

int next_token(struct parse_state *state);

}  // namespace init
}  // namespace android

#endif
