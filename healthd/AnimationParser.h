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

#ifndef HEALTHD_ANIMATION_PARSER_H
#define HEALTHD_ANIMATION_PARSER_H

#include "animation.h"

namespace android {

bool parse_animation_desc(const std::string& content, animation* anim);

bool can_ignore_line(const char* str);
bool remove_prefix(const std::string& str, const char* prefix, const char** rest);
bool parse_text_field(const char* in, animation::text_field* field);
}  // namespace android

#endif // HEALTHD_ANIMATION_PARSER_H
