/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <limits.h>
#include <assert.h>
#include <windows.h>

void get_my_path(char exe[PATH_MAX])
{
    char*  r;

    GetModuleFileName( NULL, exe, PATH_MAX-1 );
    exe[PATH_MAX-1] = 0;
    r = strrchr( exe, '\\' );
    if (r)
        *r = 0;
}

