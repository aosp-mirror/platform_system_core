/* libs/cutils/strdup16to8.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <cutils/jstring.h>
#include <assert.h>
#include <stdlib.h>


/**
 * Given a UTF-16 string, compute the length of the corresponding UTF-8
 * string in bytes.
 */
extern size_t strnlen16to8(const char16_t* utf16Str, size_t len)
{
   size_t utf8Len = 0;

   while (len--) {
       unsigned int uic = *utf16Str++;

       if (uic > 0x07ff)
           utf8Len += 3;
       else if (uic > 0x7f || uic == 0)
           utf8Len += 2;
       else
           utf8Len++;
   }
   return utf8Len;
}


/**
 * Convert a Java-Style UTF-16 string + length to a JNI-Style UTF-8 string.
 *
 * This basically means: embedded \0's in the UTF-16 string are encoded
 * as "0xc0 0x80"
 *
 * Make sure you allocate "utf8Str" with the result of strlen16to8() + 1,
 * not just "len".
 * 
 * Please note, a terminated \0 is always added, so your result will always
 * be "strlen16to8() + 1" bytes long.
 */
extern char* strncpy16to8(char* utf8Str, const char16_t* utf16Str, size_t len)
{
    char* utf8cur = utf8Str;

    while (len--) {
        unsigned int uic = *utf16Str++;

        if (uic > 0x07ff) {
            *utf8cur++ = (uic >> 12) | 0xe0;
            *utf8cur++ = ((uic >> 6) & 0x3f) | 0x80;
            *utf8cur++ = (uic & 0x3f) | 0x80;
        } else if (uic > 0x7f || uic == 0) {
            *utf8cur++ = (uic >> 6) | 0xc0;
            *utf8cur++ = (uic & 0x3f) | 0x80;
        } else {
            *utf8cur++ = uic;

            if (uic == 0) {
                break;
            }           
        }       
    }

   *utf8cur = '\0';

   return utf8Str;
}

/**
 * Convert a UTF-16 string to UTF-8.
 *
 * Make sure you allocate "dest" with the result of strblen16to8(),
 * not just "strlen16()".
 */
char * strndup16to8 (const char16_t* s, size_t n)
{
    char *ret;

    if (s == NULL) {
        return NULL;
    }

    ret = malloc(strnlen16to8(s, n) + 1);

    strncpy16to8 (ret, s, n);
    
    return ret;    
}
