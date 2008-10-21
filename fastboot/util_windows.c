/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the 
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED 
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

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


void *load_file(const char *fn, unsigned *_sz)
{
    HANDLE    file;
    char     *data;
    DWORD     file_size;

    file = CreateFile( fn,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL );

    if (file == INVALID_HANDLE_VALUE)
        return NULL;

    file_size = GetFileSize( file, NULL );
    data      = NULL;

    if (file_size > 0) {
        data = (char*) malloc( file_size );
        if (data == NULL) {
            fprintf(stderr, "load_file: could not allocate %ld bytes\n", file_size );
            file_size = 0;
        } else {
            DWORD  out_bytes;

            if ( !ReadFile( file, data, file_size, &out_bytes, NULL ) ||
                 out_bytes != file_size )
            {
                fprintf(stderr, "load_file: could not read %ld bytes from '%s'\n", file_size, fn);
                free(data);
                data      = NULL;
                file_size = 0;
            }
        }
    }
    CloseHandle( file );

    *_sz = (unsigned) file_size;
    return  data;
}
