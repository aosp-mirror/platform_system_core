/*
 * Copyright (c) 2008, The Android Open Source Project
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
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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
#include <log/logd.h>
#include <ctype.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <cutils/sockets.h>
#include <unistd.h>

/*
 * Note: also accepts 0-9 priorities
 * returns ANDROID_LOG_UNKNOWN if the character is unrecognized
 */
static android_LogPriority filterCharToPri (char c)
{
    android_LogPriority pri;

    c = tolower(c);

    if (c >= '0' && c <= '9') {
        if (c >= ('0'+ANDROID_LOG_SILENT)) {
            pri = ANDROID_LOG_VERBOSE;
        } else {
            pri = (android_LogPriority)(c - '0');
        }
    } else if (c == 'v') {
        pri = ANDROID_LOG_VERBOSE;
    } else if (c == 'd') {
        pri = ANDROID_LOG_DEBUG;
    } else if (c == 'i') {
        pri = ANDROID_LOG_INFO;
    } else if (c == 'w') {
        pri = ANDROID_LOG_WARN;
    } else if (c == 'e') {
        pri = ANDROID_LOG_ERROR;
    } else if (c == 'f') {
        pri = ANDROID_LOG_FATAL;
    } else if (c == 's') {
        pri = ANDROID_LOG_SILENT;
    } else if (c == '*') {
        pri = ANDROID_LOG_DEFAULT;
    } else {
        pri = ANDROID_LOG_UNKNOWN;
    }

    return pri;
}

static int usage(const char *s)
{
    fprintf(stderr, "USAGE: %s [-p priorityChar] [-t tag] message\n", s);

    fprintf(stderr, "\tpriorityChar should be one of:\n"
                        "\t\tv,d,i,w,e\n");
    exit(-1);
}


int log_main(int argc, char *argv[])
{
    android_LogPriority priority; 
    const char *tag = "log";
    char buffer[4096];
    int i;

    priority = ANDROID_LOG_INFO;

    for (;;) {
        int ret;

        ret = getopt(argc, argv, "t:p:h");

        if (ret < 0) {
            break;
        }

        switch(ret) {
            case 't':
                tag = optarg;
            break;
            
            case 'p':
                priority = filterCharToPri(optarg[0]);
                if (priority == ANDROID_LOG_UNKNOWN) {
                    usage(argv[0]);                    
                }
            break;

            case 'h':
                usage(argv[0]);
            break;
        }
    }

    if (optind == argc) {
        usage(argv[0]);
    }

    buffer[0] = '\0';
    
    for (i = optind ; i < argc ; i++) {
        strlcat(buffer, argv[i], sizeof(buffer)-1);
        strlcat(buffer, " ", sizeof(buffer)-1);
    }

    if(buffer[0] == 0) {
        usage(argv[0]);
    }

    __android_log_print(priority, tag, "%s", buffer);

    return 0;
}

