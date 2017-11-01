/* $OpenBSD: getopt_long.c,v 1.26 2013/06/08 22:47:56 millert Exp $ */
/* $NetBSD: getopt_long.c,v 1.15 2002/01/31 22:43:40 tv Exp $       */

/*
 * Copyright (c) 2002 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */
/*-
 * Copyright (c) 2000 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by Dieter Baron and Thomas Klausner.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>

#include <log/getopt.h>

#define PRINT_ERROR ((context->opterr) && (*options != ':'))

#define FLAG_PERMUTE 0x01  // permute non-options to the end of argv
#define FLAG_ALLARGS 0x02  // treat non-options as args to option "-1"

// return values
#define BADCH (int)'?'
#define BADARG ((*options == ':') ? (int)':' : (int)'?')
#define INORDER (int)1

#define D_PREFIX 0
#define DD_PREFIX 1
#define W_PREFIX 2

// Compute the greatest common divisor of a and b.
static int gcd(int a, int b) {
    int c = a % b;
    while (c) {
        a = b;
        b = c;
        c = a % b;
    }
    return b;
}

// Exchange the block from nonopt_start to nonopt_end with the block from
// nonopt_end to opt_end (keeping the same order of arguments in each block).
// Returns optind - (nonopt_end - nonopt_start) for convenience.
static int permute_args(getopt_context* context, char* const* nargv) {
    // compute lengths of blocks and number and size of cycles
    int nnonopts = context->nonopt_end - context->nonopt_start;
    int nopts = context->optind - context->nonopt_end;
    int ncycle = gcd(nnonopts, nopts);
    int cyclelen = (context->optind - context->nonopt_start) / ncycle;

    for (int i = 0; i < ncycle; i++) {
        int cstart = context->nonopt_end + i;
        int pos = cstart;
        for (int j = 0; j < cyclelen; j++) {
            if (pos >= context->nonopt_end) {
                pos -= nnonopts;
            } else {
                pos += nopts;
            }
            char* swap = nargv[pos];
            const_cast<char**>(nargv)[pos] = nargv[cstart];
            const_cast<char**>(nargv)[cstart] = swap;
        }
    }
    return context->optind - (context->nonopt_end - context->nonopt_start);
}

// parse_long_options_r --
//    Parse long options in argc/argv argument vector.
// Returns -1 if short_too is set and the option does not match long_options.
static int parse_long_options_r(char* const* nargv, const char* options,
                                const struct option* long_options, int* idx,
                                bool short_too, struct getopt_context* context) {
    const char* current_argv = context->place;
    const char* current_dash;
    switch (context->dash_prefix) {
        case D_PREFIX:
            current_dash = "-";
            break;
        case DD_PREFIX:
            current_dash = "--";
            break;
        case W_PREFIX:
            current_dash = "-W ";
            break;
        default:
            current_dash = "";
            break;
    }
    context->optind++;

    const char* has_equal;
    size_t current_argv_len;
    if (!!(has_equal = strchr(current_argv, '='))) {
        // argument found (--option=arg)
        current_argv_len = has_equal - current_argv;
        has_equal++;
    } else {
        current_argv_len = strlen(current_argv);
    }

    int match = -1;
    bool exact_match = false;
    bool second_partial_match = false;
    for (int i = 0; long_options[i].name; i++) {
        // find matching long option
        if (strncmp(current_argv, long_options[i].name, current_argv_len)) {
            continue;
        }

        if (strlen(long_options[i].name) == current_argv_len) {
            // exact match
            match = i;
            exact_match = true;
            break;
        }
        // If this is a known short option, don't allow
        // a partial match of a single character.
        if (short_too && current_argv_len == 1) continue;

        if (match == -1) {  // first partial match
            match = i;
        } else if (long_options[i].has_arg != long_options[match].has_arg ||
                   long_options[i].flag != long_options[match].flag ||
                   long_options[i].val != long_options[match].val) {
            second_partial_match = true;
        }
    }
    if (!exact_match && second_partial_match) {
        // ambiguous abbreviation
        if (PRINT_ERROR) {
            fprintf(context->optstderr ?: stderr,
                    "option `%s%.*s' is ambiguous", current_dash,
                    (int)current_argv_len, current_argv);
        }
        context->optopt = 0;
        return BADCH;
    }
    if (match != -1) {  // option found
        if (long_options[match].has_arg == no_argument && has_equal) {
            if (PRINT_ERROR) {
                fprintf(context->optstderr ?: stderr,
                        "option `%s%.*s' doesn't allow an argument",
                        current_dash, (int)current_argv_len, current_argv);
            }
            // XXX: GNU sets optopt to val regardless of flag
            context->optopt =
                long_options[match].flag ? 0 : long_options[match].val;
            return BADCH;
        }
        if (long_options[match].has_arg == required_argument ||
            long_options[match].has_arg == optional_argument) {
            if (has_equal) {
                context->optarg = has_equal;
            } else if (long_options[match].has_arg == required_argument) {
                // optional argument doesn't use next nargv
                context->optarg = nargv[context->optind++];
            }
        }
        if ((long_options[match].has_arg == required_argument) &&
            !context->optarg) {
            // Missing argument; leading ':' indicates no error
            // should be generated.
            if (PRINT_ERROR) {
                fprintf(context->optstderr ?: stderr,
                        "option `%s%s' requires an argument", current_dash,
                        current_argv);
            }
            // XXX: GNU sets optopt to val regardless of flag
            context->optopt =
                long_options[match].flag ? 0 : long_options[match].val;
            context->optind--;
            return BADARG;
        }
    } else {  // unknown option
        if (short_too) {
            context->optind--;
            return -1;
        }
        if (PRINT_ERROR) {
            fprintf(context->optstderr ?: stderr, "unrecognized option `%s%s'",
                    current_dash, current_argv);
        }
        context->optopt = 0;
        return BADCH;
    }
    if (idx) *idx = match;
    if (long_options[match].flag) {
        *long_options[match].flag = long_options[match].val;
        return 0;
    }
    return long_options[match].val;
}

// getopt_long_r --
//    Parse argc/argv argument vector.
int getopt_long_r(int nargc, char* const* nargv, const char* options,
                  const struct option* long_options, int* idx,
                  struct getopt_context* context) {
    if (!options) return -1;

    // XXX Some GNU programs (like cvs) set optind to 0 instead of
    // XXX using optreset.  Work around this braindamage.
    if (!context->optind) context->optind = context->optreset = 1;

    // Disable GNU extensions if options string begins with a '+'.
    int flags = FLAG_PERMUTE;
    if (*options == '-') {
        flags |= FLAG_ALLARGS;
    } else if (*options == '+') {
        flags &= ~FLAG_PERMUTE;
    }
    if (*options == '+' || *options == '-') options++;

    context->optarg = nullptr;
    if (context->optreset) context->nonopt_start = context->nonopt_end = -1;
start:
    if (context->optreset || !*context->place) {  // update scanning pointer
        context->optreset = 0;
        if (context->optind >= nargc) {  // end of argument vector
            context->place = EMSG;
            if (context->nonopt_end != -1) {
                // do permutation, if we have to
                context->optind = permute_args(context, nargv);
            } else if (context->nonopt_start != -1) {
                // If we skipped non-options, set optind to the first of them.
                context->optind = context->nonopt_start;
            }
            context->nonopt_start = context->nonopt_end = -1;
            return -1;
        }
        if (*(context->place = nargv[context->optind]) != '-' ||
            context->place[1] == '\0') {
            context->place = EMSG;  // found non-option
            if (flags & FLAG_ALLARGS) {
                // GNU extension: return non-option as argument to option 1
                context->optarg = nargv[context->optind++];
                return INORDER;
            }
            if (!(flags & FLAG_PERMUTE)) {
                // If no permutation wanted, stop parsing at first non-option.
                return -1;
            }
            // do permutation
            if (context->nonopt_start == -1) {
                context->nonopt_start = context->optind;
            } else if (context->nonopt_end != -1) {
                context->nonopt_start = permute_args(context, nargv);
                context->nonopt_end = -1;
            }
            context->optind++;
            // process next argument
            goto start;
        }
        if (context->nonopt_start != -1 && context->nonopt_end == -1) {
            context->nonopt_end = context->optind;
        }

        // If we have "-" do nothing, if "--" we are done.
        if (context->place[1] != '\0' && *++(context->place) == '-' &&
            context->place[1] == '\0') {
            context->optind++;
            context->place = EMSG;
            // We found an option (--), so if we skipped
            // non-options, we have to permute.
            if (context->nonopt_end != -1) {
                context->optind = permute_args(context, nargv);
            }
            context->nonopt_start = context->nonopt_end = -1;
            return -1;
        }
    }

    int optchar;
    // Check long options if:
    //  1) we were passed some
    //  2) the arg is not just "-"
    //  3) either the arg starts with -- we are getopt_long_only()
    if (long_options && context->place != nargv[context->optind] &&
        (*context->place == '-')) {
        bool short_too = false;
        context->dash_prefix = D_PREFIX;
        if (*context->place == '-') {
            context->place++;  // --foo long option
            context->dash_prefix = DD_PREFIX;
        } else if (*context->place != ':' && strchr(options, *context->place)) {
            short_too = true;  // could be short option too
        }

        optchar = parse_long_options_r(nargv, options, long_options, idx,
                                       short_too, context);
        if (optchar != -1) {
            context->place = EMSG;
            return optchar;
        }
    }

    const char* oli;  // option letter list index
    if ((optchar = (int)*(context->place)++) == (int)':' ||
        (optchar == (int)'-' && *context->place != '\0') ||
        !(oli = strchr(options, optchar))) {
        // If the user specified "-" and  '-' isn't listed in
        // options, return -1 (non-option) as per POSIX.
        // Otherwise, it is an unknown option character (or ':').
        if (optchar == (int)'-' && *context->place == '\0') return -1;
        if (!*context->place) context->optind++;
        if (PRINT_ERROR) {
            fprintf(context->optstderr ?: stderr, "invalid option -- %c",
                    optchar);
        }
        context->optopt = optchar;
        return BADCH;
    }

    static const char recargchar[] = "option requires an argument -- %c";
    if (long_options && optchar == 'W' && oli[1] == ';') {
        // -W long-option
        if (*context->place) {                      // no space
            ;                                       // NOTHING
        } else if (++(context->optind) >= nargc) {  // no arg
            context->place = EMSG;
            if (PRINT_ERROR) {
                fprintf(context->optstderr ?: stderr, recargchar, optchar);
            }
            context->optopt = optchar;
            return BADARG;
        } else {  // white space
            context->place = nargv[context->optind];
        }
        context->dash_prefix = W_PREFIX;
        optchar = parse_long_options_r(nargv, options, long_options, idx, false,
                                       context);
        context->place = EMSG;
        return optchar;
    }
    if (*++oli != ':') {  // doesn't take argument
        if (!*context->place) context->optind++;
    } else {  // takes (optional) argument
        context->optarg = nullptr;
        if (*context->place) {  // no white space
            context->optarg = context->place;
        } else if (oli[1] != ':') {              // arg not optional
            if (++(context->optind) >= nargc) {  // no arg
                context->place = EMSG;
                if (PRINT_ERROR) {
                    fprintf(context->optstderr ?: stderr, recargchar, optchar);
                }
                context->optopt = optchar;
                return BADARG;
            }
            context->optarg = nargv[context->optind];
        }
        context->place = EMSG;
        context->optind++;
    }
    // dump back option letter
    return optchar;
}
