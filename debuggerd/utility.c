/* system/debuggerd/utility.c
**
** Copyright 2008, The Android Open Source Project
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

#include <signal.h>
#include <string.h>
#include <cutils/logd.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <corkscrew/demangle.h>

#include "utility.h"

#define STACK_DEPTH 32
#define STACK_WORDS 16

void _LOG(int tfd, bool in_tombstone_only, const char *fmt, ...) {
    char buf[512];

    va_list ap;
    va_start(ap, fmt);

    if (tfd >= 0) {
        int len;
        vsnprintf(buf, sizeof(buf), fmt, ap);
        len = strlen(buf);
        if(tfd >= 0) write(tfd, buf, len);
    }

    if (!in_tombstone_only)
        __android_log_vprint(ANDROID_LOG_INFO, "DEBUG", fmt, ap);
    va_end(ap);
}

bool signal_has_address(int sig) {
    switch (sig) {
        case SIGILL:
        case SIGFPE:
        case SIGSEGV:
        case SIGBUS:
            return true;
        default:
            return false;
    }
}

static void dump_backtrace(const ptrace_context_t* context __attribute((unused)),
        int tfd, pid_t tid __attribute((unused)), bool at_fault,
        const backtrace_frame_t* backtrace, size_t frames) {
    _LOG(tfd, !at_fault, "\nbacktrace:\n");

    backtrace_symbol_t backtrace_symbols[STACK_DEPTH];
    get_backtrace_symbols_ptrace(context, backtrace, frames, backtrace_symbols);
    for (size_t i = 0; i < frames; i++) {
        const backtrace_symbol_t* symbol = &backtrace_symbols[i];
        const char* map_name = symbol->map_name ? symbol->map_name : "<unknown>";
        const char* symbol_name = symbol->demangled_name ? symbol->demangled_name : symbol->name;
        if (symbol_name) {
            _LOG(tfd, !at_fault, "    #%02d  pc %08x  %s (%s)\n",
                    (int)i, symbol->relative_pc, map_name, symbol_name);
        } else {
            _LOG(tfd, !at_fault, "    #%02d  pc %08x  %s\n",
                    (int)i, symbol->relative_pc, map_name);
        }
    }
    free_backtrace_symbols(backtrace_symbols, frames);
}

static void dump_stack_segment(const ptrace_context_t* context, int tfd, pid_t tid,
        bool only_in_tombstone, uintptr_t* sp, size_t words, int label) {
    for (size_t i = 0; i < words; i++) {
        uint32_t stack_content;
        if (!try_get_word_ptrace(tid, *sp, &stack_content)) {
            break;
        }

        const map_info_t* mi;
        const symbol_t* symbol;
        find_symbol_ptrace(context, stack_content, &mi, &symbol);

        if (symbol) {
            char* demangled_name = demangle_symbol_name(symbol->name);
            const char* symbol_name = demangled_name ? demangled_name : symbol->name;
            if (!i && label >= 0) {
                _LOG(tfd, only_in_tombstone, "    #%02d  %08x  %08x  %s (%s)\n",
                        label, *sp, stack_content, mi ? mi->name : "", symbol_name);
            } else {
                _LOG(tfd, only_in_tombstone, "         %08x  %08x  %s (%s)\n",
                        *sp, stack_content, mi ? mi->name : "", symbol_name);
            }
            free(demangled_name);
        } else {
            if (!i && label >= 0) {
                _LOG(tfd, only_in_tombstone, "    #%02d  %08x  %08x  %s\n",
                        label, *sp, stack_content, mi ? mi->name : "");
            } else {
                _LOG(tfd, only_in_tombstone, "         %08x  %08x  %s\n",
                        *sp, stack_content, mi ? mi->name : "");
            }
        }

        *sp += sizeof(uint32_t);
    }
}

static void dump_stack(const ptrace_context_t* context, int tfd, pid_t tid, bool at_fault,
        const backtrace_frame_t* backtrace, size_t frames) {
    bool have_first = false;
    size_t first, last;
    for (size_t i = 0; i < frames; i++) {
        if (backtrace[i].stack_top) {
            if (!have_first) {
                have_first = true;
                first = i;
            }
            last = i;
        }
    }
    if (!have_first) {
        return;
    }

    _LOG(tfd, !at_fault, "\nstack:\n");

    // Dump a few words before the first frame.
    bool only_in_tombstone = !at_fault;
    uintptr_t sp = backtrace[first].stack_top - STACK_WORDS * sizeof(uint32_t);
    dump_stack_segment(context, tfd, tid, only_in_tombstone, &sp, STACK_WORDS, -1);

    // Dump a few words from all successive frames.
    // Only log the first 3 frames, put the rest in the tombstone.
    for (size_t i = first; i <= last; i++) {
        const backtrace_frame_t* frame = &backtrace[i];
        if (sp != frame->stack_top) {
            _LOG(tfd, only_in_tombstone, "         ........  ........\n");
            sp = frame->stack_top;
        }
        if (i - first == 3) {
            only_in_tombstone = true;
        }
        if (i == last) {
            dump_stack_segment(context, tfd, tid, only_in_tombstone, &sp, STACK_WORDS, i);
            if (sp < frame->stack_top + frame->stack_size) {
                _LOG(tfd, only_in_tombstone, "         ........  ........\n");
            }
        } else {
            size_t words = frame->stack_size / sizeof(uint32_t);
            if (words == 0) {
                words = 1;
            } else if (words > STACK_WORDS) {
                words = STACK_WORDS;
            }
            dump_stack_segment(context, tfd, tid, only_in_tombstone, &sp, words, i);
        }
    }
}

void dump_backtrace_and_stack(const ptrace_context_t* context, int tfd, pid_t tid,
        bool at_fault) {
    backtrace_frame_t backtrace[STACK_DEPTH];
    ssize_t frames = unwind_backtrace_ptrace(tid, context, backtrace, 0, STACK_DEPTH);
    if (frames > 0) {
        dump_backtrace(context, tfd, tid, at_fault, backtrace, frames);
        dump_stack(context, tfd, tid, at_fault, backtrace, frames);
    }
}

void dump_memory(int tfd, pid_t tid, uintptr_t addr, bool at_fault) {
    char code_buffer[64];       /* actual 8+1+((8+1)*4) + 1 == 45 */
    char ascii_buffer[32];      /* actual 16 + 1 == 17 */
    uintptr_t p, end;

    p = addr & ~3;
    p -= 32;
    if (p > addr) {
        /* catch underflow */
        p = 0;
    }
    end = p + 80;
    /* catch overflow; 'end - p' has to be multiples of 16 */
    while (end < p)
        end -= 16;

    /* Dump the code around PC as:
     *  addr     contents                             ascii
     *  00008d34 ef000000 e8bd0090 e1b00000 512fff1e  ............../Q
     *  00008d44 ea00b1f9 e92d0090 e3a070fc ef000000  ......-..p......
     */
    while (p < end) {
        char* asc_out = ascii_buffer;

        sprintf(code_buffer, "%08x ", p);

        int i;
        for (i = 0; i < 4; i++) {
            /*
             * If we see (data == -1 && errno != 0), we know that the ptrace
             * call failed, probably because we're dumping memory in an
             * unmapped or inaccessible page.  I don't know if there's
             * value in making that explicit in the output -- it likely
             * just complicates parsing and clarifies nothing for the
             * enlightened reader.
             */
            long data = ptrace(PTRACE_PEEKTEXT, tid, (void*)p, NULL);
            sprintf(code_buffer + strlen(code_buffer), "%08lx ", data);

            int j;
            for (j = 0; j < 4; j++) {
                /*
                 * Our isprint() allows high-ASCII characters that display
                 * differently (often badly) in different viewers, so we
                 * just use a simpler test.
                 */
                char val = (data >> (j*8)) & 0xff;
                if (val >= 0x20 && val < 0x7f) {
                    *asc_out++ = val;
                } else {
                    *asc_out++ = '.';
                }
            }
            p += 4;
        }
        *asc_out = '\0';
        _LOG(tfd, !at_fault, "    %s %s\n", code_buffer, ascii_buffer);
    }
}

void dump_nearby_maps(const ptrace_context_t* context, int tfd, pid_t tid) {
    siginfo_t si;
    memset(&si, 0, sizeof(si));
    if (ptrace(PTRACE_GETSIGINFO, tid, 0, &si)) {
        _LOG(tfd, false, "cannot get siginfo for %d: %s\n",
                tid, strerror(errno));
        return;
    }
    if (!signal_has_address(si.si_signo)) {
        return;
    }

    uintptr_t addr = (uintptr_t) si.si_addr;
    addr &= ~0xfff;     /* round to 4K page boundary */
    if (addr == 0) {    /* null-pointer deref */
        return;
    }

    _LOG(tfd, false, "\nmemory map around fault addr %08x:\n", (int)si.si_addr);

    /*
     * Search for a match, or for a hole where the match would be.  The list
     * is backward from the file content, so it starts at high addresses.
     */
    bool found = false;
    map_info_t* map = context->map_info_list;
    map_info_t *next = NULL;
    map_info_t *prev = NULL;
    while (map != NULL) {
        if (addr >= map->start && addr < map->end) {
            found = true;
            next = map->next;
            break;
        } else if (addr >= map->end) {
            /* map would be between "prev" and this entry */
            next = map;
            map = NULL;
            break;
        }

        prev = map;
        map = map->next;
    }

    /*
     * Show "next" then "match" then "prev" so that the addresses appear in
     * ascending order (like /proc/pid/maps).
     */
    if (next != NULL) {
        _LOG(tfd, false, "    %08x-%08x %s\n", next->start, next->end, next->name);
    } else {
        _LOG(tfd, false, "    (no map below)\n");
    }
    if (map != NULL) {
        _LOG(tfd, false, "    %08x-%08x %s\n", map->start, map->end, map->name);
    } else {
        _LOG(tfd, false, "    (no map for address)\n");
    }
    if (prev != NULL) {
        _LOG(tfd, false, "    %08x-%08x %s\n", prev->start, prev->end, prev->name);
    } else {
        _LOG(tfd, false, "    (no map above)\n");
    }
}
