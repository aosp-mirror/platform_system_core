#include <cutils/logd.h>
#include <sys/ptrace.h>
#include "../utility.h"
#include "x86_utility.h"


int unwind_backtrace_with_ptrace_x86(int tfd, pid_t pid, mapinfo *map,
                                 bool at_fault)
{
    struct pt_regs_x86 r;
    unsigned int stack_level = 0;
    unsigned int stack_depth = 0;
    unsigned int rel_pc;
    unsigned int stack_ptr;
    unsigned int stack_content;

    if(ptrace(PTRACE_GETREGS, pid, 0, &r)) return 0;
    unsigned int eip = (unsigned int)r.eip;
    unsigned int ebp = (unsigned int)r.ebp;
    unsigned int cur_sp = (unsigned int)r.esp;
    const mapinfo *mi;
    const struct symbol* sym = 0;


//ebp==0, it indicates that the stack is poped to the bottom or there is no stack at all.
    while (ebp) {
        _LOG(tfd, !at_fault, "#0%d ",stack_level);
        mi = pc_to_mapinfo(map, eip, &rel_pc);

        /* See if we can determine what symbol this stack frame resides in */
        if (mi != 0 && mi->symbols != 0) {
            sym = symbol_table_lookup(mi->symbols, rel_pc);
        }
        if (sym) {
            _LOG(tfd, !at_fault, "    eip: %08x  %s (%s)\n", eip, mi ? mi->name : "", sym->name);
        } else {
            _LOG(tfd, !at_fault, "    eip: %08x  %s\n", eip, mi ? mi->name : "");
        }

        stack_level++;
        if (stack_level >= STACK_DEPTH || eip == 0)
            break;
        eip = ptrace(PTRACE_PEEKTEXT, pid, (void*)(ebp + 4), NULL);
        ebp = ptrace(PTRACE_PEEKTEXT, pid, (void*)ebp, NULL);
    }
    ebp = (unsigned int)r.ebp;
    stack_depth = stack_level;
    stack_level = 0;
    if (ebp)
        _LOG(tfd, !at_fault, "stack: \n");
    while (ebp) {
        _LOG(tfd, !at_fault, "#0%d \n",stack_level);
        stack_ptr = cur_sp;
        while((int)(ebp - stack_ptr) >= 0) {
            stack_content = ptrace(PTRACE_PEEKTEXT, pid, (void*)stack_ptr, NULL);
            mi = pc_to_mapinfo(map, stack_content, &rel_pc);

            /* See if we can determine what symbol this stack frame resides in */
            if (mi != 0 && mi->symbols != 0) {
                sym = symbol_table_lookup(mi->symbols, rel_pc);
            }
            if (sym) {
                _LOG(tfd, !at_fault, "    %08x  %08x  %s (%s)\n",
                    stack_ptr, stack_content, mi ? mi->name : "", sym->name);
            } else {
                _LOG(tfd, !at_fault, "    %08x  %08x  %s\n", stack_ptr, stack_content, mi ? mi->name : "");
            }

            stack_ptr = stack_ptr + 4;
            //the stack frame may be very deep.
            if((int)(stack_ptr - cur_sp) >= STACK_FRAME_DEPTH) {
                _LOG(tfd, !at_fault, "    ......  ......  \n");
                break;
            }
        }
        cur_sp = ebp + 4;
        stack_level++;
        if (stack_level >= STACK_DEPTH || stack_level >= stack_depth)
            break;
        ebp = ptrace(PTRACE_PEEKTEXT, pid, (void*)ebp, NULL);
    }

    return stack_depth;
}

