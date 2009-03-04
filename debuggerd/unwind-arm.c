/* ARM EABI compliant unwinding routines.
   Copyright (C) 2004, 2005 Free Software Foundation, Inc.
   Contributed by Paul Brook

   This file is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   In addition to the permissions in the GNU General Public License, the
   Free Software Foundation gives you unlimited permission to link the
   compiled version of this file into combinations with other programs,
   and to distribute those combinations without any restriction coming
   from the use of this file.  (The General Public License restrictions
   do apply in other respects; for example, they cover modification of
   the file, and distribution when not linked into a combine
   executable.)

   This file is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING.  If not, write to
   the Free Software Foundation, 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/****************************************************************************
 * The functions here are derived from gcc/config/arm/unwind-arm.c from the 
 * 4.3.x release. The main changes here involve the use of ptrace to retrieve
 * memory/processor states from a remote process.
 ****************************************************************************/

#include <cutils/logd.h>
#include <sys/ptrace.h>
#include <unwind.h>
#include "utility.h"

typedef struct _ZSt9type_info type_info; /* This names C++ type_info type */

void __attribute__((weak)) __cxa_call_unexpected(_Unwind_Control_Block *ucbp);
bool __attribute__((weak)) __cxa_begin_cleanup(_Unwind_Control_Block *ucbp);
bool __attribute__((weak)) __cxa_type_match(_Unwind_Control_Block *ucbp,
                        const type_info *rttip,
                        bool is_reference,
                        void **matched_object);

/* Misc constants.  */
#define R_IP	12
#define R_SP	13
#define R_LR	14
#define R_PC	15

#define EXIDX_CANTUNWIND 1
#define uint32_highbit (((_uw) 1) << 31)

#define UCB_FORCED_STOP_FN(ucbp) ((ucbp)->unwinder_cache.reserved1)
#define UCB_PR_ADDR(ucbp) ((ucbp)->unwinder_cache.reserved2)
#define UCB_SAVED_CALLSITE_ADDR(ucbp) ((ucbp)->unwinder_cache.reserved3)
#define UCB_FORCED_STOP_ARG(ucbp) ((ucbp)->unwinder_cache.reserved4)

struct core_regs
{
  _uw r[16];
};

/* We use normal integer types here to avoid the compiler generating
   coprocessor instructions.  */
struct vfp_regs
{
  _uw64 d[16];
  _uw pad;
};

struct vfpv3_regs
{
  /* Always populated via VSTM, so no need for the "pad" field from
     vfp_regs (which is used to store the format word for FSTMX).  */
  _uw64 d[16];
};

struct fpa_reg
{
  _uw w[3];
};

struct fpa_regs
{
  struct fpa_reg f[8];
};

struct wmmxd_regs
{
  _uw64 wd[16];
};

struct wmmxc_regs
{
  _uw wc[4];
};

/* Unwind descriptors.  */

typedef struct
{
  _uw16 length;
  _uw16 offset;
} EHT16;

typedef struct
{
  _uw length;
  _uw offset;
} EHT32;

/* The ABI specifies that the unwind routines may only use core registers,
   except when actually manipulating coprocessor state.  This allows
   us to write one implementation that works on all platforms by
   demand-saving coprocessor registers.

   During unwinding we hold the coprocessor state in the actual hardware
   registers and allocate demand-save areas for use during phase1
   unwinding.  */

typedef struct
{
  /* The first fields must be the same as a phase2_vrs.  */
  _uw demand_save_flags;
  struct core_regs core;
  _uw prev_sp; /* Only valid during forced unwinding.  */
  struct vfp_regs vfp;
  struct vfpv3_regs vfp_regs_16_to_31;
  struct fpa_regs fpa;
  struct wmmxd_regs wmmxd;
  struct wmmxc_regs wmmxc;
} phase1_vrs;

/* This must match the structure created by the assembly wrappers.  */
typedef struct
{
  _uw demand_save_flags;
  struct core_regs core;
} phase2_vrs;


/* An exception index table entry.  */

typedef struct __EIT_entry
{
  _uw fnoffset;
  _uw content;
} __EIT_entry;

/* Derived version to use ptrace */
typedef _Unwind_Reason_Code (*personality_routine_with_ptrace)
           (_Unwind_State,
			_Unwind_Control_Block *,
			_Unwind_Context *,
            pid_t);

/* Derived version to use ptrace */
/* ABI defined personality routines.  */
static _Unwind_Reason_Code unwind_cpp_pr0_with_ptrace (_Unwind_State,
    _Unwind_Control_Block *, _Unwind_Context *, pid_t);
static _Unwind_Reason_Code unwind_cpp_pr1_with_ptrace (_Unwind_State,
    _Unwind_Control_Block *, _Unwind_Context *, pid_t);
static _Unwind_Reason_Code unwind_cpp_pr2_with_ptrace (_Unwind_State,
    _Unwind_Control_Block *, _Unwind_Context *, pid_t);

/* Execute the unwinding instructions described by UWS.  */
extern _Unwind_Reason_Code
unwind_execute_with_ptrace(_Unwind_Context * context, __gnu_unwind_state * uws,
                           pid_t pid);

/* Derived version to use ptrace. Only handles core registers. Disregards
 * FP and others. 
 */
/* ABI defined function to pop registers off the stack.  */

_Unwind_VRS_Result unwind_VRS_Pop_with_ptrace (_Unwind_Context *context,
				    _Unwind_VRS_RegClass regclass,
				    _uw discriminator,
				    _Unwind_VRS_DataRepresentation representation,
                    pid_t pid)
{
  phase1_vrs *vrs = (phase1_vrs *) context;

  switch (regclass)
    {
    case _UVRSC_CORE:
      {
	_uw *ptr;
	_uw mask;
	int i;

	if (representation != _UVRSD_UINT32)
	  return _UVRSR_FAILED;

	mask = discriminator & 0xffff;
	ptr = (_uw *) vrs->core.r[R_SP];
	/* Pop the requested registers.  */
	for (i = 0; i < 16; i++)
	  {
	    if (mask & (1 << i)) {
	      vrs->core.r[i] = get_remote_word(pid, ptr);
          ptr++;
        }
	  }
	/* Writeback the stack pointer value if it wasn't restored.  */
	if ((mask & (1 << R_SP)) == 0)
	  vrs->core.r[R_SP] = (_uw) ptr;
      }
      return _UVRSR_OK;

    default:
      return _UVRSR_FAILED;
    }
}

/* Core unwinding functions.  */

/* Calculate the address encoded by a 31-bit self-relative offset at address
   P.  */
static inline _uw
selfrel_offset31 (const _uw *p, pid_t pid)
{
  _uw offset = get_remote_word(pid, (void*)p);

  //offset = *p;
  /* Sign extend to 32 bits.  */
  if (offset & (1 << 30))
    offset |= 1u << 31;
  else
    offset &= ~(1u << 31);

  return offset + (_uw) p;
}


/* Perform a binary search for RETURN_ADDRESS in TABLE.  The table contains
   NREC entries.  */

static const __EIT_entry *
search_EIT_table (const __EIT_entry * table, int nrec, _uw return_address,
                  pid_t pid)
{
  _uw next_fn;
  _uw this_fn;
  int n, left, right;

  if (nrec == 0)
    return (__EIT_entry *) 0;

  left = 0;
  right = nrec - 1;

  while (1)
    {
      n = (left + right) / 2;
      this_fn = selfrel_offset31 (&table[n].fnoffset, pid);
      if (n != nrec - 1)
	next_fn = selfrel_offset31 (&table[n + 1].fnoffset, pid) - 1;
      else
	next_fn = (_uw)0 - 1;

      if (return_address < this_fn)
	{
	  if (n == left)
	    return (__EIT_entry *) 0;
	  right = n - 1;
	}
      else if (return_address <= next_fn)
	return &table[n];
      else
	left = n + 1;
    }
}

/* Find the exception index table eintry for the given address. */
static const __EIT_entry*
get_eitp(_uw return_address, pid_t pid, mapinfo *map, mapinfo **containing_map)
{
  const __EIT_entry *eitp = NULL;
  int nrec;
  mapinfo *mi;
  
  /* The return address is the address of the instruction following the
     call instruction (plus one in thumb mode).  If this was the last
     instruction in the function the address will lie in the following
     function.  Subtract 2 from the address so that it points within the call
     instruction itself.  */
  if (return_address >= 2)
      return_address -= 2;

  for (mi = map; mi != NULL; mi = mi->next) {
    if (return_address >= mi->start && return_address <= mi->end) break;
  }

  if (mi) {
    if (containing_map) *containing_map = mi;
    eitp = (__EIT_entry *) mi->exidx_start;
    nrec = (mi->exidx_end - mi->exidx_start)/sizeof(__EIT_entry);
    eitp = search_EIT_table (eitp, nrec, return_address, pid);
  }
  return eitp;
}

/* Find the exception index table eintry for the given address.
   Fill in the relevant fields of the UCB.
   Returns _URC_FAILURE if an error occurred, _URC_OK on success.  */

static _Unwind_Reason_Code
get_eit_entry (_Unwind_Control_Block *ucbp, _uw return_address, pid_t pid, 
               mapinfo *map, mapinfo **containing_map)
{
  const __EIT_entry *eitp;
  
  eitp = get_eitp(return_address, pid, map, containing_map);

  if (!eitp)
    {
      UCB_PR_ADDR (ucbp) = 0;
      return _URC_FAILURE;
    }
  ucbp->pr_cache.fnstart = selfrel_offset31 (&eitp->fnoffset, pid);

  _uw eitp_content = get_remote_word(pid, (void *)&eitp->content);

  /* Can this frame be unwound at all?  */
  if (eitp_content == EXIDX_CANTUNWIND)
    {
      UCB_PR_ADDR (ucbp) = 0;
      return _URC_END_OF_STACK;
    }

  /* Obtain the address of the "real" __EHT_Header word.  */

  if (eitp_content & uint32_highbit)
    {
      /* It is immediate data.  */
      ucbp->pr_cache.ehtp = (_Unwind_EHT_Header *)&eitp->content;
      ucbp->pr_cache.additional = 1;
    }
  else
    {
      /* The low 31 bits of the content field are a self-relative
	 offset to an _Unwind_EHT_Entry structure.  */
      ucbp->pr_cache.ehtp =
	(_Unwind_EHT_Header *) selfrel_offset31 (&eitp->content, pid);
      ucbp->pr_cache.additional = 0;
    }

  /* Discover the personality routine address.  */
  if (get_remote_word(pid, ucbp->pr_cache.ehtp) & (1u << 31))
    {
      /* One of the predefined standard routines.  */
      _uw idx = (get_remote_word(pid, ucbp->pr_cache.ehtp) >> 24) & 0xf;
      if (idx == 0)
	UCB_PR_ADDR (ucbp) = (_uw) &unwind_cpp_pr0_with_ptrace;
      else if (idx == 1)
	UCB_PR_ADDR (ucbp) = (_uw) &unwind_cpp_pr1_with_ptrace;
      else if (idx == 2)
	UCB_PR_ADDR (ucbp) = (_uw) &unwind_cpp_pr2_with_ptrace;
      else
	{ /* Failed */
	  UCB_PR_ADDR (ucbp) = 0;
	  return _URC_FAILURE;
	}
    } 
  else
    {
      /* Execute region offset to PR */
      UCB_PR_ADDR (ucbp) = selfrel_offset31 (ucbp->pr_cache.ehtp, pid);
      /* Since we are unwinding the stack from a different process, it is
       * impossible to execute the personality routine in debuggerd. Punt here.
       */
	  return _URC_FAILURE;
    }
  return _URC_OK;
}

/* Print out the current call level, pc, and module name in the crash log */
static _Unwind_Reason_Code log_function(_Unwind_Context *context, pid_t pid, 
                                        int tfd,
                                        int stack_level,
                                        mapinfo *map,
                                        unsigned int sp_list[],
                                        bool at_fault)
{
    _uw pc;
    _uw rel_pc; 
    phase2_vrs *vrs = (phase2_vrs*) context;
    const mapinfo *mi;
    bool only_in_tombstone = !at_fault;

    if (stack_level < STACK_CONTENT_DEPTH) {
        sp_list[stack_level] = vrs->core.r[R_SP];
    }
    pc = vrs->core.r[R_PC];

    // Top level frame
    if (stack_level == 0) {
        pc &= ~1;
    }
    // For deeper framers, rollback pc by one instruction
    else {
        pc = vrs->core.r[R_PC];
        /* Thumb mode - need to check whether the bl(x) has long offset or not.
         * Examples:
         *
         * arm blx in the middle of thumb:
         * 187ae:       2300            movs    r3, #0
         * 187b0:       f7fe ee1c       blx     173ec
         * 187b4:       2c00            cmp     r4, #0
         *
         * arm bl in the middle of thumb:
         * 187d8:       1c20            adds    r0, r4, #0
         * 187da:       f136 fd15       bl      14f208
         * 187de:       2800            cmp     r0, #0
         *
         * pure thumb:
         * 18894:       189b            adds    r3, r3, r2
         * 18896:       4798            blx     r3
         * 18898:       b001            add     sp, #4
         */
        if (pc & 1) {
            _uw prev_word;
            pc = (pc & ~1);
            prev_word = get_remote_word(pid, (void *) pc-4);
            // Long offset 
            if ((prev_word & 0xf0000000) == 0xf0000000 && 
                (prev_word & 0x0000e000) == 0x0000e000) {
                pc -= 4;
            }
            else {
                pc -= 2;
            }
        }
        else { 
            pc -= 4;
        }
    }

    /* We used to print the absolute PC in the back trace, and mask out the top
     * 3 bits to guesstimate the offset in the .so file. This is not working for
     * non-prelinked libraries since the starting offset may not be aligned on 
     * 1MB boundaries, and the library may be larger than 1MB. So for .so 
     * addresses we print the relative offset in back trace.
     */
    rel_pc = pc;
    mi = pc_to_mapinfo(map, pc, &rel_pc);

    _LOG(tfd, only_in_tombstone, 
         "         #%02d  pc %08x  %s\n", stack_level, rel_pc, 
         mi ? mi->name : "");

    return _URC_NO_REASON;
}

/* Derived from __gnu_Unwind_Backtrace to use ptrace */
/* Perform stack backtrace through unwind data. Return the level of stack it
 * unwinds.
 */
int unwind_backtrace_with_ptrace(int tfd, pid_t pid, mapinfo *map, 
                                 unsigned int sp_list[], int *frame0_pc_sane,
                                 bool at_fault)
{
    phase1_vrs saved_vrs;
    _Unwind_Reason_Code code = _URC_OK;
    struct pt_regs r;
    int i;
    int stack_level = 0;

    _Unwind_Control_Block ucb;
    _Unwind_Control_Block *ucbp = &ucb;

    if(ptrace(PTRACE_GETREGS, pid, 0, &r)) return 0;

    for (i = 0; i < 16; i++) {
        saved_vrs.core.r[i] = r.uregs[i];
        /*
        _LOG(tfd, "r[%d] = 0x%x\n", i, saved_vrs.core.r[i]);
        */
    }

    /* Set demand-save flags.  */
    saved_vrs.demand_save_flags = ~(_uw) 0;

    /* 
     * If the app crashes because of calling the weeds, we cannot pass the PC 
     * to the usual unwinding code as the EXIDX mapping will fail. 
     * Instead, we simply print out the 0 as the top frame, and resume the 
     * unwinding process with the value stored in LR.
     */
    if (get_eitp(saved_vrs.core.r[R_PC], pid, map, NULL) == NULL) { 
        *frame0_pc_sane = 0;
        log_function ((_Unwind_Context *) &saved_vrs, pid, tfd, stack_level, 
                      map, sp_list, at_fault);
        saved_vrs.core.r[R_PC] = saved_vrs.core.r[R_LR];
        stack_level++;
    }

    do {
        mapinfo *this_map = NULL;
        /* Find the entry for this routine.  */
        if (get_eit_entry(ucbp, saved_vrs.core.r[R_PC], pid, map, &this_map)
            != _URC_OK) {
            /* Uncomment the code below to study why the unwinder failed */
#if 0
            /* Shed more debugging info for stack unwinder improvement */
            if (this_map) {
                _LOG(tfd, 1, 
                     "Relative PC=%#x from %s not contained in EXIDX\n", 
                     saved_vrs.core.r[R_PC] - this_map->start, this_map->name);
            }
            _LOG(tfd, 1, "PC=%#x SP=%#x\n", 
                 saved_vrs.core.r[R_PC], saved_vrs.core.r[R_SP]);
#endif
            code = _URC_FAILURE;
            break;
        }

        /* The dwarf unwinder assumes the context structure holds things
        like the function and LSDA pointers.  The ARM implementation
        caches these in the exception header (UCB).  To avoid
        rewriting everything we make the virtual IP register point at
        the UCB.  */
        _Unwind_SetGR((_Unwind_Context *)&saved_vrs, 12, (_Unwind_Ptr) ucbp);

        /* Call log function.  */
        if (log_function ((_Unwind_Context *) &saved_vrs, pid, tfd, stack_level,
                          map, sp_list, at_fault) != _URC_NO_REASON) {
            code = _URC_FAILURE;
            break;
        }
        stack_level++;

        /* Call the pr to decide what to do.  */
        code = ((personality_routine_with_ptrace) UCB_PR_ADDR (ucbp))(
                _US_VIRTUAL_UNWIND_FRAME | _US_FORCE_UNWIND, ucbp, 
                (void *) &saved_vrs, pid);
    /* 
     * In theory the unwinding process will stop when the end of stack is
     * reached or there is no unwinding information for the code address.
     * To add another level of guarantee that the unwinding process
     * will terminate we will stop it when the STACK_CONTENT_DEPTH is reached.
     */
    } while (code != _URC_END_OF_STACK && code != _URC_FAILURE && 
             stack_level < STACK_CONTENT_DEPTH);
    return stack_level;
}


/* Derived version to use ptrace */
/* Common implementation for ARM ABI defined personality routines.
   ID is the index of the personality routine, other arguments are as defined
   by __aeabi_unwind_cpp_pr{0,1,2}.  */

static _Unwind_Reason_Code
unwind_pr_common_with_ptrace (_Unwind_State state,
			_Unwind_Control_Block *ucbp,
			_Unwind_Context *context,
			int id,
            pid_t pid)
{
  __gnu_unwind_state uws;
  _uw *data;
  int phase2_call_unexpected_after_unwind = 0;

  state &= _US_ACTION_MASK;

  data = (_uw *) ucbp->pr_cache.ehtp;
  uws.data = get_remote_word(pid, data);
  data++;
  uws.next = data;
  if (id == 0)
    {
      uws.data <<= 8;
      uws.words_left = 0;
      uws.bytes_left = 3;
    }
  else
    {
      uws.words_left = (uws.data >> 16) & 0xff;
      uws.data <<= 16;
      uws.bytes_left = 2;
      data += uws.words_left;
    }

  /* Restore the saved pointer.  */
  if (state == _US_UNWIND_FRAME_RESUME)
    data = (_uw *) ucbp->cleanup_cache.bitpattern[0];

  if ((ucbp->pr_cache.additional & 1) == 0)
    {
      /* Process descriptors.  */
      while (get_remote_word(pid, data)) {
      /**********************************************************************
       * The original code here seems to deal with exceptions that are not
       * applicable in our toolchain, thus there is no way to test it for now.
       * Instead of leaving it here and causing potential instability in
       * debuggerd, we'd better punt here and leave the stack unwound.
       * In the future when we discover cases where the stack should be unwound
       * further but is not, we can revisit the code here.
       **********************************************************************/
        return _URC_FAILURE;
	  }
	  /* Finished processing this descriptor.  */
    }

  if (unwind_execute_with_ptrace (context, &uws, pid) != _URC_OK)
    return _URC_FAILURE;

  if (phase2_call_unexpected_after_unwind)
    {
      /* Enter __cxa_unexpected as if called from the call site.  */
      _Unwind_SetGR (context, R_LR, _Unwind_GetGR (context, R_PC));
      _Unwind_SetGR (context, R_PC, (_uw) &__cxa_call_unexpected);
      return _URC_INSTALL_CONTEXT;
    }

  return _URC_CONTINUE_UNWIND;
}


/* ABI defined personality routine entry points.  */

static _Unwind_Reason_Code
unwind_cpp_pr0_with_ptrace (_Unwind_State state,
			_Unwind_Control_Block *ucbp,
			_Unwind_Context *context,
            pid_t pid)
{
  return unwind_pr_common_with_ptrace (state, ucbp, context, 0, pid);
}

static _Unwind_Reason_Code
unwind_cpp_pr1_with_ptrace (_Unwind_State state,
			_Unwind_Control_Block *ucbp,
			_Unwind_Context *context,
            pid_t pid)
{
  return unwind_pr_common_with_ptrace (state, ucbp, context, 1, pid);
}

static _Unwind_Reason_Code
unwind_cpp_pr2_with_ptrace (_Unwind_State state,
			_Unwind_Control_Block *ucbp,
			_Unwind_Context *context,
            pid_t pid)
{
  return unwind_pr_common_with_ptrace (state, ucbp, context, 2, pid);
}
