/* ARM EABI compliant unwinding routines
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
 * The functions here are derived from gcc/config/arm/pr-support.c from the 
 * 4.3.x release. The main changes here involve the use of ptrace to retrieve
 * memory/processor states from a remote process.
 ****************************************************************************/

#include <sys/types.h>
#include <unwind.h>

#include "utility.h"

/* We add a prototype for abort here to avoid creating a dependency on
   target headers.  */
extern void abort (void);

/* Derived from _Unwind_VRS_Pop to use ptrace */
extern _Unwind_VRS_Result 
unwind_VRS_Pop_with_ptrace (_Unwind_Context *context, 
                            _Unwind_VRS_RegClass regclass, 
                            _uw discriminator, 
                            _Unwind_VRS_DataRepresentation representation, 
                            pid_t pid);

typedef struct _ZSt9type_info type_info; /* This names C++ type_info type */

/* Misc constants.  */
#define R_IP    12
#define R_SP    13
#define R_LR    14
#define R_PC    15

#define uint32_highbit (((_uw) 1) << 31)

void __attribute__((weak)) __cxa_call_unexpected(_Unwind_Control_Block *ucbp);

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

/* Personality routine helper functions.  */

#define CODE_FINISH (0xb0)

/* Derived from next_unwind_byte to use ptrace */
/* Return the next byte of unwinding information, or CODE_FINISH if there is
   no data remaining.  */
static inline _uw8
next_unwind_byte_with_ptrace (__gnu_unwind_state * uws, pid_t pid)
{
  _uw8 b;

  if (uws->bytes_left == 0)
    {
      /* Load another word */
      if (uws->words_left == 0)
	return CODE_FINISH; /* Nothing left.  */
      uws->words_left--;
      uws->data = get_remote_word(pid, uws->next);
      uws->next++;
      uws->bytes_left = 3;
    }
  else
    uws->bytes_left--;

  /* Extract the most significant byte.  */
  b = (uws->data >> 24) & 0xff;
  uws->data <<= 8;
  return b;
}

/* Execute the unwinding instructions described by UWS.  */
_Unwind_Reason_Code
unwind_execute_with_ptrace(_Unwind_Context * context, __gnu_unwind_state * uws,
                           pid_t pid)
{
  _uw op;
  int set_pc;
  _uw reg;

  set_pc = 0;
  for (;;)
    {
      op = next_unwind_byte_with_ptrace (uws, pid);
      if (op == CODE_FINISH)
	{
	  /* If we haven't already set pc then copy it from lr.  */
	  if (!set_pc)
	    {
	      _Unwind_VRS_Get (context, _UVRSC_CORE, R_LR, _UVRSD_UINT32,
			       &reg);
	      _Unwind_VRS_Set (context, _UVRSC_CORE, R_PC, _UVRSD_UINT32,
			       &reg);
	      set_pc = 1;
	    }
	  /* Drop out of the loop.  */
	  break;
	}
      if ((op & 0x80) == 0)
	{
	  /* vsp = vsp +- (imm6 << 2 + 4).  */
	  _uw offset;

	  offset = ((op & 0x3f) << 2) + 4;
	  _Unwind_VRS_Get (context, _UVRSC_CORE, R_SP, _UVRSD_UINT32, &reg);
	  if (op & 0x40)
	    reg -= offset;
	  else
	    reg += offset;
	  _Unwind_VRS_Set (context, _UVRSC_CORE, R_SP, _UVRSD_UINT32, &reg);
	  continue;
	}
      
      if ((op & 0xf0) == 0x80)
	{
	  op = (op << 8) | next_unwind_byte_with_ptrace (uws, pid);
	  if (op == 0x8000)
	    {
	      /* Refuse to unwind.  */
	      return _URC_FAILURE;
	    }
	  /* Pop r4-r15 under mask.  */
	  op = (op << 4) & 0xfff0;
	  if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_CORE, op, _UVRSD_UINT32, 
                                      pid)
	      != _UVRSR_OK)
	    return _URC_FAILURE;
	  if (op & (1 << R_PC))
	    set_pc = 1;
	  continue;
	}
      if ((op & 0xf0) == 0x90)
	{
	  op &= 0xf;
	  if (op == 13 || op == 15)
	    /* Reserved.  */
	    return _URC_FAILURE;
	  /* vsp = r[nnnn].  */
	  _Unwind_VRS_Get (context, _UVRSC_CORE, op, _UVRSD_UINT32, &reg);
	  _Unwind_VRS_Set (context, _UVRSC_CORE, R_SP, _UVRSD_UINT32, &reg);
	  continue;
	}
      if ((op & 0xf0) == 0xa0)
	{
	  /* Pop r4-r[4+nnn], [lr].  */
	  _uw mask;
	  
	  mask = (0xff0 >> (7 - (op & 7))) & 0xff0;
	  if (op & 8)
	    mask |= (1 << R_LR);
	  if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_CORE, mask, _UVRSD_UINT32,
                                      pid)
	      != _UVRSR_OK)
	    return _URC_FAILURE;
	  continue;
	}
      if ((op & 0xf0) == 0xb0)
	{
	  /* op == 0xb0 already handled.  */
	  if (op == 0xb1)
	    {
	      op = next_unwind_byte_with_ptrace (uws, pid);
	      if (op == 0 || ((op & 0xf0) != 0))
		/* Spare.  */
		return _URC_FAILURE;
	      /* Pop r0-r4 under mask.  */
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_CORE, op, 
                                          _UVRSD_UINT32, pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  if (op == 0xb2)
	    {
	      /* vsp = vsp + 0x204 + (uleb128 << 2).  */
	      int shift;

	      _Unwind_VRS_Get (context, _UVRSC_CORE, R_SP, _UVRSD_UINT32,
			       &reg);
	      op = next_unwind_byte_with_ptrace (uws, pid);
	      shift = 2;
	      while (op & 0x80)
		{
		  reg += ((op & 0x7f) << shift);
		  shift += 7;
		  op = next_unwind_byte_with_ptrace (uws, pid);
		}
	      reg += ((op & 0x7f) << shift) + 0x204;
	      _Unwind_VRS_Set (context, _UVRSC_CORE, R_SP, _UVRSD_UINT32,
			       &reg);
	      continue;
	    }
	  if (op == 0xb3)
	    {
	      /* Pop VFP registers with fldmx.  */
	      op = next_unwind_byte_with_ptrace (uws, pid);
	      op = ((op & 0xf0) << 12) | ((op & 0xf) + 1);
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_VFP, op, _UVRSD_VFPX, 
                                          pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  if ((op & 0xfc) == 0xb4)
	    {
	      /* Pop FPA E[4]-E[4+nn].  */
	      op = 0x40000 | ((op & 3) + 1);
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_FPA, op, _UVRSD_FPAX, 
                                          pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  /* op & 0xf8 == 0xb8.  */
	  /* Pop VFP D[8]-D[8+nnn] with fldmx.  */
	  op = 0x80000 | ((op & 7) + 1);
	  if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_VFP, op, _UVRSD_VFPX, pid)
	      != _UVRSR_OK)
	    return _URC_FAILURE;
	  continue;
	}
      if ((op & 0xf0) == 0xc0)
	{
	  if (op == 0xc6)
	    {
	      /* Pop iWMMXt D registers.  */
	      op = next_unwind_byte_with_ptrace (uws, pid);
	      op = ((op & 0xf0) << 12) | ((op & 0xf) + 1);
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_WMMXD, op, 
                                          _UVRSD_UINT64, pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  if (op == 0xc7)
	    {
	      op = next_unwind_byte_with_ptrace (uws, pid);
	      if (op == 0 || (op & 0xf0) != 0)
		/* Spare.  */
		return _URC_FAILURE;
	      /* Pop iWMMXt wCGR{3,2,1,0} under mask.  */
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_WMMXC, op, 
                                          _UVRSD_UINT32, pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  if ((op & 0xf8) == 0xc0)
	    {
	      /* Pop iWMMXt wR[10]-wR[10+nnn].  */
	      op = 0xa0000 | ((op & 0xf) + 1);
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_WMMXD, op, 
                                          _UVRSD_UINT64, pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  if (op == 0xc8)
	    {
#ifndef __VFP_FP__
 	      /* Pop FPA registers.  */
 	      op = next_unwind_byte_with_ptrace (uws, pid);
	      op = ((op & 0xf0) << 12) | ((op & 0xf) + 1);
 	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_FPA, op, _UVRSD_FPAX,
                                          pid)
 		  != _UVRSR_OK)
 		return _URC_FAILURE;
 	      continue;
#else
              /* Pop VFPv3 registers D[16+ssss]-D[16+ssss+cccc] with vldm.  */
              op = next_unwind_byte_with_ptrace (uws, pid);
              op = (((op & 0xf0) + 16) << 12) | ((op & 0xf) + 1);
              if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_VFP, op, 
                                              _UVRSD_DOUBLE, pid)
                  != _UVRSR_OK)
                return _URC_FAILURE;
              continue;
#endif
	    }
	  if (op == 0xc9)
	    {
	      /* Pop VFP registers with fldmd.  */
	      op = next_unwind_byte_with_ptrace (uws, pid);
	      op = ((op & 0xf0) << 12) | ((op & 0xf) + 1);
	      if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_VFP, op, 
                                          _UVRSD_DOUBLE, pid)
		  != _UVRSR_OK)
		return _URC_FAILURE;
	      continue;
	    }
	  /* Spare.  */
	  return _URC_FAILURE;
	}
      if ((op & 0xf8) == 0xd0)
	{
	  /* Pop VFP D[8]-D[8+nnn] with fldmd.  */
	  op = 0x80000 | ((op & 7) + 1);
	  if (unwind_VRS_Pop_with_ptrace (context, _UVRSC_VFP, op, _UVRSD_DOUBLE, 
                                      pid)
	      != _UVRSR_OK)
	    return _URC_FAILURE;
	  continue;
	}
      /* Spare.  */
      return _URC_FAILURE;
    }
  return _URC_OK;
}
