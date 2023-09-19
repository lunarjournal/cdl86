/**
 * @file cdl.h
 * @brief cdl86 (Compact Detour Library) - cdl.h
 *
 * Experimental Linux & Windows x86_64 detour library.
 *
 * Copyright (c) 2022 (Dylan Muller)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CDL_H
#define CDL_H

#define _GNU_SOURCE

/* Global includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <signal.h>
#include <ucontext.h>
#endif

#define __in
#define __out
#define __in_out

/* Determine CPU type */
/* Check MSVC */
#if _WIN32 || _WIN64
#if _WIN64
#define ENV_64
#else
#define ENV_32
#endif
#else
/* Check other compilers */
#if __x86_64__
#define ENV_64
#else
#define ENV_32
#endif
#endif

/* Set ARCH flags */
#ifdef ENV_64
#define REG_IP REG_RIP
#define BYTES_JMP_PATCH 12
#define PTR_SIZE PRIx64
#else
#define REG_IP REG_EIP
#define BYTES_JMP_PATCH 5
#define PTR_SIZE PRIx32
#endif

/* Define SW BP patch length, see (cdl_gen_swbp) */
#define BYTES_SWBP_PATCH 1

/* General : reserve bytes */
#define BYTES_RESERVE_MAX 20

/**
 * Intruction probe struct
 *
 * @param size size of instruction (bytes)
 * @param bytes byte array of instruction (uint8_t*)
 */
struct cdl_ins_probe
{
    int size;
    uint8_t* bytes;
};

/**
 * JMP patch info struct
 *
 * @param active is patch active (bool)
 * @param nt_alloc number of bytes allocated to trampoline (int)
 * @param code instructions replaced by JMP patch (uint8_t*)
 * @param target pointer to function pointer (uint8_t**)
 * @param origin pointer to origin(real) target address (uint8_t*)
 * @param trampoline pointer to trampoline (uint8_t*)
 */
struct cdl_jmp_patch
{
    bool active;
    int nt_alloc;
    uint8_t* code;
    uint8_t** target;
    uint8_t* origin;
    uint8_t* trampoline;
};

/**
 * SWBP patch info struct.
 *
 * @param gid global id for SW BP (int)
 * @param active is patch active (bool)
 * @param ns_alloc number of bytes allocated to stub (int)
 * @param code instructions replaced by SWBP patch (uint8_t*)
 * @param target pointer to function pointer (uint8_t**)
 * @param stub pointer to stub (uint8_t*)
 * @param detour pointer to detour function (uint8_t*)
 * @param bp_add address of breakpoint (uint8_t*)
 */
struct cdl_swbp_patch
{
    int gid;
    bool active;
    int ns_alloc;
    uint8_t* code;
    uint8_t** target;
    uint8_t* stub;
    uint8_t* detour;
    uint8_t* bp_addr;
};

/**
 * Attach JMP patch to target funciton.
 *
 * @param target pointer to function pointer to function to hook.
 * @param detour function pointer to detour function
 */
struct cdl_jmp_patch cdl_jmp_attach(
    __in_out void** target,
    __in void* detour
);

/**
 * Attach INT3 patch to target funciton.
 *
 * @param target pointer to function pointer to function to hook.
 * @param detour function pointer to detour function
 */
struct cdl_swbp_patch cdl_swbp_attach(
    __in_out void** target,
    __in void* detour
);

/**
 * Detach JMP patch.
 *
 * @param jmp_patch pointer to cdl_jmp_patch struct.
 */
void cdl_jmp_detach(
    __in_out struct cdl_jmp_patch* jmp_patch
);

/**
 * Detach INT3 patch.
 *
 * @param swbp_patch pointer to cdl_swbp_patch struct.
 */
void cdl_swbp_detach(
   __in_out  struct cdl_swbp_patch* swbp_patch
);

/**
 * Print JMP patch debug info.
 *
 * @param jmp_patch pointer to cdl_jmp_patch struct.
 */
void cdl_jmp_dbg(
    __in struct cdl_jmp_patch* jmp_patch
);

/**
 * Print SW BP debug info.
 *
 * @param jmp_patch pointer to cdl_swbp_patch struct.
 */
void cdl_swbp_dbg(
    __in struct cdl_swbp_patch* swbp_patch
);

#endif
