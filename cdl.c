/**
 * @file cdl.c
 * @brief cdl86 (Compact Detour Library) - cdl.c
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

#include "cdl.h"

/**
 * Software breakpoint initialization.
 */
static int cdl_swbp_alloc(
    __in void
);

/**
 * JMP patch info struct.
 *
 * @param code address to set page protections.
 */
static int cdl_set_page_protect(
    __in uint8_t* code
);

/**
 * Generate 64-bit jmp.
 *
 * @param code address to place jmp.
 * @param address address to jmp to.
 */
static uint8_t* cdl_gen_64_jmp(
    __in uint8_t* code,
    __in uint8_t* address
);

/**
 * Generate 32-bit jmp.
 *
 * @param code address to place jmp.
 * @param address address to jmp to.
 */
static uint8_t* cdl_gen_32_jmp(
    __in uint8_t* code,
    __in uint8_t* address
);

/**
 * Generate NOP instruction.
 *
 * @param code address to place NOP.
 */
static uint8_t* cdl_gen_nop(
    __in uint8_t* code
);

/**
 * Generate INT3 instruction.
 *
 * @param code address to place breakpoint.
 */
static uint8_t* cdl_gen_swbp(
    __in uint8_t* code
);

/**
 * Create trampoline function.
 *
 * @param target address to jump back to.
 * @param bytes_orig original bytes of target.
 * @param size size of bytes_orig.
 */
static uint8_t* cdl_gen_trampoline(
    __in uint8_t* target,
    __in uint8_t* bytes_orig,
    __in int size
);

/**
 * Reserve bytes at address of target. Calculates
 * minimum number of bytes required to fully replace
 * instructions at target address by size 'reserve
 *
 * @param target address to jump back to.
 * @param reserve size of hook type.
 * @param alloc_size final allocation size.
 */
static uint8_t* cdl_reserve_bytes(
    __in uint8_t* target,
    __in int reserve,
    __out int* alloc_size
);

/**
 * Fill unpatched bytes with NOPs to avoid segfault.
 *
 * @param target address to fill.
 * @param size size of region to fill.
 * @param patch_size size of patch type.
 */
static void cdl_nop_fill(
    __in uint8_t* target,
    __in int size,
    __in int patch_size
);

#ifdef _WIN32

/**
 * Vector exception handler for windows.
 *
 * @param except exception pointer.
 */
static long NTAPIcdl_swbp_handler_win(
    __in PEXCEPTION_POINTERS except
);

#else

/**
 * Vector exception handler for linux.
 *
 * @param sig signal id.
 * @param info signal information.
 * @param context execution context.
 */
static void cdl_swbp_handler_linux(
    __in int sig,
    __in siginfo_t* info,
    __in struct ucontext_t* context
);

#endif

/**
 * Instruction length disassembler.
 *
 * @param address address to disassemble.
 * @param x86_64_mode use 64-bit mode.
 */
size_t len_disasm(
    __in const void* const address,
    __in const bool x86_64_mode
);

/* Global variables for state machine. */
int cdl_swbp_size = 0x0;
bool cdl_swbp_init = false;
void* vector_handler = 0x0;
struct cdl_swbp_patch* cdl_swbp_hk = 0x0;

const uint8_t prefixes[] =
{
    0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67
};
const uint8_t op1modrm[] =
{
    0x62, 0x63, 0x69, 0x6B, 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1,
    0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF
};
const uint8_t op1imm8[] =
{
    0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5,
    0xEB
};
const uint8_t op1imm32[] =
{
    0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9
};
const uint8_t op2modrm[] =
{
    0x0D, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

/* Four high-order bits of an opcode to index a row of the opcode table. */
#define R (*b >> 4)
/* Four low-order bits to index a column of the table. */
#define C (*b & 0xF)

static int cdl_swbp_alloc(
    __in void
)
{
    extern struct cdl_swbp_patch* cdl_swbp_hk;
    bool found = false;
    int i = 0x0;
    int size = sizeof(cdl_swbp_hk[0]);
    extern struct cdl_swbp_patch* cdl_swbp_hk;

    /* If cdl_swbp_hk is null, allocate memory. */
    if (!cdl_swbp_hk)
    {
        cdl_swbp_hk = (struct cdl_swbp_patch*)malloc(size);
        cdl_swbp_size++;
        return 0;
    }
    else
    {
        /* Search through struct for inactive member. */
        for (i = 0; i < cdl_swbp_size; i++)
        {
            if (cdl_swbp_hk[i].active == false)
            {
                found = true;
                break;
            }
        }

        /* If we couldn't find inactive member, resize memory. */
        if (!found)
        {
            cdl_swbp_size++;
            cdl_swbp_hk = (struct cdl_swbp_patch*)realloc(cdl_swbp_hk,
                                                          size * cdl_swbp_size);
            return cdl_swbp_size - 1;
        }
        else
        {
            return i;
        }
    }
}

static struct cdl_ins_probe cdl_asm_probe(
    __in uint8_t* code
)
{
    int size = 0x0;
    struct cdl_ins_probe probe;

    size = len_disasm(code, true);
    probe.size = size;
    probe.bytes = (uint8_t*)malloc(sizeof(uint8_t) * size);
    memcpy(probe.bytes, code, size);

    return probe;
}

static int cdl_set_page_protect(
    __in uint8_t* code
)
{
    int ret = 0x0;

    #ifdef _WIN32

    SYSTEM_INFO sys_info = {0};
    unsigned long old_protect = 0x0;
    GetSystemInfo(&sys_info);
    ret = VirtualProtect((LPVOID)code, sys_info.dwPageSize,
                         PAGE_EXECUTE_READWRITE, &old_protect);

    #else

    /* Calculate page size */
    uintptr_t page_size = sysconf(_SC_PAGE_SIZE);
    ret = mprotect(code - ((uintptr_t)(code) % page_size), page_size,
                   PROT_EXEC | PROT_READ | PROT_WRITE);

    #endif

    return ret;
}

static uint8_t* cdl_gen_64_jmp(
    __in uint8_t* code,
    __in uint8_t* address
)
{
    /* Generate 'mov rax', address */
    *(code + 0x0) = 0x48;
    *(code + 0x1) = 0xB8;
    *(uint64_t*)(code + 0x2) = (uint64_t)address;
    /* Generate 'jmpq *%rax' instruction. */
    *(code + 0xA) = 0xFF;
    *(code + 0xB) = 0xE0;

    return code;
}

static uint8_t* cdl_gen_32_jmp(
    __in uint8_t* code,
    __in uint8_t* address
)
{
    uint8_t* operand = 0x0;
    /* Generate 'jmp address' */
    *(code + 0x0) = 0xE9;
    operand = (uint8_t*)(address - (code + BYTES_JMP_PATCH));
    *(uint32_t*)(code + 0x1) = (uintptr_t)operand;

    return code;
}

static uint8_t* cdl_gen_nop(
    __in uint8_t* code
)
{
    *(code + 0x0) = 0x90;
    return code;
}

static uint8_t* cdl_gen_swbp(
    __in uint8_t* code
)
{
    *(code + 0x0) = 0xCC;
    return code;
}

static uint8_t* cdl_gen_trampoline(
    __in uint8_t* target,
    __in uint8_t* bytes_orig,
    __in int size
)
{
    uint8_t* trampoline = 0x0;

    /* Allocate trampoline memory pool. */

    #ifdef _WIN32

    trampoline = (uint8_t*)VirtualAlloc(NULL, size + BYTES_JMP_PATCH,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);

    #else

    trampoline = (uint8_t*)mmap(NULL, size + BYTES_JMP_PATCH,
                                PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    #endif

    memcpy(trampoline, bytes_orig, size);
    /* Generate jump to address just after call
     * to detour in trampoline. */

    #ifdef ENV_64

    cdl_gen_64_jmp(trampoline + size, target + size);

    #else

    cdl_gen_32_jmp(trampoline + size, target + size);

    #endif

    return trampoline;
}

static uint8_t* cdl_reserve_bytes(
    __in uint8_t* target,
    __in int reserve,
    __out int* alloc_size
)
{
    int bytes = 0x0;
    uint8_t* bytes_orig = NULL;
    struct cdl_ins_probe probe;

    /* Ensure we can't reserve more than
     * BYTES_RESERVE_MAX.
     */
    if (reserve > BYTES_RESERVE_MAX)
    {
        return (uint8_t*)NULL;
    }
    /* Allocate buffer to hold original instruction
     * bytes.
     */
    bytes_orig = (uint8_t*)malloc(BYTES_RESERVE_MAX);
    /* Prove instructions until bytes > reserve. */
    while (bytes < reserve)
    {
        probe = cdl_asm_probe(target + bytes);
        memcpy(bytes_orig + bytes, probe.bytes, probe.size);
        bytes += probe.size;
        free(probe.bytes);
    };

    *alloc_size = bytes;
    /* Return original instruction bytes.
     * buffer
     */

    return bytes_orig;
}

/* Fill unpatched bytes with NOPs to
 * avoid segfault.
 */
static void cdl_nop_fill(
    __in uint8_t* target,
    __in int size,
    __in int patch_size
)
{
    int nops = 0x0;

    nops = size - patch_size;
    while (nops-- > 0)
    {
        cdl_gen_nop(target + patch_size + nops);
    }

    return;
}

#ifdef _WIN32

/* Vector breakpoint handler for windows. Handles incomming
 * PEXCEPTION  once INT3 breakpoint is hit.
 *
 * The handler functions by comparing the value
 * of ContextRecord->Rip as provided by the PEXCEPTION_RECORD
 * struct of the signal to the active breakpoint addresses
 * (bp_addr).
 *
 * If a match is found then the RIP/EIP register of the current
 * context if updated to the address of the detour function.
 */
static long NTAPI cdl_swbp_handler_win(
    __in PEXCEPTION_POINTERS except
)
{
    extern struct cdl_swbp_patch* cdl_swbp_hk;
    PEXCEPTION_RECORD except_record = except->ExceptionRecord;
    PCONTEXT context_record = except->ContextRecord;
    uint8_t* bp_addr = (uint8_t*)(except_record->ExceptionAddress);
    bool active = false;
    int i = 0x0;

    switch (except->ExceptionRecord->ExceptionCode)
    {
        case EXCEPTION_BREAKPOINT:
            for (i = 0; i < cdl_swbp_size; i++)
            {
                active = cdl_swbp_hk[i].active;
                /* Compare breakpoint addresses. */
                if (bp_addr == cdl_swbp_hk[i].bp_addr && active)
                {
                    #ifdef _WIN64

                    context_record->Rip = (uintptr_t)cdl_swbp_hk[i].detour;

                    #else

                    context_record->Eip = (uintptr_t)cdl_swbp_hk[i].detour;

                    #endif

                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

#else

/* Software breakpoint handler for linux. Handles incomming
 * SIGTRAP signal once INT3 breakpoint is hit.
 *
 * The handler functions by comparing the value
 * of the RIP-0x1 register as provided by the ucontext_t
 * struct of the signal to the active breakpoint addresses
 * (bp_addr).
 *
 * If a match is found then the RIP/EIP register of the current
 * context if updated to the address of the detour function.
 */
static void cdl_swbp_handler_linux(
    __in int sig,
    __in siginfo_t* info,
    __in struct ucontext_t* context
)
{
    extern struct cdl_swbp_patch* cdl_swbp_hk;
    int i = 0x0;
    bool active = false;
    uint8_t* bp_addr = NULL;
    /* RIP register point to instruction after the
     * int3 breakpoint so we subtract 0x1.
     */
    bp_addr = (uint8_t*)(context->uc_mcontext.gregs[REG_IP] - 0x1);

    /* Iterate over all breakpoint structs. */
    for (i = 0; i < cdl_swbp_size; i++)
    {
        active = cdl_swbp_hk[i].active;
        /* Compare breakpoint addresses. */
        if (bp_addr == cdl_swbp_hk[i].bp_addr && active)
        {
            /* Update RIP and reset context. */
            context->uc_mcontext.gregs[REG_IP] = (greg_t)cdl_swbp_hk[i].detour;
            setcontext(context);
        }
    }
}
#endif

/* Patches function pointed to by 'target' with
 * a JMP to the detour function. *target is then
 * updated to point to the newly allocated trampoline.
 */
struct cdl_jmp_patch cdl_jmp_attach(
    __in_out void** target,
    __in void* detour
)
{
    int bytes = 0x0;
    int i = 0x0;
    int nops = 0x0;
    uint8_t* trampoline = NULL;
    uint8_t* target_origin = NULL;
    uint8_t* plt_got = NULL;
    uint8_t* bytes_orig = NULL;
    struct cdl_jmp_patch jmp_patch = {0};

    target_origin = (uint8_t*)*target;
    /* Check if target pointer is PLT entry. */
    jmp_patch.target = (uint8_t**)target;

    /* Reserve BYTES_JMP_PATCH bytes for incoming
     * patch.
     */
    bytes_orig = cdl_reserve_bytes(target_origin, BYTES_JMP_PATCH, &bytes);
    jmp_patch.code = bytes_orig;
    jmp_patch.nt_alloc = bytes;

    /* Generate trampoline stub. */
    trampoline = cdl_gen_trampoline(target_origin, bytes_orig, bytes);
    jmp_patch.trampoline = trampoline;

    /* Set memory permissions. */
    cdl_set_page_protect(target_origin);

    /* Generate JMP to detour function. */

    #ifdef ENV_64

    cdl_gen_64_jmp(target_origin, (uint8_t*)detour);

    #else

    cdl_gen_32_jmp(target_origin, (uint8_t*)detour);

    #endif

    /* Fill remaining bytes with NOPs. */
    cdl_nop_fill(target_origin, bytes, BYTES_JMP_PATCH);

    jmp_patch.origin = target_origin;
    /* Set* target to newly allocated trampoline. */
    *target = trampoline;

    /* Mark patch as active. */
    jmp_patch.active = true;

    return jmp_patch;
}

/* Detach JMP patch and free memory. */
void cdl_jmp_detach(
    __in_out struct cdl_jmp_patch* jmp_patch
)
{
    uint8_t* origin = jmp_patch->origin;
    uint8_t* code = jmp_patch->code;
    int nt_alloc = jmp_patch->nt_alloc;

    /* If JMP patch is active, free memory. */
    if (jmp_patch->active)
    {
        memcpy(origin, code, nt_alloc);
        /* Deallocate trampoline. */

        #ifdef _WIN32

        VirtualFree(jmp_patch->trampoline, nt_alloc + BYTES_JMP_PATCH,
                    MEM_RELEASE);

        #else

        munmap(jmp_patch->trampoline, nt_alloc + BYTES_JMP_PATCH);

        #endif

        *jmp_patch->target = jmp_patch->origin;
        free(jmp_patch->code);

        /* Set jmp_patch memory to 0. */
        memset(jmp_patch, 0, sizeof(*jmp_patch));
    }

    return;
}

/* Patches function pointed to by 'target' with
 * a INT3 BP to the detour function. *target is then
 * updated to point to the newly allocated stub.
 */
struct cdl_swbp_patch cdl_swbp_attach(
    __in_out void** target,
    __in void* detour
)
{
    extern struct cdl_swbp_patch* cdl_swbp_hk;
    int bytes = 0x0;
    int id = 0x0;
    int size = 0x0;
    uint8_t* stub = NULL;
    uint8_t* bytes_orig = NULL;
    uint8_t* target_origin = NULL;
    uint8_t* plt_got = NULL;
    struct cdl_swbp_patch swbp_patch = {0};

    /* Initialise cdl signal handler. */
    if (!cdl_swbp_init)
    {
        /* Request signal context info which
         * is required for RIP register comparison.
         */

        #ifdef _WIN32

        vector_handler = AddVectoredExceptionHandler(1, &cdl_swbp_handler_win);

        #else

        struct sigaction sa = {0};
        sa.sa_flags = SA_SIGINFO | SA_ONESHOT;
        sa.sa_sigaction = (void*)cdl_swbp_handler_linux;
        sigaction(SIGTRAP, &sa, NULL);
        cdl_swbp_init = true;

        #endif
    }

    target_origin = (uint8_t*)*target;
    swbp_patch.target = (uint8_t**)target;
    swbp_patch.detour = (uint8_t*)detour;

    /* Reserve bytes for INT3 patch. */
    bytes_orig = cdl_reserve_bytes(target_origin, BYTES_SWBP_PATCH, &bytes);
    swbp_patch.code = bytes_orig;
    swbp_patch.ns_alloc = bytes;

    /* Generate stub function. */
    stub = cdl_gen_trampoline(target_origin, bytes_orig, bytes);
    swbp_patch.stub = stub;

    /* Set memory permissions and generate INT3. */
    cdl_set_page_protect(target_origin);
    cdl_gen_swbp(target_origin);

    /* Fill remaining bytes with NOPs. */
    cdl_nop_fill(target_origin, bytes, BYTES_SWBP_PATCH);

    /* Allocate new SW BP id. */
    id = cdl_swbp_alloc();
    swbp_patch.gid = id;
    size = sizeof(swbp_patch);

    swbp_patch.bp_addr = target_origin;
    *target = stub;

    swbp_patch.active = true;
    /* Copy struct data to global SWBP variable
     * (cdl_swbp_hk).
     */
    memcpy(cdl_swbp_hk + (size * id), &swbp_patch, size);

    return swbp_patch;
}

/* Detach INT3 patch and free memory. */
void cdl_swbp_detach(
    __in_out struct cdl_swbp_patch* swbp_patch
)
{
    extern struct cdl_swbp_patch* cdl_swbp_hk;
    uint8_t* bp_addr = swbp_patch->bp_addr;
    uint8_t* stub = swbp_patch->stub;
    uint8_t* code = swbp_patch->code;
    int ns_alloc = swbp_patch->ns_alloc;

    /* If JMP patch is active, free memory. */
    if (swbp_patch->active)
    {
        memcpy(bp_addr, code, ns_alloc);
        /* Unmap stub function. */

        #ifdef _WIN32

        VirtualFree(swbp_patch->stub, ns_alloc + BYTES_JMP_PATCH,
                    MEM_RELEASE);

        #else

        munmap(swbp_patch->stub, ns_alloc + BYTES_JMP_PATCH);

        #endif

        *swbp_patch->target = swbp_patch->bp_addr;
        free(code);

        /* Set global SWBP active status for gid to
         * flase.
         */
        cdl_swbp_hk[swbp_patch->gid].active = false;
        memset(swbp_patch, 0, sizeof(*swbp_patch));
        cdl_swbp_size--;
    }

    return;
}

/* Print debug info for JMP patch. */
void cdl_jmp_dbg(
    __in struct cdl_jmp_patch* jmp_patch
)
{
    printf("origin     : 0x%" PTR_SIZE "\n", (uintptr_t)jmp_patch->origin);
    printf("trampoline : 0x%" PTR_SIZE "\n", (uintptr_t)jmp_patch->trampoline);
    printf("nt_alloc   : %i\n", jmp_patch->nt_alloc);
    printf("active     : 0x%" PTR_SIZE "\n", (uintptr_t)jmp_patch->active);
}

/* Print debug info for INT3 patch. */
void cdl_swbp_dbg(
    __in struct cdl_swbp_patch* swbp_patch
)
{
    printf("bp_addr  : 0x%" PTR_SIZE "\n", (uintptr_t)swbp_patch->bp_addr);
    printf("stub     : 0x%" PTR_SIZE "\n", (uintptr_t)swbp_patch->stub);
    printf("ns_alloc : %i\n", swbp_patch->ns_alloc);
    printf("gid      : %i\n", swbp_patch->gid);
    printf("active   : 0x%" PTR_SIZE "\n", (uintptr_t)swbp_patch->active);
}

static bool findByte(
    __in const uint8_t* arr,
    __in const size_t N,
    __in const uint8_t x
)
{
    for (size_t i = 0; i < N; i++)
    {
        if (arr[i] == x)
        {
            return true;
        }
    };

    return false;
}

static void parseModRM(
    __in uint8_t** b,
    __in const bool addressPrefix
)
{
    uint8_t modrm = *++*b;

    if (!addressPrefix || (addressPrefix && **b >= 0x40))
    {
        /* Check for SIB byte. */
        bool hasSIB = false;
        if (**b < 0xC0 && (**b & 0b111) == 0b100 && !addressPrefix)
            hasSIB = true, (*b)++;

        /* disp8 (ModR/M). */
        if (modrm >= 0x40 && modrm <= 0x7F)
            (*b)++;
        else if ((modrm <= 0x3F && (modrm & 0b111) == 0b101)
                 /* disp16,32 (ModR/M). */
                 || (modrm >= 0x80 && modrm <= 0xBF))
            *b += (addressPrefix) ? 2 : 4;

            /* disp8,32 (SIB). */
        else if (hasSIB && (**b & 0b111) == 0b101)
            *b += (modrm & 0b01000000) ? 1 : 4;
    }
    else if (addressPrefix && modrm == 0x26)
        *b += 2;
};

size_t len_disasm(
    __in const void* const address,
    __in const bool x86_64_mode
)
{
    size_t offset = 0x0;
    bool operandPrefix = false;
    bool addressPrefix = false;
    bool rexW = false;
    uint8_t* b = (uint8_t*)(address);

    /* Parse legacy prefixes & REX prefixes. */
    for (int i = 0; i < 14 && findByte(prefixes, sizeof(prefixes), *b)
         || ((x86_64_mode) ? (R == 4) : false); i++, b++)
    {
        if (*b == 0x66)
            operandPrefix = true;
        else if (*b == 0x67)
            addressPrefix = true;
        else if (R == 4 && C >= 8)
            rexW = true;
    }

    /* Parse opcode(s). */
    if (*b == 0x0F) // 2,3 bytes.
    {
        b++;
        /* 3 bytes. */
        if (*b == 0x38 || *b == 0x3A)
        {
            if (*b++ == 0x3A)
                offset++;

            parseModRM(&b, addressPrefix);
        }
        /* 2 bytes. */
        else
        {
            /* disp32. */
            if (R == 8)
                offset += 4;
            else if ((R == 7 && C < 4) || *b == 0xA4 ||
                     *b == 0xC2 || (*b > 0xC3 && *b <= 0xC6)
                     || *b == 0xBA || *b == 0xAC) /* imm8. */
                offset++;

            /* Check for ModR/M, SIB and displacement. */
            if (findByte(op2modrm, sizeof(op2modrm), *b)
                || (R != 3 && R > 0 && R < 7)
                || *b >= 0xD0 || (R == 7 && C != 7)
                || R == 9 || R == 0xB
                || (R == 0xC && C < 8)
                || (R == 0 && C < 4))
                parseModRM(&b, addressPrefix);
        }
    }
    else /* 1 byte. */
    {
        /* Check for immediate field. */
        if ((R == 0xE && C < 8) || (R == 0xB && C < 8)
            || R == 7 || (R < 4 && (C == 4 || C == 0xC))
            || (*b == 0xF6 && !(*(b + 1) & 48))
            || findByte(op1imm8, sizeof(op1imm8), *b)) /* imm8. */
            offset++;
        else if (*b == 0xC2 || *b == 0xCA) /* imm16. */
            offset += 2;
        else if (*b == 0xC8) /* imm16 + imm8 */
            offset += 3;
        else if ((R < 4 && (C == 5 || C == 0xD))
                 || (R == 0xB && C >= 8)
                 || (*b == 0xF7 && !(*(b + 1) & 48))
                 || findByte(op1imm32, sizeof(op1imm32), *b)) /* imm32,16. */
            offset += (rexW) ? 8 : (operandPrefix ? 2 : 4);
        else if (R == 0xA && C < 4)
            offset += (rexW) ? 8 : (addressPrefix ? 2 : 4);
        else if (*b == 0xEA || *b == 0x9A) /* imm32,48. */
            offset += operandPrefix ? 4 : 6;

        /* Check for ModR/M, SIB and displacement. */
        if (findByte(op1modrm, sizeof(op1modrm), *b) ||
            (R < 4 && (C < 4 || (C >= 8 && C < 0xC)))
            || R == 8 || (R == 0xD && C >= 8))
            parseModRM(&b, addressPrefix);
    }

    return (size_t)((ptrdiff_t)(++b + offset) - (ptrdiff_t)(address));
}
