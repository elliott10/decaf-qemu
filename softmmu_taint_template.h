/*
 *  Software MMU support
 *
 * Generate helpers used by TCG for qemu_ld/st ops and code load
 * functions.
 *
 * Included from target op helpers and exec.c.
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
/*
#include "qemu/timer.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"
#include "shared/DECAF_callback_to_QEMU.h"
*/
/* AWH - Piggyback off of softmmu-template.h for a lot of the size stuff */
#define DATA_SIZE (1 << SHIFT)

/* Get rid of some implicit function declaration warnings */
#include "tainting/taint_memory.h"

#if 0
#if DATA_SIZE == 8
#define SUFFIX q
#define LSUFFIX q
#define SDATA_TYPE  int64_t
#define DATA_TYPE  uint64_t
#elif DATA_SIZE == 4
#define SUFFIX l
#define LSUFFIX l
#define SDATA_TYPE  int32_t
#define DATA_TYPE  uint32_t
#elif DATA_SIZE == 2
#define SUFFIX w
#define LSUFFIX uw
#define SDATA_TYPE  int16_t
#define DATA_TYPE  uint16_t
#elif DATA_SIZE == 1
#define SUFFIX b
#define LSUFFIX ub
#define SDATA_TYPE  int8_t
#define DATA_TYPE  uint8_t
#else
#error unsupported data size
#endif


/* For the benefit of TCG generated code, we want to avoid the complication
   of ABI-specific return type promotion and always return a value extended
   to the register size of the host.  This is tcg_target_long, except in the
   case of a 32-bit host and 64-bit data, and for that we always have
   uint64_t.  Don't bother with this widened value for SOFTMMU_CODE_ACCESS.  */
#if defined(SOFTMMU_CODE_ACCESS) || DATA_SIZE == 8
# define WORD_TYPE  DATA_TYPE
# define USUFFIX    SUFFIX
#else
# define WORD_TYPE  tcg_target_ulong
# define USUFFIX    glue(u, SUFFIX)
# define SSUFFIX    glue(s, SUFFIX)
#endif

#ifdef SOFTMMU_CODE_ACCESS
#define READ_ACCESS_TYPE MMU_INST_FETCH
#define ADDR_READ addr_code
#else
#define READ_ACCESS_TYPE MMU_DATA_LOAD
#define ADDR_READ addr_read
#endif

#if DATA_SIZE == 8
# define BSWAP(X)  bswap64(X)
#elif DATA_SIZE == 4
# define BSWAP(X)  bswap32(X)
#elif DATA_SIZE == 2
# define BSWAP(X)  bswap16(X)
#else
# define BSWAP(X)  (X)
#endif

#ifdef TARGET_WORDS_BIGENDIAN
# define TGT_BE(X)  (X)
# define TGT_LE(X)  BSWAP(X)
#else
# define TGT_BE(X)  BSWAP(X)
# define TGT_LE(X)  (X)
#endif
#endif

#if DATA_SIZE == 1
# define taint_helper_le_ld_name  glue(glue(taint_helper_ret_ld, USUFFIX), MMUSUFFIX)
# define taint_helper_be_ld_name  taint_helper_le_ld_name
# define taint_helper_le_lds_name glue(glue(taint_helper_ret_ld, SSUFFIX), MMUSUFFIX)
# define taint_helper_be_lds_name taint_helper_le_lds_name
# define taint_helper_le_st_name  glue(glue(taint_helper_ret_st, SUFFIX), MMUSUFFIX)
# define taint_helper_be_st_name  taint_helper_le_st_name
#else
# define taint_helper_le_ld_name  glue(glue(taint_helper_le_ld, USUFFIX), MMUSUFFIX)
# define taint_helper_be_ld_name  glue(glue(taint_helper_be_ld, USUFFIX), MMUSUFFIX)
# define taint_helper_le_lds_name glue(glue(taint_helper_le_ld, SSUFFIX), MMUSUFFIX)
# define taint_helper_be_lds_name glue(glue(taint_helper_be_ld, SSUFFIX), MMUSUFFIX)
# define taint_helper_le_st_name  glue(glue(taint_helper_le_st, SUFFIX), MMUSUFFIX)
# define taint_helper_be_st_name  glue(glue(taint_helper_be_st, SUFFIX), MMUSUFFIX)
#endif

#ifdef TARGET_WORDS_BIGENDIAN
# define taint_helper_te_ld_name  taint_helper_be_ld_name
# define taint_helper_te_st_name  taint_helper_be_st_name
#else
# define taint_helper_te_ld_name  taint_helper_le_ld_name
# define taint_helper_te_st_name  taint_helper_le_st_name
#endif

#if 0
/* macro to check the victim tlb */
#define VICTIM_TLB_HIT(ty)                                                    \
({                                                                            \
    /* we are about to do a page table walk. our last hope is the             \
     * victim tlb. try to refill from the victim tlb before walking the       \
     * page table. */                                                         \
    int vidx;                                                                 \
    hwaddr tmpiotlb;                                                          \
    CPUTLBEntry tmptlb;                                                       \
    for (vidx = CPU_VTLB_SIZE-1; vidx >= 0; --vidx) {                         \
        if (env->tlb_v_table[mmu_idx][vidx].ty == (addr & TARGET_PAGE_MASK)) {\
            /* found entry in victim tlb, swap tlb and iotlb */               \
            tmptlb = env->tlb_table[mmu_idx][index];                          \
            env->tlb_table[mmu_idx][index] = env->tlb_v_table[mmu_idx][vidx]; \
            env->tlb_v_table[mmu_idx][vidx] = tmptlb;                         \
            tmpiotlb = env->iotlb[mmu_idx][index];                            \
            env->iotlb[mmu_idx][index] = env->iotlb_v[mmu_idx][vidx];         \
            env->iotlb_v[mmu_idx][vidx] = tmpiotlb;                           \
            break;                                                            \
        }                                                                     \
    }                                                                         \
    /* return true when there is a vtlb hit, i.e. vidx >=0 */                 \
    vidx >= 0;                                                                \
})
#endif

#ifndef SOFTMMU_CODE_ACCESS
static inline DATA_TYPE glue(taint_io_read, SUFFIX)(CPUArchState *env,
                                              hwaddr physaddr,
                                              target_ulong addr,
                                              uintptr_t retaddr)
{
    uint64_t val;
    CPUState *cpu = ENV_GET_CPU(env);
    MemoryRegion *mr = iotlb_to_region(cpu->as, physaddr);

    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    cpu->mem_io_pc = retaddr;
    if (mr != &io_mem_rom && mr != &io_mem_notdirty && !cpu_can_do_io(cpu)) {
        cpu_io_recompile(cpu, retaddr);
    }

    cpu_single_env->tempidx = 0;
    cpu->mem_io_vaddr = addr;
    io_mem_read(mr, physaddr, &val, 1 << SHIFT);
    //res.taint = cpu_single_env->tempidx;
#if 0 // AWH
    if (cpu_single_env->tempidx/*res.taint*/) {
	    fprintf(stderr, "MMAP IO %s() -> physaddr: 0x%08x, taint: %u\n", "__taint_io_read", physaddr, cpu_single_env->tempidx);
	    //__asm__ ("int $3");
    }
#endif // AWH
    return val;
}
#endif

#ifdef SOFTMMU_CODE_ACCESS
static __attribute__((unused))
#endif
WORD_TYPE taint_helper_le_ld_name(CPUArchState *env, target_ulong addr, int mmu_idx,
                            uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    uintptr_t haddr;
    DATA_TYPE res;
        //res.dummy = 0;
	#if 0 // AWH
	#if DATA_SIZE == 4
	fprintf(stderr, "Entry %s() -> addr: 0x%08x mmu_idx: 0x%08x\n", "__taint_ldl", addr, mmu_idx);
	#elif DATA_SIZE == 2
	fprintf(stderr, "Entry %s() -> addr: 0x%08x mmu_idx: 0x%08x\n", "__taint_ldw", addr, mmu_idx);
	#else
	fprintf(stderr, "Entry %s() -> addr: 0x%08x mmu_idx: 0x%08x\n", "__taint_ldb", addr, mmu_idx);
	#endif
	#endif // AWH

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
         != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                                 mmu_idx, retaddr);
        }
#endif
        if (!VICTIM_TLB_HIT(ADDR_READ)) {
            tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                     mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        res = glue(taint_io_read, SUFFIX)(env, ioaddr, addr, retaddr);
        res = TGT_LE(res);
        return res;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        DATA_TYPE res1, res2;
        unsigned shift;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
#endif
        addr1 = addr & ~(DATA_SIZE - 1);
        addr2 = addr1 + DATA_SIZE;
        /* Note the adjustment at the beginning of the function.
           Undo that for the recursion.  */
        res1 = taint_helper_le_ld_name(env, addr1, mmu_idx, retaddr + GETPC_ADJ);
        res2 = taint_helper_le_ld_name(env, addr2, mmu_idx, retaddr + GETPC_ADJ);
        shift = (addr & (DATA_SIZE - 1)) * 8;

        /* Little-endian combine.  */
        res = (res1 >> shift) | (res2 << ((DATA_SIZE * 8) - shift));
        return res;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#if DATA_SIZE == 1
    res = glue(glue(ld, LSUFFIX), _p)((uint8_t *)haddr);
    //glue(glue(__taint_ld, SUFFIX), _p)((unsigned long)haddr, addr);
    glue(glue(taint_helper_ld, SUFFIX), _p)((unsigned long)haddr, addr);
#else
    res = glue(glue(ld, LSUFFIX), _le_p)((uint8_t *)haddr);
    //glue(glue(__taint_ld, SUFFIX), _le_p)((unsigned long)haddr, addr);
    glue(glue(taint_helper_ld, SUFFIX), _le_p)((unsigned long)haddr, addr);
#endif
    //Hu-Mem read callback
#ifndef SOFTMMU_CODE_ACCESS
    if(DECAF_is_callback_needed(DECAF_MEM_READ_CB))// host vitual haddr
	    helper_DECAF_invoke_mem_read_callback(addr,qemu_ram_addr_from_host_nofail((void *)(haddr)),DATA_SIZE);
#endif
    //end

    #if 0 // AWH
    if (res.taint) {
    #if DATA_SIZE == 4
    fprintf(stderr, "Return %s() -> addr: 0x%08x, taint: 0x%08x\n", "__taint_ldl", addr, res.taint);
    #elif DATA_SIZE == 2
    fprintf(stderr, "Return %s() -> addr: 0x%08x, taint: 0x%04x\n", "__taint_ldw", addr, res.taint);
    #else
    fprintf(stderr, "Return %s() -> addr: 0x%08x, taint: 0x%02x\n", "__taint_ldb", addr, res.taint);
    #endif
    //__asm__("int $3");
    }
    #endif // AWH
    return res;
}

#if DATA_SIZE > 1
#ifdef SOFTMMU_CODE_ACCESS
static __attribute__((unused))
#endif
//static DATA_TYPE glue(glue(taint_slow_ld, SUFFIX), MMUSUFFIX)
WORD_TYPE taint_helper_be_ld_name(CPUArchState *env, target_ulong addr, int mmu_idx,
                            uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    uintptr_t haddr;
    DATA_TYPE res, taint1, taint2;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
         != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                                 mmu_idx, retaddr);
        }
#endif
        if (!VICTIM_TLB_HIT(ADDR_READ)) {
            tlb_fill(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                     mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].ADDR_READ;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        res = glue(taint_io_read, SUFFIX)(env, ioaddr, addr, retaddr);
        res = TGT_BE(res);
        return res;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        DATA_TYPE res1, res2;
        unsigned shift;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
#endif
        addr1 = addr & ~(DATA_SIZE - 1);
        addr2 = addr1 + DATA_SIZE;
        /* Note the adjustment at the beginning of the function.
           Undo that for the recursion.  */
        res1 = taint_helper_be_ld_name(env, addr1, mmu_idx, retaddr + GETPC_ADJ);

	/* Special case for 32-bit host/guest and a 64-bit load */
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
	taint1 = cpu_single_env->tempidx2;
	taint1 = taint1 << 32;
	taint1 |= cpu_single_env->tempidx;
	//taint1 = cpu_single_env->tempidx | (cpu_single_env->tempidx2 << 32);
#else
	taint1 = cpu_single_env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */

        res2 = taint_helper_be_ld_name(env, addr2, mmu_idx, retaddr + GETPC_ADJ);

#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
	taint2 = cpu_single_env->tempidx2;
	taint2 = taint2 << 32;
	taint2 |= cpu_single_env->tempidx;
	//taint2 = cpu_single_env->tempidx | (cpu_single_env->tempidx2 << 32);
#else
	taint2 = cpu_single_env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
        shift = (addr & (DATA_SIZE - 1)) * 8;

        /* Big-endian combine.  */
	res = (res1 << shift) | (res2 >> ((DATA_SIZE * 8) - shift));
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
	cpu_single_env->tempidx = ((taint1 << shift) | (taint2 >> ((DATA_SIZE * 8) - shift))) & 0xFFFFFFFF;
	cpu_single_env->tempidx2 = (((taint1 << shift) | (taint2 >> ((DATA_SIZE * 8) - shift))) >> 32) & 0xFFFFFFFF;
#else
	cpu_single_env->tempidx = (taint1 << shift) | (taint2 >> ((DATA_SIZE * 8) - shift));
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */
        return res;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, READ_ACCESS_TYPE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
    res = glue(glue(ld, LSUFFIX), _be_p)((uint8_t *)haddr);
    //glue(glue(__taint_ld, SUFFIX), _be_p)((unsigned long)haddr, addr);
    glue(glue(taint_helper_ld, SUFFIX), _be_p)((unsigned long)haddr, addr);
    //Hu-Mem read callback
#ifndef SOFTMMU_CODE_ACCESS

    if(DECAF_is_callback_needed(DECAF_MEM_READ_CB))
	    helper_DECAF_invoke_mem_read_callback(addr,qemu_ram_addr_from_host_nofail((void *)(haddr)),DATA_SIZE);
#endif
    //end

    #if 0 // AWH
    #if DATA_SIZE == 4
    fprintf(stderr, "Return %s() -> addr: 0x%08x, taint: %u\n", "__taint_slow_ldl", addr, res.taint);
    #elif DATA_SIZE == 2
    fprintf(stderr, "Return %s() -> addr: 0x%08x, taint: %u\n", "__taint_slow_ldw", addr, res.taint);
    #else
    fprintf(stderr, "Return %s() -> addr: 0x%08x, taint: %u\n", "__taint_slow_ldb", addr, res.taint);
    #endif
    #endif // AWH
    return res;
}
#endif /* DATA_SIZE > 1 */

DATA_TYPE
glue(glue(taint_helper_ld, SUFFIX), MMUSUFFIX)(CPUArchState *env, target_ulong addr,
                                         int mmu_idx)
{
    return taint_helper_te_ld_name (env, addr, mmu_idx, GETRA());
}

#ifndef SOFTMMU_CODE_ACCESS

/* Provide signed versions of the load routines as well.  We can of course
   avoid this for 64-bit data, or for 32-bit data on 32-bit host.  */
#if DATA_SIZE * 8 < TCG_TARGET_REG_BITS
WORD_TYPE taint_helper_le_lds_name(CPUArchState *env, target_ulong addr,
                             int mmu_idx, uintptr_t retaddr)
{
    return (SDATA_TYPE)taint_helper_le_ld_name(env, addr, mmu_idx, retaddr);
}

# if DATA_SIZE > 1
WORD_TYPE taint_helper_be_lds_name(CPUArchState *env, target_ulong addr,
                             int mmu_idx, uintptr_t retaddr)
{
    return (SDATA_TYPE)taint_helper_be_ld_name(env, addr, mmu_idx, retaddr);
}
# endif
#endif

static inline void glue(taint_io_write, SUFFIX)(CPUArchState *env,
                                          hwaddr physaddr,
                                          DATA_TYPE val,
                                          target_ulong addr,
                                          uintptr_t retaddr)
{
    int index;
    index = (physaddr >> IO_MEM_SHIFT) & (IO_MEM_NB_ENTRIES - 1);

    CPUState *cpu = ENV_GET_CPU(env);
    MemoryRegion *mr = iotlb_to_region(cpu->as, physaddr);

    physaddr = (physaddr & TARGET_PAGE_MASK) + addr;
    if (mr != &io_mem_rom && mr != &io_mem_notdirty && !cpu_can_do_io(cpu)) {
        cpu_io_recompile(cpu, retaddr);
    }

    cpu->mem_io_vaddr = addr;
    cpu->mem_io_pc = retaddr;
    io_mem_write(mr, physaddr, val, 1 << SHIFT);
    //Hu-for io mem not dirty
#ifndef SOFTMMU_CODE_ACCESS
    if((index == 3)&DECAF_is_callback_needed(DECAF_MEM_WRITE_CB)) { //IO_MEM_NOTDIRTY
	    helper_DECAF_invoke_mem_write_callback(addr,physaddr,DATA_SIZE);
    }
#endif
    //end
    if (index == (IO_MEM_NOTDIRTY>>IO_MEM_SHIFT))
	    glue(glue(taint_helper_st, SUFFIX), _raw_paddr)(physaddr,addr);
	    //glue(glue(__taint_st, SUFFIX), _raw_paddr)(physaddr,addr);

    /* Clean tempidx */  
    //cpu_single_env->tempidx = 0;
}

void taint_helper_le_st_name(CPUArchState *env, target_ulong addr, DATA_TYPE val,
                       int mmu_idx, uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    uintptr_t haddr;

    #if 0 // AWH
    if (taint) {
    #if DATA_SIZE == 4
    fprintf(stderr, "Start  %s() -> addr: 0x%08x, data: 0x%08x, mmu_idx: %d, taint: 0x%08x\n", "__taint_stl", addr, val, mmu_idx, taint);
    #elif DATA_SIZE == 2
    fprintf(stderr, "Start  %s() -> addr: 0x%08x, data: 0x%08x, mmu_idx: %d, taint: 0x%08x\n", "__taint_stw", addr, val, mmu_idx, taint);
    #else
    fprintf(stderr, "Start  %s() -> addr: 0x%08x, data: 0x%08x, mmu_idx: %d, taint: 0x%08x\n", "__taint_stb", addr, val, mmu_idx, taint);
    #endif
    //__asm__("int $3");
    }
    #endif // AWH

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
        != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                                 mmu_idx, retaddr);
        }
#endif
        if (!VICTIM_TLB_HIT(addr_write)) {
            tlb_fill(ENV_GET_CPU(env), addr, MMU_DATA_STORE, mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        val = TGT_LE(val);
        glue(taint_io_write, SUFFIX)(env, ioaddr, val, addr, retaddr);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
                     >= TARGET_PAGE_SIZE)) {
        int i;
    do_unaligned_access:
#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
#endif
        /* XXX: not efficient, but simple */
        /* Note: relies on the fact that tlb_fill() does not remove the
         * previous page from the TLB cache.  */
        for (i = DATA_SIZE - 1; i >= 0; i--) {
            /* Little-endian extract.  */
            uint8_t val8 = val >> (i * 8);
            /* Note the adjustment at the beginning of the function.
               Undo that for the recursion.  */
            glue(helper_ret_stb, MMUSUFFIX)(env, addr + i, val8,
                                            mmu_idx, retaddr + GETPC_ADJ);
        }
        return;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
#if DATA_SIZE == 1
    glue(glue(st, SUFFIX), _p)((uint8_t *)haddr, val);
    glue(glue(taint_helper_st, SUFFIX), _p)((unsigned long)haddr, addr);
    //glue(glue(__taint_st, SUFFIX), _p)((unsigned long)haddr, addr);
#else
    glue(glue(st, SUFFIX), _le_p)((uint8_t *)haddr, val);
    glue(glue(taint_helper_st, SUFFIX), _le_p)((unsigned long)haddr, addr);
    //glue(glue(__taint_st, SUFFIX), _le_p)((unsigned long)haddr, addr);
#endif
    //Hu-Mem write callback
#ifndef SOFTMMU_CODE_ACCESS
    if(DECAF_is_callback_needed(DECAF_MEM_WRITE_CB))
	    helper_DECAF_invoke_mem_write_callback(addr,qemu_ram_addr_from_host_nofail((void *)(haddr)),DATA_SIZE);
#endif
    //end
}

#if DATA_SIZE > 1
void taint_helper_be_st_name(CPUArchState *env, target_ulong addr, DATA_TYPE val,
                       int mmu_idx, uintptr_t retaddr)
{
    int index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    target_ulong tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    uintptr_t haddr;
    DATA_TYPE backup_taint;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* If the TLB entry is for a different page, reload and try again.  */
    if ((addr & TARGET_PAGE_MASK)
        != (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
#ifdef ALIGNED_ONLY
        if ((addr & (DATA_SIZE - 1)) != 0) {
            cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                                 mmu_idx, retaddr);
        }
#endif
        if (!VICTIM_TLB_HIT(addr_write)) {
            tlb_fill(ENV_GET_CPU(env), addr, MMU_DATA_STORE, mmu_idx, retaddr);
        }
        tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
    }

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        hwaddr ioaddr;
        if ((addr & (DATA_SIZE - 1)) != 0) {
            goto do_unaligned_access;
        }
        ioaddr = env->iotlb[mmu_idx][index];

        /* ??? Note that the io helpers always read data in the target
           byte ordering.  We should push the LE/BE request down into io.  */
        val = TGT_BE(val);
        glue(taint_io_write, SUFFIX)(env, ioaddr, val, addr, retaddr);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (DATA_SIZE > 1
		    && unlikely((addr & ~TARGET_PAGE_MASK) + DATA_SIZE - 1
				>= TARGET_PAGE_SIZE)) {
	    int i;
do_unaligned_access:
	    /* AWH - Backup the taint held in tempidx and tempidx2 and
	       setup tempidx for each of these single-byte stores */
	    /* Special case for 32-bit host/guest and a 64-bit load */
#if ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8))
	    backup_taint = cpu_single_env->tempidx2;
	    backup_taint = backup_taint << 32;
	    backup_taint |= cpu_single_env->tempidx;
	    //backup_taint = cpu_single_env->tempidx | (cpu_single_env->tempidx2 << 32);
#else
	    backup_taint = cpu_single_env->tempidx;
#endif /* ((TCG_TARGET_REG_BITS == 32) && (DATA_SIZE == 8)) */

#ifdef ALIGNED_ONLY
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
#endif
        /* XXX: not efficient, but simple */
        /* Note: relies on the fact that tlb_fill() does not remove the
         * previous page from the TLB cache.  */
        for (i = DATA_SIZE - 1; i >= 0; i--) {
	    cpu_single_env->tempidx = backup_taint >> (((DATA_SIZE - 1) * 8) - (i * 8));
            /* Big-endian extract.  */
            uint8_t val8 = val >> (((DATA_SIZE - 1) * 8) - (i * 8));
            /* Note the adjustment at the beginning of the function.
               Undo that for the recursion.  */
            glue(helper_ret_stb, MMUSUFFIX)(env, addr + i, val8,
                                            mmu_idx, retaddr + GETPC_ADJ);
        }
        return;
    }

    /* Handle aligned access or unaligned access in the same page.  */
#ifdef ALIGNED_ONLY
    if ((addr & (DATA_SIZE - 1)) != 0) {
        cpu_unaligned_access(ENV_GET_CPU(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }
#endif

    haddr = addr + env->tlb_table[mmu_idx][index].addend;
    glue(glue(st, SUFFIX), _be_p)((uint8_t *)haddr, val);
    glue(glue(taint_helper_st, SUFFIX), _be_p)((unsigned long)haddr, addr);
    //glue(glue(__taint_st, SUFFIX), _be_p)((unsigned long)haddr, addr);
    //Hu-Mem read callback
#if defined(ADD_MEM_CB)
    if(DECAF_is_callback_needed(DECAF_MEM_WRITE_CB))
	    helper_DECAF_invoke_mem_write_callback(addr,qemu_ram_addr_from_host_nofail((void *)(haddr)),DATA_SIZE);
#endif
    //end

}
#endif /* DATA_SIZE > 1 */

void
glue(glue(taint_helper_st, SUFFIX), MMUSUFFIX)(CPUArchState *env, target_ulong addr,
                                         DATA_TYPE val, int mmu_idx)
{
    taint_helper_te_st_name(env, addr, val, mmu_idx, GETRA());
}

#endif /* !defined(SOFTMMU_CODE_ACCESS) */
/*
#undef READ_ACCESS_TYPE
#undef SHIFT
#undef DATA_TYPE
#undef SUFFIX
#undef LSUFFIX
#undef DATA_SIZE
#undef ADDR_READ
#undef WORD_TYPE
#undef SDATA_TYPE
#undef USUFFIX
#undef SSUFFIX
#undef BSWAP
#undef TGT_BE
#undef TGT_LE
#undef CPU_BE
#undef CPU_LE
#undef taint_helper_le_ld_name
#undef taint_helper_be_ld_name
#undef taint_helper_le_lds_name
#undef taint_helper_be_lds_name
#undef taint_helper_le_st_name
#undef taint_helper_be_st_name
#undef taint_helper_te_ld_name
#undef taint_helper_te_st_name
*/
