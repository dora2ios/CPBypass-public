#include <stdio.h>
#include <stdint.h>

#include <mach/mach.h>
#include <mach-o/loader.h>

#include "patchfinder32.h"

/* --- planetbeing patchfinder --- */
static uint32_t bit_range(uint32_t x, int start, int end) {
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places) {
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12) {
    if (bit_range(imm12, 11, 10) == 0) {
        switch (bit_range(imm12, 9, 8)) {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t *i) {
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t *i) {
    if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if ((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t *i) {
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t *i) {
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t *i) {
    if ((*i & 0xF800) == 0xE000)
        return 1;
    else if ((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t *i) {
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t *i) {
    if ((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t *i) {
    if ((*i & 0xF800) == 0x4800)
        return (*i & 0xF) << 2;
    else if ((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

static int insn_ldr_imm_rt(uint16_t *i) {
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t *i) {
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t *i) {
    return ((*i >> 6) & 0x1F);
}

static int insn_is_add_reg(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800)
        return 1;
    else if ((*i & 0xFF00) == 0x4400)
        return 1;
    else if ((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if ((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4);
    else if ((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t *i) {
    if ((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if ((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if ((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t *i) {
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t *i) {
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t *i) {
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t *i) {
    if ((*i & 0xF800) == 0x2000)
        return 1;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t *i) {
    if ((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t *i) {
    if ((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if ((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if ((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t *find_last_insn_matching(uint8_t *kdata, size_t ksize, uint16_t *current_instruction, int (*match_func) (uint16_t *)) {
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }
        if (match_func(current_instruction)) {
            return current_instruction;
        }
    }
    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint8_t *kdata, size_t ksize, uint16_t *insn, int reg) {
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t *current_instruction = insn;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }
        
        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            found = 1;
            break;
        }
        
        if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            found = 1;
            break;
        }
    }
    
    if (!found)
        return 0;
    
    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
    uint32_t value = 0;
    while ((uintptr_t) current_instruction < (uintptr_t) insn) {
        if (insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            value = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            value = *(uint32_t *) (kdata + (((((uintptr_t) current_instruction - (uintptr_t) kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if (insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg) {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg) {
            if (insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg) {
                // Can't handle this kind of operation!
                return 0;
            }
            value += ((uintptr_t) current_instruction - (uintptr_t) kdata) + 4;
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return value;
}

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t *find_literal_ref(uint8_t *kdata, size_t ksize, uint16_t *insn, uint32_t address) {
    uint16_t *current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));
    
    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if (insn_is_ldr_literal(current_instruction)) {
            uintptr_t literal_address = (uintptr_t) kdata + ((((uintptr_t) current_instruction - (uintptr_t) kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if (literal_address >= (uintptr_t) kdata && (literal_address + 4) <= ((uintptr_t) kdata + ksize)) {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t *) (literal_address);
            }
        } else if (insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        } else if (insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if (insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += ((uintptr_t) current_instruction - (uintptr_t) kdata) + 4;
                if (value[reg] == address) {
                    return current_instruction;
                }
            }
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return NULL;
}

static int find_macho_section(struct mach_header *hdr, size_t size, const char *segname, const char *sectname, uint32_t *ret_addr, uint32_t *ret_size) {
    /* Doesn't do bounds checking for size and other values */
    if (hdr->magic == MH_MAGIC) {
        struct load_command *cmd = (struct load_command *)(hdr + 1);
        for (int i = 0; i < hdr->ncmds; i++) {
            if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg = (struct segment_command *)cmd;
                if (!strncmp(seg->segname, segname, 16)) {
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        struct section *sect = ((struct section *)(seg + 1)) + j;
                        if (!strncmp(sect->sectname, sectname, 16)) {
                            *ret_addr = sect->addr;
                            *ret_size = sect->size;
                            return 0;
                        }
                    }
                }
            }
            cmd = (struct load_command *)(((uint8_t *)cmd) + cmd->cmdsize);
        }
    }
    return 1;
}

/* Buggy, but re-implemented because some old versions of iOS don't have memmem */
static void * buggy_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (haystack == NULL || haystacklen == 0 || needle == NULL || needlelen == 0) {
        printf("ERROR: Invalid arguments for buggy_memmem.\n");
        return NULL;
    }
    for (size_t i = 0; i < haystacklen; i++) {
        if (*(uint8_t *)(haystack + i) == *(uint8_t *)needle && i + needlelen <= haystacklen && 0 == memcmp(((uint8_t *)haystack) + i, needle, needlelen)) {
            return (void *)(((uint8_t *)haystack) + i);
        }
    }
    return NULL;
}

static uint32_t find_kernel_pmap_pre_iOS_6(uint8_t *pmap_map_bd, uint32_t kernel_base, uint8_t *kdata, size_t ksize) {
    /* Find xref to string "pmap_map_bd" (that function also references kernel_pmap) */
    uint32_t xref = 0;
    for (size_t i = 0; i < ksize; i += 4)
        if (*(uint32_t *)(kdata + i) == (uint32_t)(kernel_base + pmap_map_bd - kdata)) {
            xref = i;
            break;
        }
    if (0 == xref) {
        printf("ERROR: Failed to find xref to string \"pmap_map_bd\".\n");
        return -1;
    }
    
    /* Find beginning of next function */
    uint32_t next_func_start = 0;
    for (int i = 0; i < 128; i += 2) {
        if (*(uint16_t *)(kdata + xref + i) == 0xB5F0) {
            /* Align to 4-byte boundary */
            next_func_start = (xref + i) & ~3;
            break;
        }
    }
    if (0 == next_func_start) {
        printf("ERROR: Failed to find next function within 128 bytes.\n");
        return -1;
    }
    
    /* Find end of this function */
    uint32_t this_func_end = 0;
    for (int i = 0; i < 64; i += 2) {
        if (*(uint16_t *)(kdata + xref - i) == 0xBDF0) {
            /* Align to 4-byte boundary */
            this_func_end = (xref - i + 4) & ~3;
            break;
        }
    }
    if (0 == this_func_end) {
        printf("ERROR: Failed to find end of this function within 64 bytes.\n");
        return -1;
    }
    
    uint32_t vm_addr = 0, vm_size = 0;
    /* Find location of __DATA __data section */
    if (0 != find_macho_section((struct mach_header *)kdata, ksize, SEG_DATA, SECT_DATA, &vm_addr, &vm_size)) {
        printf("ERROR: Failed to find __DATA __data in Mach-O header.\n");
        return -1;
    }
    
    uint32_t pmap = 0;
    for (uint32_t *search = (uint32_t *)(kdata + this_func_end); search < (uint32_t *)(kdata + next_func_start); search += 1) {
        if (vm_addr <= *search && *search < vm_addr + vm_size) {
            if (pmap != 0 && pmap != *search) {
                printf("ERROR: Multiple possible values within __DATA __data section were found.\n");
                return -1;
            }
            pmap = *search;
        }
    }
    if (0 == pmap) {
        printf("ERROR: No values within __DATA __data section were found.\n");
        return -1;
    }
    
    return pmap - (kernel_base);
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
static uint32_t find_kernel_pmap_post_iOS_6(uint8_t *pmap_map_bd, uint8_t *kdata, size_t ksize) {
    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t *ptr = find_literal_ref(kdata, ksize, (uint16_t *)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr) {
        return 0;
    }
    
    // Find the beginning of it (we may have a version that throws panic after the function end).
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata) {
            return 0;
        }
        ptr--;
    }
    
    // Find the end of it.
    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = buggy_memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr) {
        return 0;
    }
    
    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t *bl = find_last_insn_matching(kdata, ksize, ptr, insn_is_bl);
    if (!bl) {
        return 0;
    }
    
    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {
            --current_instruction;
        }
        
        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {
            ldr_r2 = current_instruction;
            break;
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {
            break;
        }
    }
    
    // The function has a third argument, which must be kernel_pmap. Find out its address
    if (ldr_r2) {
        return find_pc_rel_value(kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));
    }
    
    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t) bl - (uintptr_t) kdata) + 4 + imm32;
    if (target > ksize) {
        return 0;
    }
    
    // Find the first PC-relative reference in this function.
    current_instruction = (uint16_t *) (kdata + target);
    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15) {
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            return find_pc_rel_value(kdata, ksize, current_instruction, insn_add_reg_rd(current_instruction));
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    return 0;
}

static uint32_t find_larm_init_tramp(uint8_t *kdata, size_t ksize) {
    // ldr lr, [pc, lr];    b +0x0; cpsid if
    const uint8_t search[]  = { 0x0E, 0xE0, 0x9F, 0xE7, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    void *ptr = buggy_memmem(kdata, ksize, search, sizeof(search));
    if (ptr) {
        return ((uintptr_t)ptr) - ((uintptr_t)kdata);
    }
    
    // ldr lr, [pc #value]; b +0x0; cpsid if
    const uint8_t search2[] = {/* ??, ?? */ 0x9F, 0xE5, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
    ptr = buggy_memmem(kdata, ksize, search2, sizeof(search2));
    if (ptr) {
        return ((uintptr_t)ptr) - 2 - ((uintptr_t)kdata);
    }
    
    printf("ERROR: Failed to locate larm_init_tramp.\n");
    return -1;
}

uint32_t get_kernel_pmap(vm_address_t kernel_base, uint8_t *kernel_dump, size_t ksize) {
    uint8_t *pmap_map_bd = buggy_memmem(kernel_dump, ksize, "\"pmap_map_bd\"", strlen("\"pmap_map_bd\""));
    if (NULL == pmap_map_bd) {
        printf("ERROR: Failed to find string \"pmap_map_bd\".\n");
        return -1;
    }
    uint32_t kernel_pmap_offset = 0;
    kernel_pmap_offset = find_kernel_pmap_post_iOS_6(pmap_map_bd, kernel_dump, ksize);
    if (0 == kernel_pmap_offset) {
        printf("ERROR: Failed to find kernel_pmap offset.");
        return -1;
    }
    return kernel_pmap_offset;
}

/* --- end --- */

// taig8's patchfinder
struct find_search_mask
{
    uint16_t mask;
    uint16_t value;
};

// Search the range of kdata for a series of 16-bit values that match the search mask.
static uint16_t* find_with_search_mask(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks)
{
    uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
    uint16_t* cur;
    for(cur = (uint16_t*) kdata; cur <= end; ++cur)
    {
        int matched = 1;
        int i;
        for(i = 0; i < num_masks; ++i)
        {
            if((*(cur + i) & masks[i].mask) != masks[i].value)
            {
                matched = 0;
                break;
            }
        }
        
        if(matched)
            return cur;
    }
    
    return NULL;
}


uint32_t find_copyinstr(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const struct find_search_mask search_masks[] =
    {
        {0x0FFF, 0x0F90},
        {0xFFFF, 0xEE1D},
        {0x0000, 0x0000},
        {0xFFF0, 0xE590},
        {0x0000, 0x0000},
        {0xFFF0, 0xE580},
        {0x0000, 0x0000},
        {0xFFF0, 0xE590},
        {0x0FFF, 0x0F10},
        {0xFFFF, 0xEE02},
        {0x0000, 0x0000},
        {0xFFF0, 0xE590},
        {0x0FFF, 0x0F30},
        {0xFFFF, 0xEE0D}
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn)
        return 0;
    
    // Find the beginning of the function
    for ( ; (uint8_t*)insn > kdata; insn -= 2 )
    {
        if ( (insn[1] & 0xFFF0) == 0xE920 )
            break;
    }
    
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// Function used to find IOLog for printing debug messages
uint32_t find_IOLog(uint32_t region, uint8_t* kdata, size_t ksize)
{
    // Find location of the "%s: error mapping interrupt[%d]\n" string.
    uint8_t* msg = memmem(kdata, ksize, "%s: error mapping interrupt[%d]\n", sizeof("%s: error mapping interrupt[%d]\n"));
    if(!msg)
        return 0;
    
    // Find a reference to the "%s: error mapping interrupt[%d]\n" string.
    uint16_t* ref = find_literal_ref(kdata, ksize, (uint16_t*) kdata, (uintptr_t)msg - (uintptr_t)kdata);
    if(!ref)
        return 0;
    
    uint16_t* bl = NULL;
    uint16_t* current_instruction = ref;
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize))
    {
        if(insn_is_bl(current_instruction))
        {
            bl = current_instruction;
            break;
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!bl)
        return 0;
    
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)
        return 0;
    
    return target + 1;
}

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t find_syscall188(uint32_t region, uint8_t* kdata, size_t ksize, int sysent)
{
    
    /* find syscall(0) */
    uint32_t syscall0;
    uint8_t* str = memmem(kdata, ksize, ".HFS+ Private Directory Data\r", sizeof(".HFS+ Private Directory Data\r"));
    if(str) {
        uint32_t address = ((uintptr_t)str) + region - ((uintptr_t)kdata);
        uint8_t *offset = memmem(kdata, ksize, (const char *)&address, sizeof(uint32_t));
        // "HFS+" string offset preceded syscall table
        syscall0 = ((uintptr_t)offset) + 4 - ((uintptr_t)kdata);
    }
    
    if(!syscall0) return 0;
    
    if(*(uint32_t*)&kdata[syscall0+0x4] == 0x1 &&          // syscall0.sy_return_type
       *(uint16_t*)&kdata[syscall0+0x8] == 0x0 &&          // syscall0.sy_narg
       *(uint16_t*)&kdata[syscall0+0xa] == 0x0 &&          // syscall0.sy_arg_bytes
       *(uint32_t*)&kdata[syscall0+0x10] == 0x0 &&         // syscall1.sy_return_type
       *(uint16_t*)&kdata[syscall0+0x14] == 0x1 &&         // syscall1.sy_narg
       *(uint16_t*)&kdata[syscall0+0x16] == 0x4 &&         // syscall1.sy_arg_bytes
       *(uint32_t*)&kdata[syscall0+0x8D4] == 0x1 &&        // syscall188.sy_return_type
       *(uint16_t*)&kdata[syscall0+0x8D8] == 0x2 &&        // syscall188.sy_narg
       *(uint16_t*)&kdata[syscall0+0x8DA] == 0x8){         // syscall188.sy_arg_bytes
        
        if(sysent) return *(uint32_t*)&kdata[syscall0+0x8D0] - region; // syscall188.sy_call
        if(!sysent) return syscall0+0x8D0;
    }
    
    return 0;
}

// for iOS 10.x
uint32_t find_syscall188_post_iOSX(uint32_t region, uint8_t* kdata, size_t ksize, int sysent)
{
    const uint8_t syscall0_search[] = {0x80, 0xb5, 0x6f, 0x46, 0x82, 0xb0, 0x1d, 0xee, 0x90, 0x2f, 0x00, 0x20, 0x01, 0x90, 0x0c, 0x20, 0x00, 0x90, 0x00, 0x20, 0x00, 0x21, 0x04, 0x23};
    
    void* ptr = memmem(kdata, ksize, syscall0_search, sizeof(syscall0_search));
    if(!ptr)
        return 0;
    
    uint32_t syscall0_ptr = ((uintptr_t)ptr) - ((uintptr_t)kdata) + region + 1;
    
    for(int i=0;i<0x800000;i++){
        if(*(uint32_t*)&kdata[i] == syscall0_ptr &&     // syscall0.sy_call
           *(uint32_t*)&kdata[i+0x4] == 0x1 &&          // syscall0.sy_return_type
           *(uint16_t*)&kdata[i+0x8] == 0x0 &&          // syscall0.sy_narg
           *(uint16_t*)&kdata[i+0xa] == 0x0 &&          // syscall0.sy_arg_bytes
           *(uint32_t*)&kdata[i+0x10] == 0x0 &&         // syscall1.sy_return_type
           *(uint16_t*)&kdata[i+0x14] == 0x1 &&         // syscall1.sy_narg
           *(uint16_t*)&kdata[i+0x16] == 0x4 &&         // syscall1.sy_arg_bytes
           *(uint32_t*)&kdata[i+0x8D4] == 0x1 &&        // syscall188.sy_return_type
           *(uint16_t*)&kdata[i+0x8D8] == 0x2 &&        // syscall188.sy_narg
           *(uint16_t*)&kdata[i+0x8DA] == 0x8){         // syscall188.sy_arg_bytes
            
            if(sysent) return *(uint32_t*)&kdata[i+0x8D0] - region; // syscall188.sy_call
            if(!sysent) return i+0x8D0;
        }
    }
    
    return 0;
}


uint32_t find_strcmp(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t strcmp_searchX[] = {0x01, 0x31, 0x01, 0x30, 0x00, 0x2a, 0x04, 0xbf, 0x00, 0x20, 0x70, 0x47};
    
    void* ptrX = memmem(kdata, ksize, strcmp_searchX, sizeof(strcmp_searchX));
    if(!ptrX){
        const uint8_t strcmp_searchIX[] = {0x00, 0x2a, 0x00, 0xf1, 0x01, 0x00, 0x01, 0xf1, 0x01, 0x01, 0x04, 0xbf, 0x00, 0x20, 0x70, 0x47};
        void* ptrIX = memmem(kdata, ksize, strcmp_searchIX, sizeof(strcmp_searchIX));
        if(!ptrIX){
            return 0;
        }
        return ((uintptr_t)ptrIX) - ((uintptr_t)kdata) - 0x2;
    }
    
    return ((uintptr_t)ptrX) - ((uintptr_t)kdata) - 0x2;
    
}

uint32_t get_kernel_str(uint32_t region, uint8_t* kdata, size_t ksize, char* str)
{
    uint8_t *ptr = buggy_memmem(kdata, ksize, str, strlen(str) + 1);
    if (NULL == ptr) {
        printf("ERROR: Failed to find strings: %s\n", str);
        return -1;
    }
    
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

uint32_t find_IOLog_post_iOSX(uint32_t region, uint8_t* kdata, size_t ksize)
{
    const uint8_t IOLog_search[] = {0x83, 0xB0, 0x90, 0xB5, 0x01, 0xAF, 0x85, 0xB0, 0x04, 0x46, 0x3B, 0x61, 0xFA, 0x60, 0xB9, 0x60, 0x07, 0xF1, 0x08, 0x00, 0x02, 0x90, 0x04, 0x90, 0x04, 0x98, 0x03, 0x90, 0x04, 0x99, 0x20, 0x46};
    void* ptr = memmem(kdata, ksize, IOLog_search, sizeof(IOLog_search));
    if(!ptr)
        return 0;
    
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
    
    return 0;
}
// end

// make_bl - from iloader by xerub
uint32_t make_bl(int blx, int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;
    unsigned int omask = 0xF800;
    unsigned int amask = 0x7FF;
    if (blx) { // XXX untested
        omask = 0xE800;
        amask = 0x7FE;
        pos &= ~3;
    }
    delta = tgt - pos - 4; // range: 0x400000
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);
    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

unsigned int
make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;
    
    unsigned int amask = 0x7FF;
    int range;
    
    range = 0x400000;
    
    delta = tgt - pos - 4; // range: 0x400000
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    
    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range < i && i < range*2){ // range: 0x400000-0x800000
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*2 < i && i < range*3){ // range: 0x800000-0xc000000
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*3 < i && i < range*4){ // range: 0xc00000-0x10000000
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    return -1;
}
