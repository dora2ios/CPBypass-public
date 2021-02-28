/* sysent_patch32.c: Patch the kernel and hook syscall(188) for iOS 10.x
 * 2020/12/12
 * made by dora2ios
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include <notify.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <sys/utsname.h>
#include "patchfinder32/patchfinder32.h"
#include "payload/payload32.h"

/* ARM page bits for L1 sections */
#define L1_SHIFT             20  /* log2(1MB) */

#define L1_SECT_PROTO        (1 << 1)   /* 0b10 */

#define L1_SECT_B_BIT        (1 << 2)
#define L1_SECT_C_BIT        (1 << 3)

#define L1_SECT_SORDER       (0)    /* 0b00, not cacheable, strongly ordered */
#define L1_SECT_SH_DEVICE    (L1_SECT_B_BIT)
#define L1_SECT_WT_NWA       (L1_SECT_C_BIT)
#define L1_SECT_WB_NWA       (L1_SECT_B_BIT | L1_SECT_C_BIT)
#define L1_SECT_S_BIT        (1 << 16)

#define L1_SECT_AP_URW       (1 << 10) | (1 << 11)
#define L1_SECT_PFN(x)       (x & 0xFFF00000)

#define L1_SECT_DEFPROT      (L1_SECT_AP_URW)
#define L1_SECT_DEFCACHE     (L1_SECT_SORDER)

#define L1_SECT_APX         (1 << 15)
#define L1_PAGE_PROTO       (1 << 0)
#define L1_COARSE_PT        (0xFFFFFC00)
#define PT_SIZE             256
#define L2_PAGE_APX         (1 << 9)

#define L1_PROTO_TTE(paddr)  (L1_SECT_PFN(paddr) | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE | L1_SECT_PROTO)

#define PFN_SHIFT            2
#define TTB_OFFSET(vaddr)    ((vaddr >> L1_SHIFT) << PFN_SHIFT)

#define TTB_SIZE                4096
#define DEFAULT_KERNEL_SLIDE    0x80000000
#define KDUMP_SIZE              0x1200000
#define CHUNK_SIZE              2048


mach_port_t tfp0;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);
kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

void copyin(void* to, uint32_t from, size_t size) {
    mach_vm_size_t outsize = size;
    size_t szt = size;
    if (size > 0x1000) {
        size = 0x1000;
    }
    size_t off = 0;
    while (1) {
        mach_vm_read_overwrite(tfp0, off+from, size, (mach_vm_offset_t)(off+to), &outsize);
        szt -= size;
        off += size;
        if (szt == 0) {
            break;
        }
        size = szt;
        if (size > 0x1000) {
            size = 0x1000;
        }
        
    }
}

void copyout(uint32_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint32_t rk32(uint32_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint32_t wk32(uint32_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

uint32_t wk16(uint32_t addr, uint16_t val) {
    copyout(addr, &val, 2);
    return val;
}
/* -- end -- */

mach_port_t get_kernel_task() {
    task_t kernel_task;
    if (KERN_SUCCESS != task_for_pid(mach_task_self(), 0, &kernel_task)) {
        if (KERN_SUCCESS != host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kernel_task)){
            return -1;
        }
        return kernel_task;
    }
    return kernel_task;
}

/*--- 32bit ---*/
vm_address_t get_kernel_base() {
    vm_region_submap_info_data_64_t info;
    vm_size_t size;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    vm_address_t addr = 0x81200000;
    while (1) {
        if (KERN_SUCCESS != vm_region_recurse_64(tfp0, &addr, &size, &depth, (vm_region_info_t) & info, &info_count))
            break;
        if (size > 1024 * 1024 * 1024) {
            /*
             * https://code.google.com/p/iphone-dataprotection/
             * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
             */
            pointer_t buf;
            mach_msg_type_number_t sz = 0;
            addr += 0x200000;
            vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
            if (*((uint32_t *)buf) != MH_MAGIC) {
                addr -= 0x200000;
                vm_read(tfp0, addr + 0x1000, 512, &buf, &sz);
                if (*((uint32_t*)buf) != MH_MAGIC) {
                    break;
                }
            }
            vm_address_t kbase = addr + 0x1000;
            return kbase;
        }
        addr += size;
    }
    return -1;
}

void dump_kernel(vm_address_t kernel_base, uint8_t *dest, size_t ksize) {
    for (vm_address_t addr = kernel_base, e = 0; addr < kernel_base + ksize; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
        pointer_t buf = 0;
        vm_address_t sz = 0;
        vm_read(tfp0, addr, CHUNK_SIZE, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
    }
}

/*-- jailbreak --*/
void patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page) {
    uint32_t i = page >> 20;
    uint32_t j = (page >> 12) & 0xFF;
    uint32_t addr = tte_virt+(i<<2);
    uint32_t entry = rk32(addr);
    if ((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO) {
        uint32_t page_entry = ((entry & L1_COARSE_PT) - tte_phys) + tte_virt;
        uint32_t addr2 = page_entry+(j<<2);
        uint32_t entry2 = rk32(addr2);
        if (entry2) {
            uint32_t new_entry2 = (entry2 & (~L2_PAGE_APX));
            wk32(addr2, new_entry2);
        }
    } else if ((entry & L1_SECT_PROTO) == L1_SECT_PROTO) {
        uint32_t new_entry = L1_PROTO_TTE(entry);
        new_entry &= ~L1_SECT_APX;
        wk32(addr, new_entry);
    }
    usleep(200000);
}

int find_ios_version() {
    struct utsname u = { 0 };
    uname(&u);
    if (strcmp(u.release, "15.0.0") == 0 ||
        strcmp(u.release, "15.4.0") == 0 ||
        strcmp(u.release, "15.5.0") == 0 ||
        strcmp(u.release, "15.6.0") == 0){
        return 9;
    }
    
    if (strcmp(u.release, "16.0.0") == 0 ||
        strcmp(u.release, "16.1.0") == 0 ||
        strcmp(u.release, "16.3.0") == 0 ||
        strcmp(u.release, "16.5.0") == 0 ||
        strcmp(u.release, "16.6.0") == 0 ||
        strcmp(u.release, "16.7.0") == 0){
        return 10;
    }
    
    return -1;
}

void usage(char** argv) {
    printf("sysent_patcher v1.4\n");
    printf("[2020/12/27] by dora2ios\n");
    printf("Supported devices: iOS 9 - 10 (32-bit only)\n");
    printf("\n");
    printf("usage: %s [options]\n", argv[0]);
    printf("\t-p\t\tpatch syscall(188)\n");
    printf("\n");
    printf("!!!! warning !!!!\n");
    printf("This software patches the kernel. As a result, the entire system may become unstable.\n");
}

int main(int argc, char** argv){
    
#define PAYLOAD         0x80001c00
    
    int pwn_syscall;
    
    if(argc == 1) {
        usage(argv);
        return -1;
    }
    
    if(!strcmp(argv[1], "-p")) {
        pwn_syscall = 1;
    }
    
    if(pwn_syscall == 1){
        
        int iosver;
        
        iosver = find_ios_version();
        if(iosver == -1){
            printf("Failed to get ios version!\n");
            return -1;
        }
        
        tfp0 = get_kernel_task();
        if (!tfp0) {
            printf("Failed to get tfp0!\n");
            return -1;
        }
        printf("tfp0: %08x\n", tfp0);
        
        uint32_t kbase = get_kernel_base();
        if (!kbase) {
            printf("Failed to get kernel base!\n");
            return -1;
        }
        printf("kernel_base: %08x\n", kbase);
        
        uint32_t kslide = kbase - 0x80001000;
        printf("kslide: %08x\n", kslide);
        
        unsigned char *kdump;
        size_t ksize = KDUMP_SIZE;
        
        kdump = malloc(ksize);
        dump_kernel(kbase, kdump, ksize);
        if (!(*(uint32_t*)&kdump[0] == MH_MAGIC)) {
            printf("Failed to dump kernel!\n");
            return -1;
        }
        
        uint32_t kernel_pmap = kbase + get_kernel_pmap(kbase, kdump, ksize);
        if (!kbase) {
            printf("Failed to get kernel_pmap!\n");
            return -1;
        }
        printf("kernel_pmap: %08x\n", kernel_pmap);
        
        uint32_t kernel_pmap_store = rk32(kernel_pmap);
        uint32_t tte_virt = rk32(kernel_pmap_store);
        uint32_t tte_phys = rk32(kernel_pmap_store+4);
        
        printf("virt: %08x, phys: %08x\n", tte_virt, tte_phys);
        
        /* offsetfinder */
        uint32_t payload;
        uint32_t payload_start;
        uint32_t _copyinstr;
        uint32_t _IOLog;
        uint32_t _sysent_stat;
        uint32_t _syscall_stat;
        uint32_t _strcmp;
        uint32_t logdump;
        uint32_t blockdump;
        
        payload = PAYLOAD + kslide;
        payload_start = payload + 0x69;
        
        _copyinstr = find_copyinstr(kbase, kdump, ksize);
        _strcmp = find_strcmp(kbase, kdump, ksize);
        logdump = get_kernel_str(kbase, kdump, ksize, "%s: %s\n");
        blockdump = get_kernel_str(kbase, kdump, ksize, "path");
        
        if(iosver == 10){
            _IOLog = find_IOLog_post_iOSX(kbase, kdump, ksize);
            _sysent_stat = kbase + find_syscall188_post_iOSX(kbase, kdump, ksize, 0);
            _syscall_stat = find_syscall188_post_iOSX(kbase, kdump, ksize, 1);
        }
        
        if(iosver == 9){
            _IOLog = find_IOLog(kbase, kdump, ksize);
            _sysent_stat = kbase + find_syscall188(kbase, kdump, ksize, 0);
            _syscall_stat = find_syscall188(kbase, kdump, ksize, 1);
        }
        
        if((_syscall_stat + kbase) == payload_start){
            printf("Already patched.\n");
            return 0;
        }
        
        patch_page_table(tte_virt, tte_phys, _sysent_stat & ~0xFFF);
        patch_page_table(tte_virt, tte_phys, payload & ~0xFFF);
        
        /*
         * payload
         * 80001c00: _pre_strcmp
         * 80001c04: .data START
         * 80001c64: .data END
         * 80001c68: .text START, _payload
         * 80001c84: blx _copyinstr
         * 80001c96: bl  _IOLog
         * 80001dbc: bl  _orig_stat
         */
        
        copyout(payload, sysent_stat_bin, sysent_stat_bin_sz);
        
        // Use make_b_w instead of static offsets
        wk32(payload + 0x0000, make_b_w(0xc00, _strcmp)); // range: 0x10000000
        
        /* fix ptr */
        wk32(payload + 0x0004, logdump + kbase);
        wk32(payload + 0x0008, blockdump + kbase);
        wk32(payload + 0x000c, 0x000003e7 + payload);
        wk32(payload + 0x0010, 0x000003e1 + payload);
        wk32(payload + 0x0014, 0x000003dc + payload);
        wk32(payload + 0x0018, 0x000003d7 + payload);
        wk32(payload + 0x001c, 0x000003bf + payload);
        wk32(payload + 0x0020, 0x000003ae + payload);
        wk32(payload + 0x0024, 0x000003a5 + payload);
        wk32(payload + 0x0028, 0x00000371 + payload);
        wk32(payload + 0x002c, 0x00000345 + payload);
        wk32(payload + 0x0030, 0x00000334 + payload);
        wk32(payload + 0x0034, 0x0000031b + payload);
        wk32(payload + 0x0038, 0x000002ee + payload);
        wk32(payload + 0x003c, 0x000002d8 + payload);
        wk32(payload + 0x0040, 0x000002ca + payload);
        wk32(payload + 0x0044, 0x000002b7 + payload);
        wk32(payload + 0x0048, 0x000002ac + payload);
        wk32(payload + 0x004c, 0x00000290 + payload);
        wk32(payload + 0x0050, 0x0000027a + payload);
        wk32(payload + 0x0054, 0x00000242 + payload);
        wk32(payload + 0x0058, 0x0000022b + payload);
        wk32(payload + 0x005c, 0x000001f2 + payload);
        wk32(payload + 0x0060, 0x000001d8 + payload);
        wk32(payload + 0x0064, 0x000001d0 + payload);
        
        wk32(payload + 0x01c8, 0x00000004 + payload);
        
        
        /* make bl(x) */
        // Use make_bl instead of static offsets // range: 0x400000
        wk32(payload + 0x0084, make_bl(1, 0xc84, _copyinstr));
        wk32(payload + 0x0096, make_bl(0, 0xc96, _IOLog));
        wk32(payload + 0x01bc, make_bl(0, 0xdbc, _syscall_stat));
        
        /*
         * fix bl
         * global offsets
         */
        wk32(payload + 0x009e, 0xffaff7ff); // bl _pre_strcmp
        wk32(payload + 0x00aa, 0xffa9f7ff); // bl _pre_strcmp
        wk32(payload + 0x00b6, 0xffa3f7ff); // bl _pre_strcmp
        wk32(payload + 0x00c2, 0xff9df7ff); // bl _pre_strcmp
        wk32(payload + 0x00ce, 0xff97f7ff); // bl _pre_strcmp
        wk32(payload + 0x00da, 0xff91f7ff); // bl _pre_strcmp
        wk32(payload + 0x00e6, 0xff8bf7ff); // bl _pre_strcmp
        wk32(payload + 0x00f2, 0xff85f7ff); // bl _pre_strcmp
        wk32(payload + 0x00fe, 0xff7ff7ff); // bl _pre_strcmp
        wk32(payload + 0x010a, 0xff79f7ff); // bl _pre_strcmp
        wk32(payload + 0x0116, 0xff73f7ff); // bl _pre_strcmp
        wk32(payload + 0x0122, 0xff6df7ff); // bl _pre_strcmp
        wk32(payload + 0x012e, 0xff67f7ff); // bl _pre_strcmp
        wk32(payload + 0x013a, 0xff61f7ff); // bl _pre_strcmp
        wk32(payload + 0x0146, 0xff5bf7ff); // bl _pre_strcmp
        wk32(payload + 0x0152, 0xff55f7ff); // bl _pre_strcmp
        wk32(payload + 0x015e, 0xff4ff7ff); // bl _pre_strcmp
        wk32(payload + 0x016a, 0xff49f7ff); // bl _pre_strcmp
        wk32(payload + 0x0176, 0xff43f7ff); // bl _pre_strcmp
        wk32(payload + 0x0182, 0xff3df7ff); // bl _pre_strcmp
        wk32(payload + 0x0190, 0xff36f7ff); // bl _pre_strcmp
        wk32(payload + 0x019e, 0xff2ff7ff); // bl _pre_strcmp
        wk32(payload + 0x01ac, 0xff28f7ff); // bl _pre_strcmp
        
        /*
         * hook sysent
         * orig_stat -> _payload
         */
        wk32(_sysent_stat, payload_start);
        
        printf("DONE!?\n");
    }
    
    return 0;
}

/* svc list
 * stat, symlink, __sysctl, getpid, ptrace
 */
