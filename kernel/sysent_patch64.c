/* sysent_patch64.c: Patch the kernel and hook syscall(188)
 * 2021/01/01
 * made by dora2ios
 *
 */

#include <stdio.h>
#include <mach/mach.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <mach-o/loader.h>

#include "patchfinder64/patchfinder64.h"

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS 0xfffffff007004000
#define ptrSize sizeof(uintptr_t)

// krnl offsets: for n51, 10.2.1(14d27)
uint64_t OFFSETOF_COPYINSTR = 0xfffffff007183734;
uint64_t OFFSETOF_STRCMP = 0xfffffff007166d78;
uint64_t OFFSETOF_IOLOG = 0xfffffff0074653d0;
uint64_t OFFSETOF_SYSENT_STAT = 0xfffffff007067798;

mach_port_t tfp0;

kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);

void copyin(void* to, uint64_t from, size_t size) {
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

void copyout(uint64_t to, void* from, size_t size) {
    mach_vm_write(tfp0, to, (vm_offset_t)from, (mach_msg_type_number_t)size);
}

uint64_t ReadAnywhere16(uint64_t addr) {
    uint16_t val = 0;
    copyin(&val, addr, 2);
    return val;
}

uint64_t ReadAnywhere32(uint64_t addr) {
    uint32_t val = 0;
    copyin(&val, addr, 4);
    return val;
}

uint64_t WriteAnywhere32(uint64_t addr, uint32_t val) {
    copyout(addr, &val, 4);
    return val;
}

uint64_t ReadAnywhere64(uint64_t addr) {
    uint64_t val = 0;
    copyin(&val, addr, 8);
    return val;
}

uint64_t WriteAnywhere64(uint64_t addr, uint64_t val) {
    copyout(addr, &val, 8);
    return val;
}


task_t get_kernel_task() {
    task_t kt = 0;
    kern_return_t r = task_for_pid(mach_task_self(), 0, &kt);
    
    if (r) {
        r = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &kt);
        if (r) {
            printf("task_for_pid and host_get_special_port failed\n");
            exit(-1);
        }
    }
    
    return kt;
}

uint64_t get_kernel_base(mach_port_t kernel_task) {
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS+MAX_KASLR_SLIDE;
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(kernel_task, addr, 0x200, (vm_offset_t*)&buf, &sz);
        if (ret) {
            goto next;
        }
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(kernel_task, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(kernel_task, i, 0x120, (vm_offset_t*)&buf, &sz);
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    return 0;
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
    next:
        addr -= 0x200000;
    }
    printf("ERROR: Failed to find kernel base.\n");
    return 0;
}

#include "patchfinder64/pte_stuff.h"

uint64_t gPhysBase;
uint64_t gVirtBase;
uint64_t level1_table;

void kpp(int uref, uint64_t kernbase, uint64_t slide){
    
    int hooked;
    
    checkvad();
    uint64_t entryp;
    
    int rv = init_kernel(kernbase, NULL);
    assert(rv == 0);
    
    /*
     *  @qwertyoruiop's KPP bypass
     *
     *
     */
    
    
    // hook sysent_stat
    {
        uint64_t payload_base = 0;
        kern_return_t err = mach_vm_allocate(tfp0, &payload_base, isvad == 0 ? 0x4000 : 0x1000, VM_FLAGS_ANYWHERE);
        
        uint64_t copyinstr_ptr = OFFSETOF_COPYINSTR + slide;
        uint64_t strcmp_ptr = OFFSETOF_STRCMP + slide;
        uint64_t IOLog_ptr = OFFSETOF_IOLOG + slide;
        uint64_t sysent_stat_addr = OFFSETOF_SYSENT_STAT + slide;
        uint64_t orig_stat = ReadAnywhere64(sysent_stat_addr);
        
        printf("sysent_stat_addr: 0x%016llx\n", sysent_stat_addr);
        printf("orig_stat: 0x%016llx\n", orig_stat);
        printf("copyinstr: 0x%016llx\n", copyinstr_ptr);
        printf("strcmp: 0x%016llx\n", strcmp_ptr);
        printf("IOLog: 0x%016llx\n", IOLog_ptr); // not work??
        
        printf("allocate: 0x%x\n", err);
        printf("payload_base: 0x%016llx\n", payload_base);
        
        printf("writing payload...\n");
        // Section __text
        // Range: [0x0; 0x2d8[ (728 bytes)
        WriteAnywhere32(0x000 + payload_base, 0xa9bc6ffc);
        WriteAnywhere32(0x004 + payload_base, 0xa90157f6);
        WriteAnywhere32(0x008 + payload_base, 0xa9024ff4);
        WriteAnywhere32(0x00c + payload_base, 0xa9037bfd);
        WriteAnywhere32(0x010 + payload_base, 0x9100c3fd);
        WriteAnywhere32(0x014 + payload_base, 0xd11083ff);
        WriteAnywhere32(0x018 + payload_base, 0xaa0103f4);
        WriteAnywhere32(0x01c + payload_base, 0xf9000fff);
        WriteAnywhere32(0x020 + payload_base, 0x90000008);
        WriteAnywhere32(0x024 + payload_base, 0xf942f909);
        WriteAnywhere32(0x028 + payload_base, 0xf9400288);
        WriteAnywhere32(0x02c + payload_base, 0xaa0203f3);
        WriteAnywhere32(0x030 + payload_base, 0xaa0003f5);
        WriteAnywhere32(0x034 + payload_base, 0x910083e1);
        WriteAnywhere32(0x038 + payload_base, 0x321603e2);
        WriteAnywhere32(0x03c + payload_base, 0x910063e3);
        WriteAnywhere32(0x040 + payload_base, 0xaa0803e0);
        WriteAnywhere32(0x044 + payload_base, 0x910083f6);
        WriteAnywhere32(0x048 + payload_base, 0xd63f0120);
        WriteAnywhere32(0x04c + payload_base, 0x34000100);
        WriteAnywhere32(0x050 + payload_base, 0x321f03e0);
        WriteAnywhere32(0x054 + payload_base, 0x911083ff);
        WriteAnywhere32(0x058 + payload_base, 0xa9437bfd);
        WriteAnywhere32(0x05c + payload_base, 0xa9424ff4);
        WriteAnywhere32(0x060 + payload_base, 0xa94157f6);
        WriteAnywhere32(0x064 + payload_base, 0xa8c46ffc);
        WriteAnywhere32(0x068 + payload_base, 0xd65f03c0);
        WriteAnywhere32(0x06c + payload_base, 0x90000008);
        WriteAnywhere32(0x070 + payload_base, 0x90000009);
        WriteAnywhere32(0x074 + payload_base, 0x9000000a);
        WriteAnywhere32(0x078 + payload_base, 0xf9430108);
        WriteAnywhere32(0x07c + payload_base, 0xf942ed20);
        WriteAnywhere32(0x080 + payload_base, 0xf942f149);
        WriteAnywhere32(0x084 + payload_base, 0xa9005be9);
        WriteAnywhere32(0x088 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x08c + payload_base, 0x90000016);
        WriteAnywhere32(0x090 + payload_base, 0x90000008);
        WriteAnywhere32(0x094 + payload_base, 0xf942fec9);
        WriteAnywhere32(0x098 + payload_base, 0xf9429101);
        WriteAnywhere32(0x09c + payload_base, 0x910083e0);
        WriteAnywhere32(0x0a0 + payload_base, 0xd63f0120);
        WriteAnywhere32(0x0a4 + payload_base, 0x34fffd60);
        WriteAnywhere32(0x0a8 + payload_base, 0x90000009);
        WriteAnywhere32(0x0ac + payload_base, 0xf942fec8);
        WriteAnywhere32(0x0b0 + payload_base, 0xf9429521);
        WriteAnywhere32(0x0b4 + payload_base, 0x910083e0);
        WriteAnywhere32(0x0b8 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x0bc + payload_base, 0x34fffca0);
        WriteAnywhere32(0x0c0 + payload_base, 0x90000009);
        WriteAnywhere32(0x0c4 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x0c8 + payload_base, 0xf9429921);
        WriteAnywhere32(0x0cc + payload_base, 0x910083e0);
        WriteAnywhere32(0x0d0 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x0d4 + payload_base, 0x34fffbe0);
        WriteAnywhere32(0x0d8 + payload_base, 0x90000009);
        WriteAnywhere32(0x0dc + payload_base, 0xf942fec8);
        WriteAnywhere32(0x0e0 + payload_base, 0xf9429d21);
        WriteAnywhere32(0x0e4 + payload_base, 0x910083e0);
        WriteAnywhere32(0x0e8 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x0ec + payload_base, 0x34fffb20);
        WriteAnywhere32(0x0f0 + payload_base, 0x90000009);
        WriteAnywhere32(0x0f4 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x0f8 + payload_base, 0xf942a121);
        WriteAnywhere32(0x0fc + payload_base, 0x910083e0);
        WriteAnywhere32(0x100 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x104 + payload_base, 0x34fffa60);
        WriteAnywhere32(0x108 + payload_base, 0x90000009);
        WriteAnywhere32(0x10c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x110 + payload_base, 0xf942a521);
        WriteAnywhere32(0x114 + payload_base, 0x910083e0);
        WriteAnywhere32(0x118 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x11c + payload_base, 0x34fff9a0);
        WriteAnywhere32(0x120 + payload_base, 0x90000009);
        WriteAnywhere32(0x124 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x128 + payload_base, 0xf942a921);
        WriteAnywhere32(0x12c + payload_base, 0x910083e0);
        WriteAnywhere32(0x130 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x134 + payload_base, 0x34fff8e0);
        WriteAnywhere32(0x138 + payload_base, 0x90000009);
        WriteAnywhere32(0x13c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x140 + payload_base, 0xf942ad21);
        WriteAnywhere32(0x144 + payload_base, 0x910083e0);
        WriteAnywhere32(0x148 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x14c + payload_base, 0x34fff820);
        WriteAnywhere32(0x150 + payload_base, 0x90000009);
        WriteAnywhere32(0x154 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x158 + payload_base, 0xf942b121);
        WriteAnywhere32(0x15c + payload_base, 0x910083e0);
        WriteAnywhere32(0x160 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x164 + payload_base, 0x34fff760);
        WriteAnywhere32(0x168 + payload_base, 0x90000009);
        WriteAnywhere32(0x16c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x170 + payload_base, 0xf942b521);
        WriteAnywhere32(0x174 + payload_base, 0x910083e0);
        WriteAnywhere32(0x178 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x17c + payload_base, 0x34fff6a0);
        WriteAnywhere32(0x180 + payload_base, 0x90000009);
        WriteAnywhere32(0x184 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x188 + payload_base, 0xf942b921);
        WriteAnywhere32(0x18c + payload_base, 0x910083e0);
        WriteAnywhere32(0x190 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x194 + payload_base, 0x34fff5e0);
        WriteAnywhere32(0x198 + payload_base, 0x90000009);
        WriteAnywhere32(0x19c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x1a0 + payload_base, 0xf942bd21);
        WriteAnywhere32(0x1a4 + payload_base, 0x910083e0);
        WriteAnywhere32(0x1a8 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x1ac + payload_base, 0x34fff520);
        WriteAnywhere32(0x1b0 + payload_base, 0x90000009);
        WriteAnywhere32(0x1b4 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x1b8 + payload_base, 0xf942c121);
        WriteAnywhere32(0x1bc + payload_base, 0x910083e0);
        WriteAnywhere32(0x1c0 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x1c4 + payload_base, 0x34fff460);
        WriteAnywhere32(0x1c8 + payload_base, 0x90000009);
        WriteAnywhere32(0x1cc + payload_base, 0xf942fec8);
        WriteAnywhere32(0x1d0 + payload_base, 0xf942c521);
        WriteAnywhere32(0x1d4 + payload_base, 0x910083e0);
        WriteAnywhere32(0x1d8 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x1dc + payload_base, 0x34fff3a0);
        WriteAnywhere32(0x1e0 + payload_base, 0x90000009);
        WriteAnywhere32(0x1e4 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x1e8 + payload_base, 0xf942c921);
        WriteAnywhere32(0x1ec + payload_base, 0x910083e0);
        WriteAnywhere32(0x1f0 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x1f4 + payload_base, 0x34fff2e0);
        WriteAnywhere32(0x1f8 + payload_base, 0x90000009);
        WriteAnywhere32(0x1fc + payload_base, 0xf942fec8);
        WriteAnywhere32(0x200 + payload_base, 0xf942cd21);
        WriteAnywhere32(0x204 + payload_base, 0x910083e0);
        WriteAnywhere32(0x208 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x20c + payload_base, 0x34fff220);
        WriteAnywhere32(0x210 + payload_base, 0x90000009);
        WriteAnywhere32(0x214 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x218 + payload_base, 0xf942d121);
        WriteAnywhere32(0x21c + payload_base, 0x910083e0);
        WriteAnywhere32(0x220 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x224 + payload_base, 0x34fff160);
        WriteAnywhere32(0x228 + payload_base, 0x90000009);
        WriteAnywhere32(0x22c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x230 + payload_base, 0xf942d521);
        WriteAnywhere32(0x234 + payload_base, 0x910083e0);
        WriteAnywhere32(0x238 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x23c + payload_base, 0x34fff0a0);
        WriteAnywhere32(0x240 + payload_base, 0x90000009);
        WriteAnywhere32(0x244 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x248 + payload_base, 0xf942d921);
        WriteAnywhere32(0x24c + payload_base, 0x910083e0);
        WriteAnywhere32(0x250 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x254 + payload_base, 0x34ffefe0);
        WriteAnywhere32(0x258 + payload_base, 0x90000009);
        WriteAnywhere32(0x25c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x260 + payload_base, 0xf942dd21);
        WriteAnywhere32(0x264 + payload_base, 0x910083e0);
        WriteAnywhere32(0x268 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x26c + payload_base, 0x34ffef20);
        WriteAnywhere32(0x270 + payload_base, 0x90000009);
        WriteAnywhere32(0x274 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x278 + payload_base, 0xf942e121);
        WriteAnywhere32(0x27c + payload_base, 0x910083e0);
        WriteAnywhere32(0x280 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x284 + payload_base, 0x34ffee60);
        WriteAnywhere32(0x288 + payload_base, 0x90000009);
        WriteAnywhere32(0x28c + payload_base, 0xf942fec8);
        WriteAnywhere32(0x290 + payload_base, 0xf942e521);
        WriteAnywhere32(0x294 + payload_base, 0x910083e0);
        WriteAnywhere32(0x298 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x29c + payload_base, 0x34ffeda0);
        WriteAnywhere32(0x2a0 + payload_base, 0x90000009);
        WriteAnywhere32(0x2a4 + payload_base, 0xf942fec8);
        WriteAnywhere32(0x2a8 + payload_base, 0xf942e921);
        WriteAnywhere32(0x2ac + payload_base, 0x910083e0);
        WriteAnywhere32(0x2b0 + payload_base, 0xd63f0100);
        WriteAnywhere32(0x2b4 + payload_base, 0x34ffece0);
        WriteAnywhere32(0x2b8 + payload_base, 0x90000008);
        WriteAnywhere32(0x2bc + payload_base, 0xf942f508);
        WriteAnywhere32(0x2c0 + payload_base, 0xaa1503e0);
        WriteAnywhere32(0x2c4 + payload_base, 0xaa1403e1);
        WriteAnywhere32(0x2c8 + payload_base, 0xaa1303e2);
        WriteAnywhere32(0x2cc + payload_base, 0xd63f0100);
        WriteAnywhere32(0x2d0 + payload_base, 0x93407c00);
        WriteAnywhere32(0x2d4 + payload_base, 0x17ffff60);
        
        
        // Section __cstring
        // Range: [0x2d8; 0x51e[ (582 bytes)
        WriteAnywhere32(0x2d8 + payload_base, 0x6573552f);
        WriteAnywhere32(0x2dc + payload_base, 0x622f0072);
        WriteAnywhere32(0x2e0 + payload_base, 0x00746f6f);
        WriteAnywhere32(0x2e4 + payload_base, 0x62696c2f);
        WriteAnywhere32(0x2e8 + payload_base, 0x6e6d2f00);
        WriteAnywhere32(0x2ec + payload_base, 0x412f0074);
        WriteAnywhere32(0x2f0 + payload_base, 0x696c7070);
        WriteAnywhere32(0x2f4 + payload_base, 0x69746163);
        WriteAnywhere32(0x2f8 + payload_base, 0x2f736e6f);
        WriteAnywhere32(0x2fc + payload_base, 0x69647943);
        WriteAnywhere32(0x300 + payload_base, 0x70612e61);
        WriteAnywhere32(0x304 + payload_base, 0x702f0070);
        WriteAnywhere32(0x308 + payload_base, 0x61766972);
        WriteAnywhere32(0x30c + payload_base, 0x762f6574);
        WriteAnywhere32(0x310 + payload_base, 0x6c2f7261);
        WriteAnywhere32(0x314 + payload_base, 0x2f006269);
        WriteAnywhere32(0x318 + payload_base, 0x2f726176);
        WriteAnywhere32(0x31c + payload_base, 0x0062696c);
        WriteAnywhere32(0x320 + payload_base, 0x6972702f);
        WriteAnywhere32(0x324 + payload_base, 0x65746176);
        WriteAnywhere32(0x328 + payload_base, 0x7261762f);
        WriteAnywhere32(0x32c + payload_base, 0x626f6d2f);
        WriteAnywhere32(0x330 + payload_base, 0x2f656c69);
        WriteAnywhere32(0x334 + payload_base, 0x7262694c);
        WriteAnywhere32(0x338 + payload_base, 0x2f797261);
        WriteAnywhere32(0x33c + payload_base, 0x68636143);
        WriteAnywhere32(0x340 + payload_base, 0x632f7365);
        WriteAnywhere32(0x344 + payload_base, 0x732e6d6f);
        WriteAnywhere32(0x348 + payload_base, 0x69727561);
        WriteAnywhere32(0x34c + payload_base, 0x79432e6b);
        WriteAnywhere32(0x350 + payload_base, 0x00616964);
        WriteAnywhere32(0x354 + payload_base, 0x7261762f);
        WriteAnywhere32(0x358 + payload_base, 0x626f6d2f);
        WriteAnywhere32(0x35c + payload_base, 0x2f656c69);
        WriteAnywhere32(0x360 + payload_base, 0x7262694c);
        WriteAnywhere32(0x364 + payload_base, 0x2f797261);
        WriteAnywhere32(0x368 + payload_base, 0x68636143);
        WriteAnywhere32(0x36c + payload_base, 0x632f7365);
        WriteAnywhere32(0x370 + payload_base, 0x732e6d6f);
        WriteAnywhere32(0x374 + payload_base, 0x69727561);
        WriteAnywhere32(0x378 + payload_base, 0x79432e6b);
        WriteAnywhere32(0x37c + payload_base, 0x00616964);
        WriteAnywhere32(0x380 + payload_base, 0x6972702f);
        WriteAnywhere32(0x384 + payload_base, 0x65746176);
        WriteAnywhere32(0x388 + payload_base, 0x6374652f);
        WriteAnywhere32(0x38c + payload_base, 0x6873732f);
        WriteAnywhere32(0x390 + payload_base, 0x694c2f00);
        WriteAnywhere32(0x394 + payload_base, 0x72617262);
        WriteAnywhere32(0x398 + payload_base, 0x6f4d2f79);
        WriteAnywhere32(0x39c + payload_base, 0x656c6962);
        WriteAnywhere32(0x3a0 + payload_base, 0x73627553);
        WriteAnywhere32(0x3a4 + payload_base, 0x74617274);
        WriteAnywhere32(0x3a8 + payload_base, 0x4c2f0065);
        WriteAnywhere32(0x3ac + payload_base, 0x61726269);
        WriteAnywhere32(0x3b0 + payload_base, 0x462f7972);
        WriteAnywhere32(0x3b4 + payload_base, 0x656d6172);
        WriteAnywhere32(0x3b8 + payload_base, 0x6b726f77);
        WriteAnywhere32(0x3bc + payload_base, 0x79432f73);
        WriteAnywhere32(0x3c0 + payload_base, 0x53616964);
        WriteAnywhere32(0x3c4 + payload_base, 0x74736275);
        WriteAnywhere32(0x3c8 + payload_base, 0x65746172);
        WriteAnywhere32(0x3cc + payload_base, 0x6172662e);
        WriteAnywhere32(0x3d0 + payload_base, 0x6f77656d);
        WriteAnywhere32(0x3d4 + payload_base, 0x2f006b72);
        WriteAnywhere32(0x3d8 + payload_base, 0x76697270);
        WriteAnywhere32(0x3dc + payload_base, 0x2f657461);
        WriteAnywhere32(0x3e0 + payload_base, 0x2f726176);
        WriteAnywhere32(0x3e4 + payload_base, 0x732f6264);
        WriteAnywhere32(0x3e8 + payload_base, 0x68736174);
        WriteAnywhere32(0x3ec + payload_base, 0x61762f00);
        WriteAnywhere32(0x3f0 + payload_base, 0x62642f72);
        WriteAnywhere32(0x3f4 + payload_base, 0x6174732f);
        WriteAnywhere32(0x3f8 + payload_base, 0x2f006873);
        WriteAnywhere32(0x3fc + payload_base, 0x76697270);
        WriteAnywhere32(0x400 + payload_base, 0x2f657461);
        WriteAnywhere32(0x404 + payload_base, 0x2f726176);
        WriteAnywhere32(0x408 + payload_base, 0x73617473);
        WriteAnywhere32(0x40c + payload_base, 0x762f0068);
        WriteAnywhere32(0x410 + payload_base, 0x732f7261);
        WriteAnywhere32(0x414 + payload_base, 0x68736174);
        WriteAnywhere32(0x418 + payload_base, 0x73752f00);
        WriteAnywhere32(0x41c + payload_base, 0x696c2f72);
        WriteAnywhere32(0x420 + payload_base, 0x696c2f62);
        WriteAnywhere32(0x424 + payload_base, 0x62757362);
        WriteAnywhere32(0x428 + payload_base, 0x61727473);
        WriteAnywhere32(0x42c + payload_base, 0x642e6574);
        WriteAnywhere32(0x430 + payload_base, 0x62696c79);
        WriteAnywhere32(0x434 + payload_base, 0x694c2f00);
        WriteAnywhere32(0x438 + payload_base, 0x72617262);
        WriteAnywhere32(0x43c + payload_base, 0x72422f79);
        WriteAnywhere32(0x440 + payload_base, 0x546b6165);
        WriteAnywhere32(0x444 + payload_base, 0x756f7268);
        WriteAnywhere32(0x448 + payload_base, 0x2f006867);
        WriteAnywhere32(0x44c + payload_base, 0x7262694c);
        WriteAnywhere32(0x450 + payload_base, 0x2f797261);
        WriteAnywhere32(0x454 + payload_base, 0x66657250);
        WriteAnywhere32(0x458 + payload_base, 0x6e657265);
        WriteAnywhere32(0x45c + payload_base, 0x6f4c6563);
        WriteAnywhere32(0x460 + payload_base, 0x72656461);
        WriteAnywhere32(0x464 + payload_base, 0x6572502f);
        WriteAnywhere32(0x468 + payload_base, 0x65726566);
        WriteAnywhere32(0x46c + payload_base, 0x7365636e);
        WriteAnywhere32(0x470 + payload_base, 0x62694c2f);
        WriteAnywhere32(0x474 + payload_base, 0x79747265);
        WriteAnywhere32(0x478 + payload_base, 0x66657250);
        WriteAnywhere32(0x47c + payload_base, 0x696c702e);
        WriteAnywhere32(0x480 + payload_base, 0x2f007473);
        WriteAnywhere32(0x484 + payload_base, 0x6c707041);
        WriteAnywhere32(0x488 + payload_base, 0x74616369);
        WriteAnywhere32(0x48c + payload_base, 0x736e6f69);
        WriteAnywhere32(0x490 + payload_base, 0x656c462f);
        WriteAnywhere32(0x494 + payload_base, 0x70612e78);
        WriteAnywhere32(0x498 + payload_base, 0x4c2f0070);
        WriteAnywhere32(0x49c + payload_base, 0x61726269);
        WriteAnywhere32(0x4a0 + payload_base, 0x502f7972);
        WriteAnywhere32(0x4a4 + payload_base, 0x65666572);
        WriteAnywhere32(0x4a8 + payload_base, 0x636e6572);
        WriteAnywhere32(0x4ac + payload_base, 0x616f4c65);
        WriteAnywhere32(0x4b0 + payload_base, 0x2f726564);
        WriteAnywhere32(0x4b4 + payload_base, 0x66657250);
        WriteAnywhere32(0x4b8 + payload_base, 0x6e657265);
        WriteAnywhere32(0x4bc + payload_base, 0x2f736563);
        WriteAnywhere32(0x4c0 + payload_base, 0x75536f4e);
        WriteAnywhere32(0x4c4 + payload_base, 0x69747362);
        WriteAnywhere32(0x4c8 + payload_base, 0x65747574);
        WriteAnywhere32(0x4cc + payload_base, 0x696c702e);
        WriteAnywhere32(0x4d0 + payload_base, 0x2f007473);
        WriteAnywhere32(0x4d4 + payload_base, 0x76697270);
        WriteAnywhere32(0x4d8 + payload_base, 0x2f657461);
        WriteAnywhere32(0x4dc + payload_base, 0x2f726176);
        WriteAnywhere32(0x4e0 + payload_base, 0x69626f6d);
        WriteAnywhere32(0x4e4 + payload_base, 0x4c2f656c);
        WriteAnywhere32(0x4e8 + payload_base, 0x61726269);
        WriteAnywhere32(0x4ec + payload_base, 0x462f7972);
        WriteAnywhere32(0x4f0 + payload_base, 0x3378656c);
        WriteAnywhere32(0x4f4 + payload_base, 0x61762f00);
        WriteAnywhere32(0x4f8 + payload_base, 0x6f6d2f72);
        WriteAnywhere32(0x4fc + payload_base, 0x656c6962);
        WriteAnywhere32(0x500 + payload_base, 0x62694c2f);
        WriteAnywhere32(0x504 + payload_base, 0x79726172);
        WriteAnywhere32(0x508 + payload_base, 0x656c462f);
        WriteAnywhere32(0x50c + payload_base, 0x5b003378);
        WriteAnywhere32(0x510 + payload_base, 0x3a5d7325);
        WriteAnywhere32(0x514 + payload_base, 0x0a732520);
        WriteAnywhere32(0x518 + payload_base, 0x61747300);
        WriteAnywhere32(0x51c + payload_base, 0x00000074);
        
        // Section __data
        // Range: [0x520; 0x608[ (232 bytes)
        WriteAnywhere64(0x520 + payload_base, 0x00000000000002d8 + payload_base);
        WriteAnywhere64(0x528 + payload_base, 0x00000000000002de + payload_base);
        WriteAnywhere64(0x530 + payload_base, 0x00000000000002e4 + payload_base);
        WriteAnywhere64(0x538 + payload_base, 0x00000000000002e9 + payload_base);
        WriteAnywhere64(0x540 + payload_base, 0x00000000000002ee + payload_base);
        WriteAnywhere64(0x548 + payload_base, 0x0000000000000306 + payload_base);
        WriteAnywhere64(0x550 + payload_base, 0x0000000000000317 + payload_base);
        WriteAnywhere64(0x558 + payload_base, 0x0000000000000320 + payload_base);
        WriteAnywhere64(0x560 + payload_base, 0x0000000000000354 + payload_base);
        WriteAnywhere64(0x568 + payload_base, 0x0000000000000380 + payload_base);
        WriteAnywhere64(0x570 + payload_base, 0x0000000000000391 + payload_base);
        WriteAnywhere64(0x578 + payload_base, 0x00000000000003aa + payload_base);
        WriteAnywhere64(0x580 + payload_base, 0x00000000000003d7 + payload_base);
        WriteAnywhere64(0x588 + payload_base, 0x00000000000003ed + payload_base);
        WriteAnywhere64(0x590 + payload_base, 0x00000000000003fb + payload_base);
        WriteAnywhere64(0x598 + payload_base, 0x000000000000040e + payload_base);
        WriteAnywhere64(0x5a0 + payload_base, 0x0000000000000419 + payload_base);
        WriteAnywhere64(0x5a8 + payload_base, 0x0000000000000435 + payload_base);
        WriteAnywhere64(0x5b0 + payload_base, 0x000000000000044b + payload_base);
        WriteAnywhere64(0x5b8 + payload_base, 0x0000000000000483 + payload_base);
        WriteAnywhere64(0x5c0 + payload_base, 0x000000000000049a + payload_base);
        WriteAnywhere64(0x5c8 + payload_base, 0x00000000000004d3 + payload_base);
        WriteAnywhere64(0x5d0 + payload_base, 0x00000000000004f5 + payload_base);
        WriteAnywhere64(0x5d8 + payload_base, 0x000000000000050f + payload_base);
        WriteAnywhere64(0x5e0 + payload_base, 0x0000000000000519 + payload_base);
        WriteAnywhere64(0x5e8 + payload_base, orig_stat);       // _orig_stat
        WriteAnywhere64(0x5f0 + payload_base, copyinstr_ptr);   // _copyinstr
        WriteAnywhere64(0x5f8 + payload_base, strcmp_ptr);      // _strcmp
        WriteAnywhere64(0x600 + payload_base, IOLog_ptr);       // _IOLog
        
        err = mach_vm_protect(tfp0, payload_base, isvad == 0 ? 0x4000 : 0x1000, 0, VM_PROT_READ|VM_PROT_EXECUTE);
        printf("vm_protect: 0x%d\n", err);
        sleep(1);
        
        RemapPage(sysent_stat_addr);
        printf("0x%016llx -> 0x%016llx\n", sysent_stat_addr, NewPointer(sysent_stat_addr));
        printf("patching kernel...\n");
        WriteAnywhere64(NewPointer(sysent_stat_addr), payload_base);
        
    }
    
}

int main(){
    
    uint64_t kbase;
    uint64_t kslide;
    
    tfp0 = get_kernel_task();
    kbase = get_kernel_base(tfp0);
    kslide = kbase - KERNEL_SEARCH_ADDRESS;
    printf("kernel base: 0x%016llx\n", kbase);
    printf("kslide: 0x%016llx\n", kslide);
    
    kpp(0, kbase, kslide);
    
    printf("well done??\n");
    
    return 0;
}
