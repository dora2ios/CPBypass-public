
uint32_t get_kernel_pmap(vm_address_t kernel_base, uint8_t *kernel_dump, size_t ksize);
uint32_t find_copyinstr(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_IOLog(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_syscall188_post_iOSX(uint32_t region, uint8_t* kdata, size_t ksize, int sysent);
uint32_t find_syscall188(uint32_t region, uint8_t* kdata, size_t ksize, int sysent);
uint32_t find_strcmp(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t get_kernel_str(uint32_t region, uint8_t* kdata, size_t ksize, char* str);
uint32_t find_IOLog_post_iOSX(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t make_bl(int blx, int pos, int tgt);
unsigned int make_b_w(int pos, int tgt);
