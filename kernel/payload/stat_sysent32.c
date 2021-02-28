/* stat_sysent.c: Bypassing file detection with kernel hooking
 * 2020/12/12
 * made by dora2ios
 */

#include <stdint.h>

typedef uint32_t user_addr_t;
typedef uint32_t size_t;
typedef struct vfs_context *vfs_context_t;
typedef uintptr_t vm_size_t;
typedef struct vm_allocation_site vm_allocation_site_t;

int
strcmp(const char *s1, const char *s2);

__attribute__((noinline)) int _pre_strcmp(const char *a, const char *b){
    return strcmp(a, b);
}

void IOLog(const char *format, ...)
__attribute__((format(printf, 1, 2)));

#define MAXPATHLEN 0x400

#if 0
/* 64-bit */
/* rootlessjb */
const char *STR_JB = "/jb"; // not need
const char *STR_VAR_CONT_BUNDLES_BINPACK64 = "/var/containers/Bundle/iosbinpack64"; // not need
const char *STR_PRV_VAR_CONT_BUNDLES_BINPACK64 = "/private/var/containers/Bundle/iosbinpack64"; // not need
const char *STR_VAR_LIBEXEC = "/var/libexec"; // not need
const char *STR_PRV_VAR_LIBEXEC = "/private/var/libexec"; // not need
/* sileo */
const char *STR_APP_SILEO = "/Applications/Sileo.app"; // not need
const char *STR_PRV_VAR_MOBILE_LIBRARY_CACHES_SNAPSHOTS_SILEO = "/private/var/mobile/Library/Caches/Snapshots/org.coolstar.SileoStore"; // not need
const char *STR_PRV_VAR_MOBILE_LIBRARY_PREF_SILEO = "/private/var/mobile/Library/Preferences/org.coolstar.SileoStore.plist"; // not need
/* zebra */
const char *STR_APP_ZEBRA = "/Applications/Zebra.app"; // not need
const char *STR_LIBRARY_DPKG_INFO_ZEBRA = "/Library/dpkg/info/xyz.willy.zebra.list"; // not need
const char *STR_PRV_VAR_MOBILE_LIBRARY_PREF_ZEBRA = "/private/var/mobile/Library/Preferences/xyz.willy.Zebra.plist"; // not need
#endif

/* Universal */
const char *STR_USER = "/User";
const char *STR_BOOT = "/boot";
const char *STR_LIB = "/lib";
const char *STR_MNT = "/mnt";
const char *STR_APP_CYDIA = "/Applications/Cydia.app";
const char *STR_PRV_VAR_LIB = "/private/var/lib";
const char *STR_VAR_LIB = "/var/lib"; // not need?
const char *STR_PRV_VAR_MOBILE_LIBRARY_CACHES_CYDIA = "/private/var/mobile/Library/Caches/com.saurik.Cydia";
const char *STR_VAR_MOBILE_LIBRARY_CACHES_CYDIA = "/var/mobile/Library/Caches/com.saurik.Cydia";
const char *STR_PRV_ETC_SSH = "/private/etc/ssh";
const char *STR_LIBRARY_MS = "/Library/MobileSubstrate";
const char *STR_LIBRARY_FRAMEWORKS_MS = "/Library/Frameworks/CydiaSubstrate.framework";
const char *STR_PRIV_VAR_DB_STASH = "/private/var/db/stash";
const char *STR_VAR_DB_STASH = "/var/db/stash";
const char *STR_PRIV_VAR_STASH = "/private/var/stash";
const char *STR_VAR_STASH = "/var/stash";
const char *STR_USR_LIB_SUBSTRATE = "/usr/lib/libsubstrate.dylib";

/* anti-anti jb detection */
const char *STR_LIBRARY_BT = "/Library/BreakThrough";
const char *STR_LIBRARY_PREFLOADER_PREF_LIBERTY = "/Library/PreferenceLoader/Preferences/LibertyPref.plist";
const char *STR_APP_FLEX = "/Applications/Flex.app";
const char *STR_LIBRARY_PREFLOADER_PREF_NOMS = "/Library/PreferenceLoader/Preferences/NoSubstitute.plist";
const char *STR_PRIV_VAR_MOBILE_LIBRARY_FLEX3 = "/private/var/mobile/Library/Flex3";
const char *STR_VAR_MOBILE_LIBRARY_FLEX3 = "/var/mobile/Library/Flex3";

/* IOLog */
const char *LOGDUMP = "a";
const char *BLOCKDUMP = "b";

/* hook */
struct proc;
typedef uint32_t sy_call_t(struct proc *arg1, void *arg2, int *arg3);
uint32_t orig_stat(struct proc *p, struct stat_args *uap, /* __unused */ uint32_t *retval);

struct stat_args {
    uint32_t path;
    uint32_t ub;
};

uint32_t main(struct proc *p, struct stat_args *uap, /* __unused */ uint32_t *retval){
    
    char pathname[MAXPATHLEN];
    size_t dummy=0;
    int error;
    
    error = copyinstr(uap->path, pathname, MAXPATHLEN, &dummy);
    if(error) return 2;
    
    // iPhone5,2 11D27 kern_offsets
    // 803aab6f         db         "%s: %s\n"
    // 803b3a2d         db         "path"
    //
    // LOGDUMP -> "%s: %s\n"
    // BLOCKDUMP -> "path"
    
    IOLog(LOGDUMP, BLOCKDUMP, pathname);
    //_IOLog("%s: %s\n", "path", pathname);
    
    if(_pre_strcmp(pathname, STR_USER) == 0 ||
       _pre_strcmp(pathname, STR_BOOT) == 0 ||
       _pre_strcmp(pathname, STR_LIB) == 0 ||
       _pre_strcmp(pathname, STR_MNT) == 0 ||
       _pre_strcmp(pathname, STR_APP_CYDIA) == 0 ||
       _pre_strcmp(pathname, STR_PRV_VAR_LIB) == 0 ||
       _pre_strcmp(pathname, STR_VAR_LIB) == 0 ||
       _pre_strcmp(pathname, STR_PRV_VAR_MOBILE_LIBRARY_CACHES_CYDIA) == 0 ||
       _pre_strcmp(pathname, STR_VAR_MOBILE_LIBRARY_CACHES_CYDIA) == 0 ||
       _pre_strcmp(pathname, STR_PRV_ETC_SSH) == 0 ||
       _pre_strcmp(pathname, STR_LIBRARY_MS) == 0 ||
       
       _pre_strcmp(pathname, STR_LIBRARY_FRAMEWORKS_MS) == 0 ||
       _pre_strcmp(pathname, STR_PRIV_VAR_DB_STASH) == 0 ||
       _pre_strcmp(pathname, STR_VAR_DB_STASH) == 0 ||
       _pre_strcmp(pathname, STR_PRIV_VAR_STASH) == 0 ||
       _pre_strcmp(pathname, STR_VAR_STASH) == 0 ||
       _pre_strcmp(pathname, STR_USR_LIB_SUBSTRATE) == 0 ||
       
       _pre_strcmp(pathname, STR_LIBRARY_BT) == 0 ||
       _pre_strcmp(pathname, STR_LIBRARY_PREFLOADER_PREF_LIBERTY) == 0 ||
       _pre_strcmp(pathname, STR_APP_FLEX) == 0 ||
       _pre_strcmp(pathname, STR_LIBRARY_PREFLOADER_PREF_NOMS) == 0 ||
       _pre_strcmp(pathname, STR_PRIV_VAR_MOBILE_LIBRARY_FLEX3) == 0 ||
       _pre_strcmp(pathname, STR_VAR_MOBILE_LIBRARY_FLEX3) == 0){
        // return ENOENT;
        return 2;
    }
    
    return orig_stat(p, uap, retval);
}
