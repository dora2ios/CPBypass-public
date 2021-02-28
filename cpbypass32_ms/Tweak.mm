/* Tweak.mm: Bypass file detection with MS hooking
 * 2020/12/12
 * made by dora2ios
 */

#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach/mach.h>

#import <CoreFoundation/CoreFoundation.h>
#import <utime.h>
#import <limits.h>
#import <stdlib.h>
#import <sys/types.h>
#import <sys/stat.h>
#include <sys/mount.h>
#include <sys/attr.h>
#import <fcntl.h>
#import <dirent.h>
#import <stdarg.h>
#include <dlfcn.h>
#include <string.h>
#include <errno.h>

int checkfiles(const char *path){
    
    /* **f**u****c--*k* v3.0.0 */
    
    if (strcasecmp(path, "/User") == 0 ||
        strcasecmp(path, "/boot") == 0 ||
        strcasecmp(path, "/lib") == 0 ||
        strcasecmp(path, "/mnt") == 0 ||
        strcasecmp(path, "/.cydia_no_stash") == 0 ||
        strcasecmp(path, "/bin/bash") == 0 ||
        strcasecmp(path, "/bin/sh") == 0 ||
        strcasecmp(path, "/Applications/Cydia.app") == 0 ||
        strcasecmp(path, "/Library/MobileSubstrate") == 0 ||
        strcasecmp(path, "/Library/MobileSubstrate/DynamicLibraries") == 0 ||
        strcasecmp(path, "/Library/MobileSubstrate/MobileSubstrate.dylib") == 0 ||
        strcasecmp(path, "/Library/Frameworks/CydiaSubstrate.framework") == 0 ||
        strcasecmp(path, "/Library/Frameworks/CydiaSubstrate.framework/Libraries") == 0 ||
        strcasecmp(path, "/Library/Frameworks/CydiaSubstrate.framework/Libraries/SubstrateLoader.dylib") == 0 ||
        strcasecmp(path, "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate") == 0 ||
        strcasecmp(path, "/private/var/lib") == 0 ||
        strcasecmp(path, "/var/lib") == 0 ||
        strcasecmp(path, "/private/var/lib/apt") == 0 ||
        strcasecmp(path, "/var/lib/apt") == 0 ||
        strcasecmp(path, "/private/var/db/stash") == 0 ||
        strcasecmp(path, "/var/db/stash") == 0 ||
        strcasecmp(path, "/private/var/stash") == 0 ||
        strcasecmp(path, "/var/stash") == 0 ||
        strcasecmp(path, "/private/var/mobile/Library/Cydia") == 0 ||
        strcasecmp(path, "/var/mobile/Library/Cydia") == 0 ||
        strcasecmp(path, "/private/var/mobile/Library/Caches/com.saurik.Cydia") == 0 ||
        strcasecmp(path, "/var/mobile/Library/Caches/com.saurik.Cydia") == 0 ||
        strcasecmp(path, "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist") == 0 ||
        strcasecmp(path, "/var/mobile/Library/Preferences/com.saurik.Cydia.plist") == 0 ||
        strcasecmp(path, "/private/etc/ssh") == 0 ||
        strcasecmp(path, "/etc/ssh") == 0 ||
        strcasecmp(path, "/private/etc/apt") == 0 ||
        strcasecmp(path, "/etc/apt") == 0 ||
        strcasecmp(path, "/usr/bin/ssh") == 0 ||
        strcasecmp(path, "/usr/sbin/sshd") == 0 ||
        strcasecmp(path, "/usr/libexec/cydia") == 0){
        return 0;
    }
    return -1;
}

%group hookf

/* ---- Bypass by akusio's cp-c https://github.com/akusio/cp-c/blob/master/Tweak.xm#L29 ---- */
struct dirent* readdir(DIR* dir);
%hookf(struct dirent*,readdir,DIR* dir)
{
    
    struct dirent* dire;
    
    while((dire = %orig(dir)) != NULL)
    {
        if (strcasecmp(dire->d_name,"User") == 0)
        {
            strcpy(dire->d_name,"System");
        }
        if (strcasecmp(dire->d_name,"boot") == 0)
        {
            strcpy(dire->d_name,"System");
        }
        if (strcasecmp(dire->d_name,"lib") == 0)
        {
            strcpy(dire->d_name,"System");
        }
        if (strcasecmp(dire->d_name,"mnt") == 0)
        {
            strcpy(dire->d_name,"System");
        }
        
        return dire;
    }
    return %orig;
    
}
/* ---- end ---- */

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (checkfiles(path) == 0){
        errno = ENOENT;
        return NULL;
    }
    
    return %orig;
}

%hookf(int, stat, const char *path, struct stat *buf) {
    if (checkfiles(path) == 0){
        errno = ENOENT;
        return -1;
    }
    
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (checkfiles(path) == 0){
        errno = ENOENT;
        return -1;
    }
    
    return %orig;
}

%hookf(int, getattrlist, const char* path, struct attrlist * attrList, void * attrBuf, size_t attrBufSize, unsigned long options){
    if (checkfiles(path) == 0){
        errno = ENOENT;
        return -1;
    }
    
    return %orig;
}

%hookf(DIR *,__opendir2,const char *path, int buf){
    if (checkfiles(path) == 0){
        errno = ENOENT;
        return NULL;
    }
    
    return %orig;
}
%end

static int (*orig_open)(const char *path, int oflag, ...);
static int hook_open(const char *path, int oflag, ...) { // not need ?
    va_list args;
    int fd = 0;
    
    if (checkfiles(path) == 0){
        errno = ENOENT;
        return -1;
    }
    
    if ((oflag & O_CREAT) == O_CREAT){
        mode_t mode;
        
        va_start(args, oflag);
        mode = (mode_t) va_arg(args, int);
        va_end(args);
        
        fd = orig_open(path, oflag, mode);
    } else {
        fd = orig_open(path, oflag);
    }
    return fd;
}

%ctor{
    %init(hookf);
    MSHookFunction((void *) open, (void *) hook_open, (void **) &orig_open);
}
