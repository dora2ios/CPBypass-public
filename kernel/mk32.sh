#!/bin/sh
xcrun -sdk iphoneos clang -arch armv7 sysent_patch32.c patchfinder32/patchfinder32.c -o sysent_patch32; ldid -Stfp0.xml sysent_patch32; mv -v sysent_patch32 sysent_patch
