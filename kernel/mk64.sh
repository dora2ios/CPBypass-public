#!/bin/sh
xcrun -sdk iphoneos clang -arch arm64 -o sysent_patch64 sysent_patch64.c patchfinder64/patchfinder64.c; ldid -Stfp0.xml sysent_patch64
