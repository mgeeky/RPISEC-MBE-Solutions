#!/bin/bash

echo "This is only a preparation script intended to enable us of locally debugging target binary"

echo "Step 1: Preparing LD_PRELOAD library to fake fopen('/home/lab6A/.pass') return value"
pushd /tmp
mkdir lab6b
cat<<EOF>myfopen.c
#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>

typedef FILE* (*orig_fopen_type)(const char *path, const char *mode);

FILE *fopen(const char *path, const char *mode) {
    orig_fopen_type orig_fopen;
    orig_fopen = (orig_fopen_type)dlsym(RTLD_NEXT, "fopen");
    return orig_fopen("/tmp/lab6b/test.txt", "r");
}
EOF

gcc -Wall -shared -fPIC myfopen.c -o myfopen.so -ldl

echo "Step 2: Creating a decoy file named 'test.txt'"
python -c 'import sys; sys.stdout.write("this_is_a_test_file")' > /tmp/lab6b/test.txt

echo "Step 3: Setting LD_PRELOAD"
export LD_PRELOAD=/tmp/lab6b/myfopen.so

echo "Step 4: Now you can launch target binary locally:"
/levels/lab06/lab6B
