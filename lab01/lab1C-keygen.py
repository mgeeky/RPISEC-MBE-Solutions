#!/usr/bin/python

import ctypes

def uint32(x):
    return ctypes.c_uint32(x).value

def uint64(x):
    return ctypes.c_uint64(x).value

def mul64(a, b):
    res = uint64(uint32(a) * uint32(b))
    return (uint32(res & 0xFFFFFFFF), uint32((res & (0xFFFFFFFF << 32)) >> 32))

def compute():
    login = 'mariusz'
    serial = (ord(login[3]) ^ 0x1337) + 0x5eeded

    for i in range(len(login)):
        a = uint32(ord(login[i]) ^ serial)
        blower, bupper = mul64(a, 0x88233b2b)
        d = uint32(((uint32(a - bupper) / 2 + bupper) / 1024) * 1337)
        serial += uint32(uint32(a) - uint32(d))
        print "%u (%x)" % (serial, serial)

    print 'Serial: %u (%x)' % (serial, serial)

compute()
