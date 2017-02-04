#!/bin/bash

while true; do
	gdb -q -x gdb.txt socat
	sleep 1
done
