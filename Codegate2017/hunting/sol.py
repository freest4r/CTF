#!/usr/bin/python
from pwn import *
import time
from ctypes import *

def get_rand():
    rand_value = libc.rand() & 3;
    return str(rand_value)

def change_skill(skill):
    p.sendline('3')
    print p.recv()
    p.sendline(skill)
    return

libc=cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")

p1 = ssh(host="110.10.212.133", user="hunting", port=5555, password="hunting")
p = p1.run("/home/hunting/hunting")
#p = process("./hunting")
libc.srand(libc.time(0))

print p.recv()
change_skill('2')
for i in range(0,300):
    data=p.recv()
    print data
    p.sendline("2")
    rand_value = get_rand()
    time.sleep(0.3)
    data = p.recv()
    print data

    rand_value = get_rand()
    if rand_value == '1':
        shield = '3' 
    elif rand_value == '2':
        shield = '2' 
    else:
        shield = '1' 

    p.sendline(shield)

    if 'game over' in data:
        break
    elif 'level:4' in data:
        change_skill('7')

p.close()
