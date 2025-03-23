---
author: Chinmay Govind
pubDatetime: 2025-03-23T17:22:00Z
modDatetime: 2025-03-23T17:22:00Z
title: picoCTF 2025 - Cha Cha Slide
featured: true
draft: false
tags:
  - Cryptography
  - Encryption
  - picoCTF 2025
  - picoCTF
description:
  A writeup for the PicoCTF 2025 cryptography challenge, Cha Cha Slide.
---

## Table of contents

## Challenge-Information 

400 Points

Tags: picoCTF 2025, Cryptography, browser_webshell_solvable

Author: ASINGHANI

Description:

Modern authenticated-encryption ciphers like ChaCha20-Poly1305 are great, but they can quickly fall apart if their limits aren't respected. Can you violate the integrity of a message encrypted by this program? 

Connect to the program with netcat:

`$ nc activist-birds.picoctf.net 60842`

The program's source code can be downloaded [here](https://challenge-files.picoctf.net/c_activist_birds/0b248cc311615f0d67effe119d44e1700493cb1914c10dbc1b5deecd941f3186/challenge.py).

Challenge Link: [https://play.picoctf.org/practice/challenge/493](https://play.picoctf.org/practice/challenge/493)

## Explanation

### The Problem

The challenge generates a random 32-byte key and 12-byte nonce, and encrypts 2 messages with ChaCha20Poly1305 reusing the same key and nonce pair, printing out the ciphertext, Poly1305 tag, and nonce. To get the flag, we need to forge a target message ("But it's only secure if used correctly!") and give the correct ciphertext, tag and nonce without knowing the secret key. We are already given the nonce, so it remains to forge the ciphertext and the tag.

### Forging the ChaCha20 Ciphertext

Reading up on the [design of ChaCha20](https://loup-vaillant.fr/tutorials/chacha20-design), we see that the cipher works by XORing the plaintext with a ChaCha keystream, generated from the key and nonce. Since we know the key and nonce are constant, the ChaCha keystream will always be constant. So, we can XOR the known plaintext with the given ciphertext to recover the ChaCha keystream. Then, we can XOR the keystream with the target message to get the correct ChaCha20 ciphertext. 

```python
from pwn import *

# Connect to the target process
p = process(["python", "challenge.py"]) 
#p = remote('activist-birds.picoctf.net',63900)
def extract_hex(line):
    return re.search(r'([0-9a-fA-F]+)', line).group(1)

# Read output and extract values
p.recvuntil(b"Plaintext: ")
plaintext1 = p.recvline().strip().decode()
p.recvuntil(b"Plaintext (hex): ")
plaintext1_hex = extract_hex(p.recvline().strip().decode())
print(p.recvuntil(b"Ciphertext (hex): "))
ciphertext1 = extract_hex(p.recvline().strip().decode())

p.recvuntil(b"Plaintext: ")
plaintext2 = p.recvline().strip().decode()
p.recvuntil(b"Plaintext (hex): ")
plaintext2_hex = extract_hex(p.recvline().strip().decode())
p.recvuntil(b"Ciphertext (hex): ")
ciphertext2 = extract_hex(p.recvline().strip().decode())

# Extract nonce and tag
nonce1, tag1 = ciphertext1[-24:], ciphertext1[-56:-24]
nonce2, tag2 = ciphertext2[-24:], ciphertext2[-56:-24]
ciphertext1 = ciphertext1[:-56]
ciphertext2 = ciphertext2[:-56]

print(f"Nonce reused? {nonce1 == nonce2}")

pt1 = binascii.unhexlify(plaintext1_hex)
pt2 = binascii.unhexlify(plaintext2_hex)
ct1 = binascii.unhexlify(ciphertext1)
ct2 = binascii.unhexlify(ciphertext2)

# extract ChaCha keystream by XORing plaintext and ciphertext
ks = bytes(x ^ y for x, y in zip(pt1, ct1))
ks2 = bytes(x ^ y for x, y in zip(pt2, ct2))
ks_shared = ks[:len(ks2)]

# verify that same keystream is reused
print(f"Keystream shared? {ks2 == ks_shared}")

# Generate the goal ciphertext by XORing the keystream with the goal plaintext
goal = "But it's only secure if used correctly!"
goal_hex = goal.encode().hex()
raw_goal_hex = binascii.unhexlify(goal_hex)
goal_ct = bytes(x ^ y for x, y in zip(raw_goal_hex, ks[:len(raw_goal_hex)]))

```

### Forging the Poly1305 Tag
Forging the Poly1305 tag is much tricker. ChaCha20Poly1305 is an authenticated-encryption cipher, which means that even if we have forged some ciphertext, we also need to generate the Poly1305 authentication tag to prove that a message hasn't been tampered with.

Reading up on [Poly1305's design](https://loup-vaillant.fr/tutorials/poly1305-design), we see the basic operation involves using a polynomial, whose coefficients are determined by the ChaCha20 ciphertext. The basic formula is as follows:

```
tag = m_1 * r^q + m_2 * r^(q - 1) + m_3 * r^(q - 2) + ... + m_(N - 1) * r^2 + m_N * r + s (mod 2^130 - 5)
```

where each m_i is one 16-byte chunk of the ciphertext as a little-endian integer, q is the number of 16-byte chunks, and r and s are secret 16-byte integers derived from the key and nonce. The tag is reduced modulo 2^128 and returned as a 16-byte hash.

Note: each m_i isn't actually one 16-byte chunk- we take the chunk and add a \0x01 byte in front of it (a one byte). This means that trailing zero bytes on a message won't be ignored. Also, the ciphertext is padded with a 16-byte chunk of null bytes and then another 16-byte little endian integer chunk that is the length of the ciphertext (see the code implementation).

We know m_i (the ciphertext we calculated earlier) and we know q (derived from the length of the ciphertext), but without knowing r and s it is impossible to calculate the tag. So, we need to figure out r and s. 

### Solving for R and S
Note that in all of the documentation for Poly1305, it clearly says you should not reuse the same key and nonce. Why is this?

Notice what happens if we reuse the same key and nonce (meaning same r and s values) on 2 different messages, m and n:

```
tag1 = m_1 * r^q + m_2 * r^(q - 1) + m_3 * r^(q - 2) + ... + m_(N - 1) * r^2 + m_N * r + s
tag2 = n_1 * r^q + n_2 * r^(q - 1) + n_3 * r^(q - 2) + ... + n_(N - 1) * r^2 + n_N * r + s
```
Subtracting the two equations, we get:

```
tag1 - tag2 = (m_1 - n_1) * r^q + (m_2 - n_2) * r^(q - 1) + ... + (m_(N - 1) - n_(N - 1)) * r^2 + (m_N - n_N) * r (mod 2^128)
```

Notice that the s term vanishes. Since we know tag1, tag2, m, and n, we can backsolve this polynomial for r! Then we can substitute r into one of the original equations to find s. (Note that messages m and n aren't the same length here, so the polynomial coefficients are slightly different but the same logic holds).

So, the workflow is as follows: First, generate the coefficients of tag1 and tag2's polynomial equations, and then find the coefficient differences for the "tag1 - tag2" equation.

```python
tag1num = int.from_bytes(binascii.unhexlify(tag1), byteorder='little', signed=False)
tag2num = int.from_bytes(binascii.unhexlify(tag2), byteorder='little', signed=False)
tagdiff = (tag1num - tag2num) % (2**130 - 5)
print(f"Tag 1 num: {tag1num}")
print(f"Tag 2 num: {tag2num}")
print(f"Tags Diff: {tagdiff}")

def poly1305_coefficients(data: bytes) -> list[int]:
    # Prime modulus used in Poly1305
    coefficients = []
    chunks = [data[i:i+16] for i in range(0, len(data), 16)]
    print([chunk.hex() for chunk in chunks])
    for chunk in chunks:
        # Convert chunk to little-endian integer
        chunk_int = int.from_bytes(chunk + b'\x01', byteorder='little')
        coefficients.append(chunk_int)
    
    return coefficients

coeffs1 = poly1305_coefficients(ct1 + bytes.fromhex("00000000000000000000004d00000000000000"))
coeffs2 = poly1305_coefficients(ct2 + bytes.fromhex("0000000000000000000000000000000000004600000000000000"))
while len(coeffs1) < len(coeffs2):
    coeffs1 = [0] + coeffs1
coeffDiffs = [coeffs1[i] - coeffs2[i] for i in range(len(coeffs1))]

print(f"coeffs1 = {coeffs1}")
print(f"coeffs2 = {coeffs2}")
print(f"diff_coeffs = {coeffDiffs}")
print(f"tag1 = {tag1num}")
print(f"tag2 = {tag2num}")
print(f"tagdiff = {tagdiff}")

```

Then, using these coefficients, we solve the tag1 - tag2 polynomial to recover r and use the original coefficients to recover s. Note that in the Poly1305 implementation, certain bits of r are cleared (set to zero) for performance reasons, so we can use these to narrow down our candidates for r.

```python
def byte(number, i):
    return (number & (0xff << (i * 8))) >> (i * 8)

def find_valid_r(coeffs, tagdiff):
    p = (1 << 130) - 5  # Prime modulus
    R = PolynomialRing(Integers(p), 'v')  # Define polynomial ring modulo 2^130 - 5
    v = R.gen()
    possible_rs = []

    # Define the polynomial variable

    # Iterate over possible k values: -4, -3, ..., 4
    for k in range(-5, 5):
        # print(f"Trying k = {k}")
        new_coeffs = []
        new_coeffs.extend(coeffs)
        rhs = (tagdiff + k * (1 <<128)) % p
        new_coeffs.append(-rhs)
        new_coeffs.reverse()
        
        # Polynomial coefficients: c1 r^5 + c2 r^4 + c3 r^3 + c2 r^2 + c1 r - rhs
        poly = sum(c * v**i for i, c in enumerate(new_coeffs))
        #print(f"Poly: {poly.polynomial(v)}")
        roots = poly.roots(multiplicities=False)
        # print(roots)
        possible_rs.extend(roots)
    possible_rs = [x.lift() for x in possible_rs]
    for r in possible_rs:
        hex_str = hex(r)[2:].zfill(32)  # Convert to hex, remove '0x', and pad to 32 chars
        formatted_hex = ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
        print(f"{str(r)}\t: {formatted_hex}")

    possible_rs = [
        r for r in possible_rs 
        if  (byte(r, 3)  & 0xF0 == 0) 
        and  (byte(r, 7)  & 0xF0 == 0)  
        and  (byte(r, 11)  & 0xF0 == 0)  
        and  (byte(r, 15)  & 0xF0 == 0)  
        and  (byte(r, 4)  & 0x03 == 0)  
        and  (byte(r, 8)  & 0x03 == 0)  
        and  (byte(r, 12)  & 0x03 == 0)  
    ]
    return possible_rs

def find_valid_s(r_candidates, coeffs1, coeffs2, tag1, tag2):
    p = (1 << 130) - 5  # Prime modulus
    rs_candidates = []
    print(r_candidates)
    for r in r_candidates:
        acc1 = 0
        acc2 = 0
        for i in range(len(coeffs1)):
            acc1 += coeffs1[i] % p
            acc1 = (acc1 * r) % p
            acc2 += coeffs2[i] % p
            acc2 = (acc2 * r) % p
        #print(acc1, acc2)
        s1 = (tag1 - acc1) % (1 << 128)
        s2 = (tag2 - acc2) % (1 << 128)
        if s1 == s2:
            rs_candidates.append([r, s1])
    return rs_candidates
```

To solve for R and S:

```python
coeffs1 = [538640274081240381019147370272758415192, 462029317561921617150287947377116959195, 514826131592740245787887153031584711298, 535550505289509202810815754775617154302, 340282369155093552765040269583743790077, 340282366920938464883773901107403685888]
coeffs2 = [518575531808390145367352643422387617352, 439370050837056053909361816896710739392, 613210017993548771521380264009051921874, 550280077919642477568980272650752502763, 340282366920938463463374621277054575026, 340282366920938464754646692591436824576]
diff_coeffs = [20064742272850235651794726850370797840, 22659266724865563240926130480406219803, -98383886400808525733493110977467210576, -14729572630133274758164517875135348461, 2234155089301665648306689215051, 129127208515966861312]
tag1 = 214997742450230526426862784708746195147
tag2 = 11700909561346116411883985678737627548
tagdiff = 203296832888884410014978799030008567599

find_valid_s(find_valid_r(diff_coeffs, tagdiff), coeffs1, coeffs2, tag1, tag2)
```

## Using R and S to forge a tag
Once we have R and S, the hardest part is done. We can just follow the algorithm for Poly1305 to forge the tag.

```python
def forge_tag(message, r, s):
    r = r & 0x0ffffffc0ffffffc0ffffffc0fffffff
    coeffs = poly1305_coefficients(message)
    acc = 0
    p = (1 << 130) - 5
    for i in range(len(coeffs)):
        acc += coeffs[i] % p
        acc = (acc * r) % p
    acc = (acc + s) % (1 << 128)
    return acc.to_bytes(16, 'little')

goal = "But it's only secure if used correctly!"
goal_hex = goal.encode().hex()
raw_goal_hex = binascii.unhexlify(goal_hex)
goal_ct = bytes(x ^ y for x, y in zip(raw_goal_hex, ks[:len(raw_goal_hex)]))
padded_goal_ct = goal_ct + bytes.fromhex("00000000000000000000000000000000002700000000000000") # pad the goal ct with null chunk and ciphertext length chunk

tag = forge_tag(padded_goal_ct, r, s).hex()
```

Putting everything together, we can print out our final forged ciphertext-nonce-tag string:

```python
print(f"PT1: {plaintext1_hex}\nCT1: {ciphertext1}\nKS1: {ks.hex()} \nTag 1: {tag1}\nNonce 1: {nonce1}\n")
print(f"PT2: {plaintext2_hex}\nCT2: {ciphertext2}\nKS2: {ks2.hex()} \nTag 2: {tag2}\nNonce 2: {nonce2}\n")
print(f"PTG: {goal_hex}")
print()
print(f"Ciphertext: {goal_ct.hex()}")
print('\033[1m' + f"Tag       : {tag}" + '\033[0m')
print(f"Nonce     : {nonce}")
flag = goal_ct.hex() + str(tag) + str(nonce)
print(f"My Flag   : {flag}")
```

## Summary
Because the given script reuses the same key and nonce, we can exploit our knowledge of the plaintext to extract the ChaCha20 keystream and exploit the key reuse to solve for R and S and forge the Poly1305 tag. This challenge took a lot of research, trial and error, but it was a lot of fun and we learned a lot!