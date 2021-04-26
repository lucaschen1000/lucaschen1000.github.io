---
layout: post
title:  "DownUnderCTF 2020"
---

Here are writeups for the crypto challenges I solved during the CTF.

## Table of Contents
1. [Baby RSA](#baby-rsa)
2. [Extra Cool Block Chaining](#ecbc)

## Baby RSA <a name="baby-rsa"></a>

{::options parse_block_html="true" /}

<details>
  <summary markdown="span">**`babyrsa.py`**</summary>

  ```python
from Crypto.Util.number import bytes_to_long, getPrime

flag = open('flag.txt', 'rb').read().strip()

p, q = getPrime(1024), getPrime(1024)
n = p*q
e = 0x10001

s = pow(557*p - 127*q, n - p - q, n)

c = pow(bytes_to_long(flag), e, n)

print(f'n = {n}')
print(f's = {s}')
print(f'c = {c}')
  ```

</details>

<details>
  <summary markdown="span">**`output.txt`**</summary>

  ```python
n = 19574201286059123715221634877085223155972629451020572575626246458715199192950082143183900970133840359007922584516900405154928253156404028820410452946729670930374022025730036806358075325420793866358986719444785030579682635785758091517397518826225327945861556948820837789390500920096562699893770094581497500786817915616026940285194220703907757879335069896978124429681515117633335502362832425521219599726902327020044791308869970455616185847823063474157292399830070541968662959133724209945293515201291844650765335146840662879479678554559446535460674863857818111377905454946004143554616401168150446865964806314366426743287
s = 3737620488571314497417090205346622993399153545806108327860889306394326129600175543006901543011761797780057015381834670602598536525041405700999041351402341132165944655025231947620944792759658373970849932332556577226700342906965939940429619291540238435218958655907376220308160747457826709661045146370045811481759205791264522144828795638865497066922857401596416747229446467493237762035398880278951440472613839314827303657990772981353235597563642315346949041540358444800649606802434227470946957679458305736479634459353072326033223392515898946323827442647800803732869832414039987483103532294736136051838693397106408367097
c = 7000985606009752754441861235720582603834733127613290649448336518379922443691108836896703766316713029530466877153379023499681743990770084864966350162010821232666205770785101148479008355351759336287346355856788865821108805833681682634789677829987433936120195058542722765744907964994170091794684838166789470509159170062184723590372521926736663314174035152108646055156814533872908850156061945944033275433799625360972646646526892622394837096683592886825828549172814967424419459087181683325453243145295797505798955661717556202215878246001989162198550055315405304235478244266317677075034414773911739900576226293775140327580
  ```

</details>

{::options parse_block_html="false" /}

I was given `babyrsa.py` and `output.txt`, where `output.txt` was the result of running `babyrsa.py`.

This looked to me like [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Example){:target="_blank" rel="noopener"} except that I was given an extra variable $$s \equiv (557p - 127q)^{n - p - q} \pmod {n}$$.
I simplified the exponent of $$s$$ to $$n - p - q = pq - p - q = (p - 1)(q - 1) - 1 = \phi(n) - 1$$.

After this, I went down a rabbit hole trying to extract \\( \phi(n) \\) from \\( s \\).
I simplified \\( s \\) to $$s \equiv (557p)^{\phi(n) - 1} - (127q)^{\phi(n) - 1} \pmod{n}$$
since when expanding \\( (557p - 127q)^{\phi(n) - 1} \\) using the binomial theorem, every term except for the first and last will have \\( pq \\) as a factor. But, I couldn't extract \\( \phi(n) \\) any further.

Then, I realized that I could solve for \\( 557p - 127q \\), drawing inspiration from RSA decryption. I'm given the integer \\( n \\), so I would have two equations: \\( 557p - 127q \\) equal to an integer and \\( n = pq \\). I realized that using Euler's Theorem, I could simplify \\( s \\) into
$$s \equiv (557p - 127q)^{-1} \pmod{n}$$
since \\( (557p - 127q)^{\phi(n)} \equiv 1 \pmod{n} \\).

Finally, I used Sage's equation solver to solve for \\( p \\) and \\( q \\), which will net the flag.

**`solution.sage`**

```python    
from Crypto.Util.number import long2str

exec(open("output.txt").read())
var("p q")
for soln in solve([557*p - 127*q == inverse_mod(s, n), p*q == n], p, q, solution_dict=True):
    if soln[p] <= 1 or soln[q] <= 1:
        continue
    d = inverse_mod(0x10001, (soln[p]-1) * (soln[q]-1))
    print(f"m = {long2str(pow(c, d, n))}")
```

Flag: `DUCTF{e4sy_RSA_ch4ll_t0_g3t_st4rt3d}`

## Extra Cool Block Chaining <a name="ecbc"></a>

{::options parse_block_html="true" /}

<details>
  <summary markdown="span">**`server.py`**</summary>

  ```python
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor
from os import urandom

flag = open('./flag.txt', 'rb').read().strip()
KEY = urandom(16)
IV = urandom(16)

def encrypt(msg, key, iv):
    msg = pad(msg, 16)
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    out = b''
    for i, block in enumerate(blocks):
        cipher = AES.new(key, AES.MODE_ECB)
        enc = cipher.encrypt(block)
        if i > 0:
            enc = strxor(enc, out[-16:])
        out += enc
    return strxor(out, iv*(i+1))

def decrypt(ct, key, iv):
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    out = b''
    for i, block in enumerate(blocks):
        dec = strxor(block, iv)
        if i > 0:
            dec = strxor(dec, ct[(i-1)*16:i*16])
        cipher = AES.new(key, AES.MODE_ECB)
        dec = cipher.decrypt(dec)
        out += dec
    return out

flag_enc = encrypt(flag, KEY, IV).hex()

print('Welcome! You get 1 block of encryption and 1 block of decryption.')
print('Here is the ciphertext for some message you might like to read:', flag_enc)

try:
    pt = bytes.fromhex(input('Enter plaintext to encrypt (hex): '))
    pt = pt[:16] # only allow one block of encryption
    enc = encrypt(pt, KEY, IV)
    print(enc.hex())
except:
    print('Invalid plaintext! :(')
    exit()

try:
    ct = bytes.fromhex(input('Enter ciphertext to decrypt (hex): '))
    ct = ct[:16] # only allow one block of decryption
    dec = decrypt(ct, KEY, IV)
    print(dec.hex())
except:
    print('Invalid ciphertext! :(')
    exit()

print('Goodbye! :)')
  ```
</details>

{::options parse_block_html="false" /}

I was given `server.py` and the connection details to a live server running `server.py`.

I translated the cryptosystem into equations to understand its vulnerability.

Let \\( P_k \\) be the \\(k^{th} \\) 16 byte block of the plaintext.
Let the same logic apply to the ciphertext block \\( C_k \\).
Let \\( E \\) be the AES ECB encryption function, \\( D \\) be the AES ECB decryption function, and \\( \mathrm{iv} \\) be the initialiation vector.
Then,
\\[ E(P_0) \oplus \mathrm{iv} = C_0 \tag{1} \\]
\\[ E(P_k) \oplus E(P_{k-1}) \oplus \mathrm{iv} = C_k \tag{2} \\]
\\[ D(C_0 \oplus \mathrm{iv}) = P_0 \tag{3} \\]
\\[ D(C_k \oplus \mathrm{iv} \oplus E(P_{k-1})) = P_k \tag{4} \\]

The server would output the result of an encrypted flag ($$C$$) with that cryptosystem. Then, the client would input any 16 byte block and have the server display its decryption using the same cryptosystem as the first output.

Because the server allowed me to decrypt any 16 byte block, I could decrypt $$C_0$$, but in order to decrypt non-primary blocks, I needed $$E(P_{k-1})$$ from equation $$4$$, which is $$C_{k-1} \oplus \mathrm{iv} $$. I had $$C_{k-1}$$ but retrieving iv was not so simple. From equation $$2$$, I saw that if $$E(P_k) = E(P_{k-1})$$, then I could recover iv from $$C_k$$. However, that requires two 16 byte blocks.

After playing around with the server code, I noticed that if I fed the encryption oracle a null string, I would still get a $$16$$ byte response. Thus, in order to bypass the one block restriction, I chose `'\x10' * 16` as a plaintext, which gets padded to `'\x10' * 32`, and then I retrieved the iv from the second block of the response.

#### **`solution.py`**
```python
from pwn import *
from Crypto.Util.strxor import strxor

context.log_level = "debug"
flag = b""

for i in range(6):
    r = remote("chal.duc.tf", "30201")

    r.recvuntil(": ")
    ciphertext = bytes.fromhex(r.recvline().strip().decode())
    c = [ciphertext[i*16: (i+1)*16] for i in range(len(ciphertext) // 16)]

    r.recvuntil(": ")
    r.sendline((b"\x10" * 16).hex())
    iv = bytes.fromhex(r.recvline().strip().decode())[16:32]

    r.recvuntil(": ")
    if i == 0:
        block = c[0]
    else:
        block = strxor(c[i], c[i - 1])
        block = strxor(block, iv)
    r.sendline(block.hex())
    plain = bytes.fromhex(r.recvline().strip().decode())
    flag += plain

print(flag)
```

Flag: `DUCTF{4dD1nG_r4nd0M_4rR0ws_4ND_x0RS_h3r3_4nD_th3R3_U5u4Lly_H3lps_Bu7_n0T_7H1s_t1m3_i7_s33ms!!}`