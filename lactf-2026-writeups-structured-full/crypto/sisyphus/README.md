# sisyphus

**Category:** crypto

---

#### Description

A garbled circuit challenge implementing Yao's garbled circuits with the free XOR optimization. The circuit computes `AND(0, your_choice)`, which always outputs 0 regardless of input. To get the flag, you must provide the output wire's **one** label key — a value that should be unreachable through normal evaluation.

#### Solution

The circuit uses the **half-gates / point-and-permute** technique where one garbled table entry (at pointer position (0,0)) is implicit (derived via `decrypt_zeros`), and the other three entries are stored explicitly.

In the free XOR scheme, every wire has `one.key = zero.key ⊕ Δ` for a global secret `Δ`. Normal evaluation only yields `wc.zero` (since AND(0, x) = 0). To get `wc.one.key = wc.zero.key ⊕ Δ`, we need to recover `Δ`.

**The vulnerability**: For an AND gate, three of the four truth table rows encrypt `wc.zero` and one encrypts `wc.one`. The encrypted key at position (i,j) is `E(la.key) ⊕ E(lb.key) ⊕ lc.key`, where `E(k) = AES_k(iv‖0)`. Due to the algebraic structure of free XOR (where paired labels differ by `Δ` in key-space), XORing all three explicit table entries causes all the AES terms to cancel:

```
ek[0][1] ⊕ ek[1][0] ⊕ ek[1][1] = Δ
```

This holds regardless of the random pointer bit assignment. With `Δ` recovered, we evaluate normally to get `c0 = wc.zero.key`, then compute `c1 = c0 ⊕ Δ`.

```python
#!/usr/bin/env python3
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

r = remote('chall.lac.tf', 31182)

r.recvuntil(b'decide your fate: ')
r.sendline(b'0')

# Parse wire labels
line0 = r.recvline().decode().strip()  # wire 0: key_hex ptr
line1 = r.recvline().decode().strip()  # wire 1: key_hex ptr

parts0 = line0.split()
key_a = bytes.fromhex(parts0[2])
ptr_a = int(parts0[3])

parts1 = line1.split()
key_b = bytes.fromhex(parts1[2])
ptr_b = int(parts1[3])

# Parse 3 table entries (positions (0,1), (1,0), (1,1))
table_entries = {}
for i, j in ((0, 1), (1, 0), (1, 1)):
    line = r.recvline().decode().strip()
    parts = line.split()
    ek = bytes.fromhex(parts[0])
    ep = int(parts[1])
    table_entries[(i, j)] = (ek, ep)

# Parse IV
iv_line = r.recvline().decode().strip()
iv = bytes.fromhex(iv_line.split()[-1])

# KEY INSIGHT: delta = XOR of the three encrypted keys
ek01 = table_entries[(0, 1)][0]
ek10 = table_entries[(1, 0)][0]
ek11 = table_entries[(1, 1)][0]
delta = strxor(strxor(ek01, ek10), ek11)

# Evaluate normally to get c0 (wc.zero.key)
BUF_LEN = 16

if ptr_a == 0 and ptr_b == 0:
    aes1 = AES.new(key_a, AES.MODE_CTR, nonce=iv)
    aes2 = AES.new(key_b, AES.MODE_CTR, nonce=iv)
    ks2 = aes2.decrypt(bytes(BUF_LEN))
    c0 = aes1.decrypt(ks2)
else:
    ek, ep = table_entries[(ptr_a, ptr_b)]
    aes1 = AES.new(key_a, AES.MODE_CTR, nonce=iv)
    aes2 = AES.new(key_b, AES.MODE_CTR, nonce=iv)
    dec2 = aes2.decrypt(ek)
    c0 = aes1.decrypt(dec2)

# c1 = c0 XOR delta
c1 = strxor(c0, delta)

r.recvuntil(b'mountain: ')
r.sendline(c1.hex().encode())
print(r.recvall(timeout=5).decode())
```

**Flag**: `lactf{m4yb3_h3_w4s_h4ppy_aft3r_4all}`
