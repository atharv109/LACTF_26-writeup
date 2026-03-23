# six seven again

**Category:** crypto

---

#### Description

LA CTF will take place on Feburary 6 and Feburary 7, 2026.

`nc chall.lac.tf 31181`

RSA challenge where one prime `p` is generated with a highly structured form: 67 digits of '6', followed by 67 digits each randomly '6' or '7', followed by 67 digits of '7' (201 decimal digits total). The other prime `q` is a standard 670-bit prime.

#### Solution

The prime `p` has the form:

```
p = base + 10^67 * x
```

where `base = 6 * (10^201 - 10^67)/9 + 7 * (10^67 - 1)/9` is fully known (the contribution from the fixed 6s and 7s, plus the minimum contribution of 6 from each middle digit), and `x = sum(b_i * 10^i for i in 0..66)` with each `b_i ∈ {0,1}` represents the unknown bits (whether each middle digit is 6 or 7).

The key insight is that `x < (10^67 - 1)/9 ≈ 10^66`, which is roughly 219 bits. Since `p ≈ 10^200` (668 bits) and `q ≈ 670` bits, `N ≈ 1338` bits. Coppersmith's method can find small roots of a polynomial modulo an unknown factor of N when the root is smaller than `N^(β²)` where `β ≈ 0.5`. Here `N^0.25 ≈ 2^334`, and our unknown `x ≈ 2^219 < 2^334`, so Coppersmith's method applies directly.

We construct the monic polynomial `f(x) = x + base * (10^67)^{-1} mod N` and use SageMath's `small_roots()` to recover `x`, then factor `N = p * q` and decrypt.

```python
#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import long_to_bytes
from sage.all import *
import subprocess

io = remote('chall.lac.tf', 31181)

# Handle proof of work
io.recvuntil(b'proof of work:\n')
pow_cmd = io.recvline().decode().strip()
io.recvuntil(b'solution:')
challenge = pow_cmd.split()[-1]
result = subprocess.run(
    ['bash', '-c', f'curl -sSfL https://pwn.red/pow | sh -s {challenge}'],
    capture_output=True, text=True, timeout=120
)
io.sendline(result.stdout.strip().encode())

data = io.recvall(timeout=30).decode().strip()
io.close()

lines = [l.strip() for l in data.split('\n') if '=' in l]
vals = {}
for line in lines:
    key, val = line.split('=', 1)
    vals[key.strip()] = int(val.strip())

n = vals['n']
c = vals['c']

# p = 666...6 (67 digits) || mixed 6/7 (67 digits) || 777...7 (67 digits)
# p = base + 10^67 * x where x has 67 binary digits (each 0 or 1)
base = 6 * (10**201 - 10**67) // 9 + 7 * (10**67 - 1) // 9

# Coppersmith's method - make polynomial monic
P = PolynomialRing(Zmod(n), 'x')
x = P.gen()
inv_coeff = inverse_mod(ZZ(10)**67, n)
f = x + ZZ(base) * ZZ(inv_coeff)

X = (10**67 - 1) // 9 + 1
roots = f.small_roots(X=X, beta=0.49, epsilon=1/32)

x0 = int(roots[0])
p = base + 10**67 * x0
q = n // p
assert p * q == n

phi = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)
print(f"Flag: {flag}")
```

**Flag:** `lactf{n_h4s_1337_b1ts_b3c4us3_667+670=1337}`
