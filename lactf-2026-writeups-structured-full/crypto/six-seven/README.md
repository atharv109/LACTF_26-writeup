# six seven

**Category:** crypto

---

#### Description

RSA encryption where primes p and q are 256-digit numbers composed only of digits 6 and 7, with the last digit always being 7. We're given `n = p*q` and `c = pow(m, 65537, n)` and need to decrypt the flag.

#### Solution

Since every digit of p and q is either 6 or 7, we can recover p digit-by-digit from the least significant digit (LSB) upward using the constraint that `n = p * q`.

**Key insight:** If we know `p mod 10^k`, we can compute `q mod 10^k = n * p^(-1) mod 10^k` (since p ends in 7, it's always invertible mod powers of 10). We then check whether the k-th digit of q is in {6, 7}. If not, that candidate is pruned.

At each step we try extending p's next digit with both 6 and 7 (2 choices), but only \~2/10 of candidates survive the digit check on q. The branching factor of 2 \* 0.2 = 0.4 means false candidates die off exponentially, leaving only 1-4 candidates throughout the entire search.

After recovering all 256 digits of p, we verify `n % p == 0`, compute `phi = (p-1)(q-1)`, find `d = e^(-1) mod phi`, and decrypt `m = c^d mod n`.

```python
#!/usr/bin/env python3
from pwn import *
from Crypto.Util.number import long_to_bytes
import subprocess, os

POW_BIN = os.path.expanduser("~/.cache/redpwnpow/redpwnpow-v0.1.2-linux-amd64")

r = remote('chall.lac.tf', 31180)

# Handle proof of work
r.recvuntil(b'proof of work:\n')
pow_cmd = r.recvline().decode().strip()
r.recvuntil(b'solution: ')
challenge = pow_cmd.split()[-1]
result = subprocess.run([POW_BIN, challenge], capture_output=True, text=True, timeout=120)
r.sendline(result.stdout.strip().encode())

# Parse n and c
n = int(r.recvline().decode().strip().split('=')[1])
c = int(r.recvline().decode().strip().split('=')[1])
r.close()

# Factor n digit-by-digit from LSB
# Both p and q have digits in {6,7} and end in 7
candidates = [7]

for k in range(1, 256):
    mod = 10 ** (k + 1)
    n_mod = n % mod
    new_candidates = []
    for p_cand in candidates:
        for d in [6, 7]:
            p_new = p_cand + d * (10 ** k)
            q_new = (n_mod * pow(p_new, -1, mod)) % mod
            q_digit = (q_new // (10 ** k)) % 10
            if q_digit in (6, 7):
                new_candidates.append(p_new)
    candidates = new_candidates

for p in candidates:
    if n % p == 0:
        q = n // p
        phi = (p - 1) * (q - 1)
        d = pow(65537, -1, phi)
        m = pow(c, d, n)
        print(long_to_bytes(m).decode())
        break
```

**Flag:** `lactf{wh4t_67s_15_blud_f4ct0r1ng_15_blud_31nst31n}`
