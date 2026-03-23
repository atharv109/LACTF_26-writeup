# smol cats

**Category:** crypto

---

#### Description

My cat walked across my keyboard and made this RSA implementation, encrypting the location of the treats they stole from me! However, they already got fed twice today, and are already overweight and needs to lose some weight, so I cannot let them eat more treats. Can you defeat my cat's encryption so I can find their secret stash of treats and keep my cat from overeating?

`nc chall.lac.tf 31224`

#### Solution

Connecting to the server presents an RSA challenge: given `n`, `e=65537`, and `c`, decrypt the ciphertext to recover the plaintext number of treats. The values change each connection.

The key insight is in the description: "my paws are small, so I used tiny primes." The modulus `n` is \~200 bits (60 digits), composed of two \~100-bit primes. This is far too small for secure RSA and can be factored quickly using ECM (Elliptic Curve Method) or other factoring algorithms.

Once `n` is factored into `p * q`, standard RSA decryption recovers the plaintext: compute `phi = (p-1)(q-1)`, then `d = e^(-1) mod phi`, and `m = c^d mod n`.

```python
#!/usr/bin/env sage -python
import re
from pwn import *
from sage.all import *

r = remote('chall.lac.tf', 31224)

data = r.recvuntil(b'How many treats do I want?')
text = data.decode()

n = int(re.search(r'n = (\d+)', text).group(1))
e = int(re.search(r'e = (\d+)', text).group(1))
c = int(re.search(r'c = (\d+)', text).group(1))

# Factor the small RSA modulus using SageMath's built-in factoring (ECM)
factors = factor(n)

# Compute phi(n)
phi = 1
for p, exp in factors:
    phi *= (p - 1) * p**(exp - 1)

# RSA decrypt
d = inverse_mod(e, phi)
m = power_mod(c, d, n)

r.sendline(str(m).encode())
print(r.recvall(timeout=5).decode())
r.close()
```

**Flag:** `lactf{sm0l_pr1m3s_4r3_n0t_s3cur3}`
