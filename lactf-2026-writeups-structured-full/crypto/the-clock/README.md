# the-clock

**Category:** crypto

---

#### Description

Don't run out of time

A Diffie-Hellman key exchange is performed on the "clock group" — points (x, y) satisfying x² + y² ≡ 1 (mod p) with the group law `(x1*y2 + y1*x2, y1*y2 - x1*x2)`. The prime p is omitted from the source. Alice and Bob exchange public keys, derive a shared secret, and use it to AES-ECB encrypt the flag. We're given both public keys and the ciphertext.

#### Solution

**Step 1: Recover p.** Each point satisfies x² + y² ≡ 1 (mod p), so p divides (x² + y² - 1) for every known point. Taking the GCD of these values across the base point and both public keys yields p = 13767529254441196841515381394007440393432406281042568706344277693298736356611.

**Step 2: Identify the group structure.** The clock group operation is equivalent to multiplication of elements z = y + ix in F\_{p²} restricted to norm-1 elements. This group has order p+1 when -1 is a quadratic non-residue mod p (which it is here). The order p+1 factors completely into small (\~16-bit) primes: 4 × 39623 × 41849 × 42773 × 46511 × 47951 × 50587 × 50741 × 51971 × 54983 × 55511 × 56377 × 58733 × 61843 × 63391 × 63839 × 64489.

**Step 3: Pohlig-Hellman attack.** Since the group order is entirely smooth, the discrete log problem decomposes via Pohlig-Hellman into tiny subgroup DLPs, each solvable with baby-step giant-step in O(√q) time where q ≤ 64489. CRT combines the partial results to recover Alice's full secret key.

**Step 4: Decrypt.** Compute the shared secret using Alice's secret and Bob's public key, derive the AES key via MD5, and decrypt.

```python
from math import gcd
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import md5
import math

# Points from the challenge
xb = 13187661168110324954294058945757101408527953727379258599969622948218380874617
yb = 5650730937120921351586377003219139165467571376033493483369229779706160055207
xa = 13109366899209289301676180036151662757744653412475893615415990437597518621948
ya = 5214723011482927364940019305510447986283757364508376959496938374504175747801
xbo = 1970812974353385315040605739189121087177682987805959975185933521200533840941
ybo = 12973039444480670818762166333866292061530850590498312261363790018126209960024
enc_flag = bytes.fromhex("d345a465538e3babd495cd89b43a224ac93614e987dfb4a6d3196e2d0b3b57d9")

# Step 1: Recover p from x^2 + y^2 - 1 values via GCD
v1 = xb**2 + yb**2 - 1
v2 = xa**2 + ya**2 - 1
v3 = xbo**2 + ybo**2 - 1
p = gcd(gcd(v1, v2), v3)
# Remove any small factors
for s in range(2, 10000):
    while p % s == 0 and p > s:
        p //= s

# Group order = p+1 (since -1 is a non-residue mod p)
order = p + 1
factors = {
    2: 2, 39623: 1, 41849: 1, 42773: 1, 46511: 1, 47951: 1,
    50587: 1, 50741: 1, 51971: 1, 54983: 1, 55511: 1, 56377: 1,
    58733: 1, 61843: 1, 63391: 1, 63839: 1, 64489: 1
}

def clockadd(P1, P2):
    x1, y1 = P1
    x2, y2 = P2
    return ((x1*y2 + y1*x2) % p, (y1*y2 - x1*x2) % p)

def scalarmult(P, n):
    if n == 0:
        return (0, 1)
    if n < 0:
        P = ((-P[0]) % p, P[1])
        n = -n
    result = (0, 1)
    base = P
    while n > 0:
        if n & 1:
            result = clockadd(result, base)
        base = clockadd(base, base)
        n >>= 1
    return result

def bsgs(base, target, n):
    m = int(math.isqrt(n)) + 1
    table = {}
    base_inv = ((-base[0]) % p, base[1])
    current = target
    for j in range(m):
        table[current] = j
        current = clockadd(current, base_inv)
    giant = scalarmult(base, m)
    current = (0, 1)
    for i in range(m + 1):
        if current in table:
            return (i * m + table[current]) % n
        current = clockadd(current, giant)
    raise ValueError("BSGS failed")

# Pohlig-Hellman
base = (xb, yb)
target = (xa, ya)
remainders, moduli = [], []

for q, e in factors.items():
    exp = order // (q**e)
    g_sub = scalarmult(base, exp)
    t_sub = scalarmult(target, exp)
    if e == 1:
        r = bsgs(g_sub, t_sub, q)
    else:
        r = 0
        gamma = scalarmult(g_sub, q**(e-1))
        t_k = t_sub
        for k in range(e):
            h = scalarmult(t_k, q**(e-1-k))
            d_k = bsgs(gamma, h, q)
            r += d_k * (q**k)
            t_k = clockadd(t_k, scalarmult(g_sub, order - d_k * (q**k)))
    remainders.append(r)
    moduli.append(q**e)

# CRT
def extended_gcd(a, b):
    if a == 0: return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

r, m = remainders[0], moduli[0]
for i in range(1, len(remainders)):
    r2, m2 = remainders[i], moduli[i]
    g, x, _ = extended_gcd(m, m2)
    lcm = m * m2 // g
    r = (r + m * ((r2 - r) // g) * x) % lcm
    m = lcm
alice_secret = r

# Decrypt
shared = scalarmult((xbo, ybo), alice_secret)
key = md5(f"{shared[0]},{shared[1]}".encode()).digest()
flag = unpad(AES.new(key, AES.MODE_ECB).decrypt(enc_flag), 16)
print(f"Flag: {flag.decode()}")
# lactf{t1m3_c0m3s_f4r_u_4all}
```

Flag: `lactf{t1m3_c0m3s_f4r_u_4all}`
