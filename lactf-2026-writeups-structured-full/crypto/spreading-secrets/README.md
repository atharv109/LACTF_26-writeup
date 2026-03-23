# spreading-secrets

**Category:** crypto

---

#### Description

The server uses Shamir Secret Sharing over a 512-bit prime field, but it generates the polynomial coefficients from an RNG seeded with the secret itself. Only one share is revealed: `(x, y) = (1, f(1))`, plus the modulus `p`.

#### Solution

In proper Shamir, `threshold` shares are needed because the non-constant coefficients are uniform random and independent of the secret.

Here, coefficients are deterministic functions of the secret:

* `c0 = s`
* `c1 = g(s)`
* `c2 = g(g(s)) = g^2(s)`
* ...
* `c9 = g^9(s)`

where `g(z) = a z^3 + b z^2 + c z + d (mod p)` is the RNG transition.

With only the share at `x=1`:

`f(1) = sum_{i=0..9} c_i = s + g(s) + g^2(s) + ... + g^9(s) = y`.

So `s` is a root of the univariate polynomial over `GF(p)`:

`h(x) = x + g(x) + g^2(x) + ... + g^9(x) - y`.

Since `deg(g)=3`, `deg(g^9)=3^9=19683`, so `h` has degree 19683. We build `h` by iterated composition in the polynomial ring `GF(p)[x]`.

To extract roots without fully factoring `h`, use the finite-field identity that the product of all distinct linear factors of `h` divides `x^p - x`. Thus:

`gcd(h(x), x^p - x)` is the squarefree product of linear factors of `h`.

Compute `x^p mod h(x)` by binary exponentiation (repeated squaring with polynomial modular reduction), then take the GCD and read its roots. There are two roots; the correct one decodes to a flag string.

```python
# solve2.sage
import time

p = 12670098302188507742440574100120556372985016944156009521523684257469947870807586552014769435979834701674318132454810503226645543995288281801918123674138911
F = GF(p)
R.<x> = F[]

a_val = F(4378187236568178488156374902954033554168817612809876836185687985356955098509507459200406211027348332345207938363733672019865513005277165462577884966531159)
b_val = F(5998166089683146776473147900393246465728273146407202321254637450343601143170006002385750343013383427197663710513197549189847700541599566914287390375415919)
c_val = F(4686793799228153029935979752698557491405526130735717565192889910432631294797555886472384740255952748527852713105925980690986384345817550367242929172758571)
d_val = F(4434206240071905077800829033789797199713643458206586525895301388157719638163994101476076768832337473337639479654350629169805328840025579672685071683035027)

y1 = F(6435837956013280115905597517488571345655611296436677708042037032302040770233786701092776352064370211838708484430835996068916818951183247574887417224511655)

def g(poly):
    return a_val * poly^3 + b_val * poly^2 + c_val * poly + d_val

print("Building polynomial...", flush=True)
t0 = time.time()
P = x
total = P
for i in range(9):
    t = time.time()
    P = g(P)
    total += P
    print(f"  Step {i+1}/9, degree: {P.degree()}, time: {time.time()-t:.2f}s", flush=True)

h = total - y1
print(f"Total polynomial degree: {h.degree()}, build time: {time.time()-t0:.2f}s", flush=True)

print("Computing x^p mod h(x) via repeated squaring...", flush=True)
t0 = time.time()
p_bits = bin(p)[2:]
n_bits = len(p_bits)
print(f"  p has {n_bits} bits", flush=True)

xpow = x % h
for i, bit in enumerate(p_bits[1:], 1):
    xpow = (xpow * xpow) % h
    if bit == "1":
        xpow = (xpow * x) % h
    if i % 25 == 0:
        elapsed = time.time() - t0
        rate = i / elapsed if elapsed > 0 else 0
        eta = (n_bits - 1 - i) / rate if rate > 0 else 0
        print(f"  Bit {i}/{n_bits-1}, elapsed: {elapsed:.1f}s, ETA: {eta:.1f}s", flush=True)

print(f"x^p mod h computed in {time.time()-t0:.1f}s", flush=True)

print("Computing GCD...", flush=True)
t = time.time()
linear_factors = gcd(h, xpow - x)
print(f"GCD degree: {linear_factors.degree()}, time: {time.time()-t:.1f}s", flush=True)

roots = linear_factors.roots(multiplicities=False)
print(f"Found {len(roots)} roots", flush=True)
for root in roots:
    s = int(root)
    flag_bytes = s.to_bytes((s.bit_length() + 7) // 8, "big")
    if b"lactf{" in flag_bytes:
        print(flag_bytes.decode())
```

Flag: `lactf{d0nt_d3r1v3_th3_wh0l3_p0lyn0m14l_fr0m_th3_s3cr3t_t00!!!}`
