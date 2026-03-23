# mutation mutation

**Category:** web

---

#### Description

The site claims the flag is “constantly mutating” and that you can get it by inspecting the page.

#### Solution

The server serves two different HTML pages based on `User-Agent`:

* A short decoy page (sent to `curl`-like UAs) that contains a fake `REAL_FLAG`.
* A much larger “real” page (sent to browser UAs) with heavily obfuscated JavaScript that computes the real flag string at runtime.

To solve, fetch the real page using a browser UA, extract the inline `<script>...</script>`, and execute it in Node with minimal DOM stubs. The script computes a constant `F` that is the real `lactf{...}` flag.

Code (one-shot extractor):

```bash
python3 - <<'PY'
import re, subprocess, tempfile, textwrap

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
URL = "https://mutation-mutation.chall.lac.tf/"

html = subprocess.check_output(["curl", "-m", "30", "-sS", "-A", UA, URL]).decode("utf-8", "replace")
script = re.search(r"<script>([\\s\\S]*?)</script>", html).group(1)

runner = textwrap.dedent(\"\"\"\n\
  // Minimal browser stubs so the challenge script can run in Node.\n\
  global.window = { outerWidth: 800, innerWidth: 800, outerHeight: 600, innerHeight: 600 };\n\
  global.NodeFilter = { SHOW_COMMENT: 128 };\n\
\n\
  const fakeParent = { insertBefore() {} };\n\
  const fakeHtml = { parentNode: fakeParent };\n\
  global.document = {\n\
    documentElement: fakeHtml,\n\
    addEventListener() {},\n\
    createTreeWalker() { return { nextNode() { return false; }, currentNode: null }; },\n\
    createComment(s) { return { nodeValue: String(s), remove() {} }; },\n\
  };\n\
\n\
  // Avoid infinite timers.\n\
  global.setInterval = function() { return 0; };\n\
\"\"\")\n+\n+with tempfile.NamedTemporaryFile(\"w\", suffix=\".js\", delete=False, encoding=\"utf-8\") as f:\n+    f.write(runner)\n+    f.write(script)\n+    f.write(\"\\nconsole.log(String(F));\\n\")\n+    path = f.name\n+\n+flag = subprocess.check_output([\"node\", path]).decode(\"utf-8\", \"replace\").strip()\n+print(flag)\n+PY
```

Resulting flag (note: contains Unicode confusables, emoji, and other non-ASCII characters; copy exactly):

```
lactf{с0nѕtаnt_mutаtі0n_1s_fun!_🧬_👋🏽_ІlІ1| ض픋ԡೇ∑ᦞ୞땾᥉༂↗ۑீ᤼യ⌃±❣Ӣ◼ௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌ}
```
