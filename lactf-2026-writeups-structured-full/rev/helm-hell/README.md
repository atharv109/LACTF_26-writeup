# helm hell

**Category:** rev

---

#### Description

We are given a Helm chart (`helm-hell.zip`). Rendering it always produces a ConfigMap with `result: "false"`.

#### Solution

The core logic lives in `work/helm-hell/templates/_helpers.tpl`: thousands of `define` blocks that implement a tiny VM using only Go-template/Sprig primitives (`dict`, `set`, `index`, `add`, `sub`, `mod`, etc.).

Even though the final rendered output is always `false`, the VM still performs prefix-dependent work on `.Values.input`. We can exploit a deterministic side channel:

* The VM uses a small tape `sea` (a map keyed by stringified integers).
* Early in execution, `sea["2"]` is set to `1` and later cleared back to `0`.
* The exact **number of executed template statements** and the current **input index** (`logbook`) at the moment `sea["2"]` transitions `1 -> 0` increases when more of the provided input prefix matches the embedded expected flag.

So we:

1. Implement a minimal interpreter for this limited Go-template subset.
2. Execute the entry template `volumeWorker7940` with `provisions = .Values.input`.
3. Stop exactly when `sea["2"]` clears from `1` to `0`, returning `(logbook, steps)`.
4. Recover the flag one character at a time by trying a charset and choosing the character that maximizes `(logbook, steps)` (using constant padding so the program never runs out of input).

Recovered flag: `lactf{t4k1ng_7h3_h3lm_0f_h31m_73mp14t3s}`

**Solver Code**

```python
#!/usr/bin/env python3
"""Solve LACTF 2026: helm hell

The provided Helm chart always renders `false`, but the (obfuscated) template VM
still runs a prefix-checker internally. We exploit a deterministic side channel:
track the moment tape cell `sea["2"]` is cleared from 1 -> 0. The number of
steps executed and the `logbook` (input index) at that moment increases when
more of the flag prefix matches.

This script:
- Parses templates/_helpers.tpl into a tiny Go-template interpreter.
- Executes the entry template until the 1->0 clear event.
- Brute-forces the flag one character at a time by maximizing (logbook, steps).
"""

import re
import string
from dataclasses import dataclass

TPL_PATH = "work/helm-hell/templates/_helpers.tpl"
BLOCK_RE = re.compile(r"\{\{-\s*(.*?)\s*-\}\}")


# -------- Expression parsing --------

def tokenize_expr(s: str):
    toks = []
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c.isspace():
            i += 1
            continue
        if c in "()":
            toks.append(c)
            i += 1
            continue
        if c == '"':
            i += 1
            out = []
            while i < n:
                if s[i] == '"':
                    break
                if s[i] == "\\" and i + 1 < n:
                    out.append(s[i + 1])
                    i += 2
                    continue
                out.append(s[i])
                i += 1
            if i >= n or s[i] != '"':
                raise ValueError(f"unterminated string: {s!r}")
            i += 1
            toks.append(("str", "".join(out)))
            continue
        j = i
        while j < n and (not s[j].isspace()) and s[j] not in "()":
            j += 1
        toks.append(s[i:j])
        i = j
    return toks


def parse_atom(tok):
    if isinstance(tok, tuple) and tok[0] == "str":
        return ("str", tok[1])
    if tok == "true":
        return ("bool", True)
    if tok == "false":
        return ("bool", False)
    if re.fullmatch(r"-?\d+", tok):
        return ("int", int(tok))
    if tok.startswith("$"):
        if "." in tok:
            base, rest = tok.split(".", 1)
            return ("varpath", base, rest.split("."))
        return ("var", tok)
    if tok.startswith("."):
        return ("dot", tok)
    return ("ident", tok)


def parse_expr_tokens(toks, pos=0, stop_at=None):
    terms = []
    n = len(toks)
    while pos < n:
        t = toks[pos]
        if stop_at is not None and t == stop_at:
            break
        if t == "(":
            sub, pos = parse_expr_tokens(toks, pos + 1, stop_at=")")
            if pos >= n or toks[pos] != ")":
                raise ValueError("missing ')'")
            pos += 1
            terms.append(sub)
            continue
        terms.append(parse_atom(t))
        pos += 1

    if not terms:
        return ("nil", None), pos
    if len(terms) == 1:
        # `(dict)` is used to construct empty maps.
        if terms[0][0] == "ident" and terms[0][1] in {"dict"}:
            return ("call", terms[0][1], []), pos
        return terms[0], pos

    head = terms[0]
    if head[0] != "ident":
        raise ValueError(f"call head not ident: {head}")
    return ("call", head[1], terms[1:]), pos


def parse_expr(s: str):
    toks = tokenize_expr(s)
    expr, pos = parse_expr_tokens(toks, 0, stop_at=None)
    if pos != len(toks):
        raise ValueError(f"unconsumed tokens: {toks[pos:]}")
    return expr


def is_empty(v):
    if v is None:
        return True
    if v is False:
        return True
    if v == 0:
        return True
    if v == "" or v == b"":
        return True
    if isinstance(v, (list, dict, tuple, set)) and len(v) == 0:
        return True
    return False


def to_int(v):
    if isinstance(v, bool):
        return 1 if v else 0
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        v = v.strip()
        return 0 if v == "" else int(v, 10)
    return int(v)


def eval_dot(dot, ref: str):
    cur = dot
    if ref == ".":
        return cur
    path = ref[1:].split(".")
    for p in path:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            cur = getattr(cur, p)
    return cur


def eval_expr(expr, vars_, dot):
    t = expr[0]
    if t == "nil":
        return None
    if t == "int":
        return expr[1]
    if t == "str":
        return expr[1]
    if t == "bool":
        return expr[1]
    if t == "var":
        return vars_[expr[1]]
    if t == "varpath":
        cur = vars_[expr[1]]
        for p in expr[2]:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                cur = getattr(cur, p)
        return cur
    if t == "dot":
        return eval_dot(dot, expr[1])
    if t == "ident":
        return expr[1]

    # call
    fn = expr[1]
    args = [eval_expr(a, vars_, dot) for a in expr[2]]

    if fn == "add":
        return to_int(args[0]) + to_int(args[1])
    if fn == "sub":
        return to_int(args[0]) - to_int(args[1])
    if fn == "mul":
        return to_int(args[0]) * to_int(args[1])
    if fn == "mod":
        return to_int(args[0]) % to_int(args[1])
    if fn == "len":
        return len(args[0])
    if fn == "printf":
        fmt = args[0]
        if not isinstance(fmt, str):
            fmt = str(fmt)
        vals = []
        for v in args[1:]:
            if isinstance(v, bytes):
                v = v.decode("latin-1")
            vals.append(v)
        if len(vals) == 0:
            return fmt
        if len(vals) == 1:
            return fmt % vals[0]
        return fmt % tuple(vals)
    if fn == "int":
        return to_int(args[0])
    if fn == "default":
        dflt, v = args[0], args[1]
        return dflt if is_empty(v) else v
    if fn == "dict":
        if len(args) % 2 != 0:
            raise ValueError("dict requires even args")
        m = {}
        for i in range(0, len(args), 2):
            k = args[i]
            v = args[i + 1]
            if not isinstance(k, str):
                k = str(k)
            m[k] = v
        return m
    if fn == "index":
        container, key = args[0], args[1]
        if isinstance(container, dict):
            # Go templates require matching key types; in this chart `sea` is
            # keyed by strings, so callers always pass string keys.
            return container.get(key) if isinstance(key, str) else None
        if isinstance(container, (bytes, bytearray)):
            return container[to_int(key)]
        if isinstance(container, str):
            return ord(container[to_int(key)])
        return container[to_int(key)]
    if fn == "set":
        m, k, v = args[0], args[1], args[2]
        if not isinstance(m, dict):
            raise ValueError("set on non-dict")
        if not isinstance(k, str):
            k = str(k)
        m[k] = v
        return m
    if fn == "ternary":
        a, b, cond = args[0], args[1], args[2]
        return a if bool(cond) else b

    if fn == "ne":
        return args[0] != args[1]
    if fn == "lt":
        return to_int(args[0]) < to_int(args[1])
    if fn == "gt":
        return to_int(args[0]) > to_int(args[1])

    raise KeyError(f"unsupported function: {fn}")


# -------- Template parsing and execution --------


@dataclass
class Stmt:
    kind: str
    a: object = None
    b: object = None


def parse_templates(path: str):
    templates = {}
    cur_name = None
    cur_stmts = None
    block_stack = []

    def finish():
        nonlocal cur_name, cur_stmts
        if cur_name is not None:
            templates[cur_name] = cur_stmts
        cur_name = None
        cur_stmts = None

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for m in BLOCK_RE.finditer(line):
                content = m.group(1).strip()
                if not content:
                    continue
                if content.startswith('define '):
                    name_m = re.match(r'define\s+"([^"]+)"', content)
                    if not name_m:
                        raise ValueError(f"bad define: {content}")
                    finish()
                    cur_name = name_m.group(1)
                    cur_stmts = []
                    block_stack = ["define"]
                    continue
                if content == "end":
                    ended = block_stack.pop()
                    if ended == "define":
                        finish()
                    else:
                        cur_stmts.append(Stmt("end"))
                    continue
                if cur_name is None:
                    continue
                if content.startswith("if "):
                    cur_stmts.append(Stmt("if", parse_expr(content[3:].strip())))
                    block_stack.append("if")
                    continue

                am = re.match(r'^(\$[A-Za-z0-9_\.]+|\$_)\s*(:=|=)\s*(.*)$', content)
                if am:
                    lhs, rhs = am.group(1), am.group(3)
                    cur_stmts.append(Stmt("assign", lhs, parse_expr(rhs)))
                    continue

                if content.startswith("include "):
                    im = re.match(r'include\s+"([^"]+)"\s+(.*)$', content)
                    if not im:
                        raise ValueError(f"bad include: {content}")
                    tname = im.group(1)
                    arg_expr = parse_expr(im.group(2))
                    cur_stmts.append(Stmt("include", tname, arg_expr))
                    continue

                cur_stmts.append(Stmt("expr", parse_expr(content)))

    if cur_name is not None:
        raise ValueError("unterminated define")

    return templates


def link_ifs(stmts):
    stack = []
    for i, st in enumerate(stmts):
        if st.kind == "if":
            stack.append(i)
        elif st.kind == "end":
            if_i = stack.pop()
            stmts[if_i].b = i + 1
    if stack:
        raise ValueError("unclosed if")


@dataclass
class Frame:
    name: str
    dot: dict
    pc: int
    vars: dict


class Engine:
    def __init__(self, templates):
        self.templates = templates
        for _, stmts in templates.items():
            link_ifs(stmts)

    def run_until_clear(self, provisions: str, *, max_steps=800000):
        root = {"sea": {}, "helm": 0, "cargo": "", "provisions": provisions, "logbook": 0}

        stack = [Frame("volumeWorker7940", dot=root, pc=0, vars={})]
        steps = 0
        last2 = 0

        while stack:
            fr = stack[-1]
            prog = self.templates[fr.name]
            if fr.pc >= len(prog):
                stack.pop()
                continue

            st = prog[fr.pc]
            fr.pc += 1
            steps += 1
            if steps > max_steps:
                return None

            if st.kind == "assign":
                fr.vars[st.a] = eval_expr(st.b, fr.vars, fr.dot)
            elif st.kind == "expr":
                _ = eval_expr(st.a, fr.vars, fr.dot)
            elif st.kind == "if":
                if not bool(eval_expr(st.a, fr.vars, fr.dot)):
                    fr.pc = st.b
            elif st.kind == "end":
                pass
            elif st.kind == "include":
                arg = eval_expr(st.b, fr.vars, fr.dot)
                stack.append(Frame(st.a, dot=arg, pc=0, vars={}))
            else:
                raise ValueError(st.kind)

            sea = fr.vars.get("$sea")
            if isinstance(sea, dict):
                cur2 = sea.get("2", 0)
                if last2 == 1 and cur2 == 0:
                    return steps, fr.vars.get("$logbook")
                last2 = cur2

        return None


def main():
    templates = parse_templates(TPL_PATH)
    eng = Engine(templates)

    charset = string.ascii_lowercase + string.digits + "_" + "}" + string.ascii_uppercase
    padding = "A" * 80

    prefix = "lactf{"
    while True:
        best = None
        for ch in charset:
            res = eng.run_until_clear(prefix + ch + padding)
            if res is None:
                continue
            steps, lb = res
            cand = (lb, steps, ch)
            if best is None or cand > best:
                best = cand
        if best is None:
            raise SystemExit("no candidates")
        prefix += best[2]
        print(prefix)
        if best[2] == "}":
            break


if __name__ == "__main__":
    main()
```
