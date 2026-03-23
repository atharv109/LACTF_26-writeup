# flag-finder

**Category:** rev

---

#### Description

The challenge provides a web UI with a 19x101 checkbox grid. Pressing "Find" serializes the grid as a 1919-character string of `#` (checked) and `.` (unchecked) and tests it against a single huge JavaScript regex in `script.js`.

The regex encodes a nonogram: one set of constraints for each row and each column. Solving the nonogram reveals 3 lines of 3x5 pixel text spelling the flag.

#### Solution

1. Fetch `script.js` from the challenge and extract the `const theFlag = /^...$/;` regex.
2. Parse constraints from the regex.

* Row constraints: after the `(?=^.{1919}$)` marker, there are 19 capturing groups, one per row, that contain `#` and `#{n}` runs separated by `\.+` (at least one `.`). Converting each group into a list of run-lengths gives the row clues.
* Column constraints: at the start of the regex there is a large group of nested `(?=...)` lookaheads. Each leaf lookahead constrains a single column by repeatedly jumping by `WIDTH` (`.{col}X.{WIDTH-1-col}` patterns). Counting the `(?: ... # ... ){n}` pieces yields the run-lengths for that column.

3. Solve the 19x101 nonogram.

* Use a standard nonogram line-solver with DP: for a given line (row or column) with some forced cells (filled/empty/unknown) and a list of runs, enumerate valid placements via dynamic programming and compute which cells are always filled or always empty.
* Propagate row/column deductions until no more changes.
* If cells remain unknown, backtrack (try `#` then `.`) with propagation at each step.

4. Decode the solved grid.

* The text is arranged as 3 bands of 25 characters each.
* For each band, take rows `6*band+1 .. 6*band+5` (5 rows) and columns in 25 blocks of 3 pixels with 1-column gaps: block `k` is columns `4*k+1 .. 4*k+3`.
* Map each 3x5 bitmap to a character (letters plus leetspeak digits/punctuation).

Decoded flag (from the solved grid): `lactf{Wh47_d0_y0u_637_wh3n_y0u_cr055_4_r363x_4nd_4_n0n06r4m?_4_r363x06r4m!}`

Solver (end-to-end: fetch regex, parse clues, solve, render):

```python
#!/usr/bin/env python3
import re
import sys
from functools import lru_cache
from urllib.request import urlopen, Request

WIDTH = 101
HEIGHT = 19
N = WIDTH * HEIGHT

URL = "https://flag-finder.chall.lac.tf/script.js"


def fetch_script() -> str:
    req = Request(URL, headers={"User-Agent": "ctf-solver"})
    with urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def extract_regex(js: str) -> str:
    # Extract between `const theFlag = /` and `$/;`
    m = re.search(r"const\s+theFlag\s*=\s*/\^(.*)\$\/;", js, flags=re.S)
    if not m:
        raise RuntimeError("could not extract regex")
    return "^" + m.group(1) + "$"


def extract_lookaheads(prefix: str):
    # Extract all (?=...) blocks with balanced parentheses.
    out = []
    i = 0
    # Important: lookaheads are nested (there's an outer (?=...) containing many inner (?=...)),
    # so we must allow overlaps and keep scanning inside already-extracted spans.
    while i < len(prefix):
        if not prefix.startswith("(?=", i):
            i += 1
            continue

        j = i
        depth = 0
        k = j
        while k < len(prefix):
            ch = prefix[k]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    out.append(prefix[j : k + 1])
                    break
            k += 1
        else:
            raise RuntimeError("unbalanced parentheses while extracting lookahead")

        i = j + 3
    return out


def infer_col_idx(lookahead_content: str) -> int:
    # Find the first (?: ... ) stride group and infer the fixed column index from its leading wildcard length.
    m = re.search(r"\(\?:([^)]*)\)", lookahead_content)
    if not m:
        raise RuntimeError(f"no (?:...) stride found in lookahead: {lookahead_content[:80]}...")
    inside = m.group(1)

    if inside.startswith(".{"):
        m2 = re.match(r"\.\{(\d+)\}", inside)
        if not m2:
            raise RuntimeError(f"failed to parse .{{n}} prefix: {inside[:40]}")
        return int(m2.group(1))
    if inside.startswith("."):
        # Single wildcard '.' means lead=1
        return 1
    if inside.startswith("\\.") or inside.startswith("#"):
        return 0

    raise RuntimeError(f"unrecognized stride prefix: {inside[:40]}")


def parse_runs_from_row_group(group_pat: str):
    runs = []
    i = 0
    while i < len(group_pat):
        if group_pat[i] == "#":
            if i + 1 < len(group_pat) and group_pat[i + 1] == "{":
                j = group_pat.find("}", i + 2)
                if j == -1:
                    raise RuntimeError(f"unterminated #{{n}} in {group_pat}")
                runs.append(int(group_pat[i + 2 : j]))
                i = j + 1
            else:
                runs.append(1)
                i += 1
        else:
            i += 1
    return runs


def parse_runs_from_col_lookahead(lookahead_content: str):
    runs = []
    # Find each (?: ... # ... ) with optional {n} quantifier.
    for m in re.finditer(r"\(\?:[^)]*#[^)]*\)(?:\{(\d+)\})?", lookahead_content):
        n = m.group(1)
        runs.append(int(n) if n else 1)
    return runs


def extract_row_groups(row_part: str):
    # Capturing groups ( ... ) that are not special groups like (?: or (?<= ... )
    # Row groups have no nested parentheses, so this is safe.
    return re.findall(r"\((?!\?)([^()]*)\)", row_part)


def deduce_line(assign, runs):
    L = len(assign)
    mask = (1 << L) - 1

    pref_one = [0] * (L + 1)
    pref_zero = [0] * (L + 1)
    for i, v in enumerate(assign):
        pref_one[i + 1] = pref_one[i] + (1 if v == 1 else 0)
        pref_zero[i + 1] = pref_zero[i] + (1 if v == 0 else 0)

    def has_one(a, b):
        return (pref_one[b] - pref_one[a]) != 0

    def has_zero(a, b):
        return (pref_zero[b] - pref_zero[a]) != 0

    @lru_cache(None)
    def dp(i, pos):
        # Return (union_filled, inter_filled) for suffix starting at pos placing runs[i:]
        if i == len(runs):
            if has_one(pos, L):
                return None
            return (0, 0)

        r = runs[i]
        union_total = 0
        inter_total = None

        max_start = L - r
        for s in range(pos, max_start + 1):
            # empties before run
            if has_one(pos, s):
                continue
            # run cells cannot contain forced empty
            if has_zero(s, s + r):
                continue

            if i != len(runs) - 1:
                # need a gap cell
                if s + r >= L:
                    continue
                if assign[s + r] == 1:
                    continue
                nxt = s + r + 1
            else:
                nxt = s + r

            tail = dp(i + 1, nxt)
            if tail is None:
                continue
            union_tail, inter_tail = tail

            run_bits = ((1 << r) - 1) << s
            union_here = run_bits | union_tail
            inter_here = run_bits | inter_tail

            union_total |= union_here
            inter_total = inter_here if inter_total is None else (inter_total & inter_here)

        if inter_total is None:
            return None
        return (union_total & mask, inter_total & mask)

    res = dp(0, 0)
    if res is None:
        return None

    union_filled, inter_filled = res

    forced = list(assign)
    for j in range(L):
        bit = 1 << j
        can_fill = (union_filled & bit) != 0
        must_fill = (inter_filled & bit) != 0

        if must_fill:
            if forced[j] == 0:
                return None
            forced[j] = 1
        elif not can_fill:
            if forced[j] == 1:
                return None
            forced[j] = 0

    return forced


def solve_nonogram(row_runs, col_runs):
    grid = [[-1] * WIDTH for _ in range(HEIGHT)]

    def propagate():
        changed = True
        while changed:
            changed = False

            # Rows
            for r in range(HEIGHT):
                ded = deduce_line(tuple(grid[r]), tuple(row_runs[r]))
                if ded is None:
                    return False
                if list(ded) != grid[r]:
                    for c in range(WIDTH):
                        if grid[r][c] != ded[c]:
                            grid[r][c] = ded[c]
                            changed = True

            # Columns
            for c in range(WIDTH):
                col = tuple(grid[r][c] for r in range(HEIGHT))
                ded = deduce_line(col, tuple(col_runs[c]))
                if ded is None:
                    return False
                if any(grid[r][c] != ded[r] for r in range(HEIGHT)):
                    for r in range(HEIGHT):
                        if grid[r][c] != ded[r]:
                            grid[r][c] = ded[r]
                            changed = True

        return True

    def find_unknown():
        for r in range(HEIGHT):
            for c in range(WIDTH):
                if grid[r][c] == -1:
                    return (r, c)
        return None

    def backtrack():
        if not propagate():
            return False
        unk = find_unknown()
        if unk is None:
            return True

        r, c = unk
        snapshot = [row[:] for row in grid]

        for v in (1, 0):
            grid[r][c] = v
            if backtrack():
                return True
            # restore
            for rr in range(HEIGHT):
                grid[rr] = snapshot[rr][:]

        return False

    if not backtrack():
        raise RuntimeError("no solution")

    return grid


def render_grid(grid):
    return "\n".join("".join("#" if v == 1 else "." for v in row) for row in grid)


def flatten_grid(grid):
    return "".join("".join("#" if v == 1 else "." for v in row) for row in grid)


def render_bands(grid):
    # Print each of 3 bands (6 rows: 5 glyph rows + descender row) with spaces between glyphs.
    out = []
    for band in range(3):
        y0 = 6 * band + 1
        out.append(f"[band {band} rows {y0}-{y0+5}]")
        for dy in range(6):
            y = y0 + dy
            line = []
            for k in range(25):
                x0 = 4 * k + 1
                block = "".join("#" if grid[y][x] == 1 else " " for x in range(x0, x0 + 3))
                line.append(block)
            out.append(" ".join(line))
        out.append("")
    return "\n".join(out)


def extract_glyphs(grid):
    # 3 bands, 25 glyphs each, 3x5. (Separator rows may contain decoration; ignore them.)
    glyphs = []
    for band in range(3):
        y0 = 6 * band + 1
        for k in range(25):
            x0 = 4 * k + 1
            g = []
            for dy in range(5):
                y = y0 + dy
                g.append("".join("#" if grid[y][x] == 1 else "." for x in range(x0, x0 + 3)))
            glyphs.append(tuple(g))
    return glyphs


def check_candidate(glyphs, name, cand):
    if len(cand) != len(glyphs):
        print(f"[check:{name}] length mismatch: cand={len(cand)} glyphs={len(glyphs)}")
        return False

    mp = {}
    conflicts = []
    for i, ch in enumerate(cand):
        g = glyphs[i]
        if ch in mp and mp[ch] != g:
            conflicts.append((i, ch))
        mp.setdefault(ch, g)

    if conflicts:
        print(f"[check:{name}] conflicts={len(conflicts)} (showing up to 10): {conflicts[:10]}")
        return False

    print(f"[check:{name}] OK")
    return True


def main():
    js = fetch_script()
    full_re = extract_regex(js)

    # Split regex into prefix (column assertions) and row part.
    marker = "(?=^.{1919}$)"
    idx = full_re.find(marker)
    if idx == -1:
        raise RuntimeError("marker not found")

    prefix = full_re[:idx]
    row_part = full_re[idx + len(marker) :]

    # Rows
    row_groups = extract_row_groups(row_part)
    if len(row_groups) != HEIGHT:
        raise RuntimeError(f"expected {HEIGHT} row groups, got {len(row_groups)}")
    row_runs = [parse_runs_from_row_group(g) for g in row_groups]

    # Columns
    all_lookaheads = extract_lookaheads(prefix)
    leaf_lookaheads = []
    for la in all_lookaheads:
        content = la[3:-1]
        if "(?=" in content:
            continue
        leaf_lookaheads.append(content)

    cols_by_idx = {}
    for content in leaf_lookaheads:
        c = infer_col_idx(content)
        cols_by_idx[c] = parse_runs_from_col_lookahead(content)

    if len(cols_by_idx) != WIDTH:
        missing = sorted(set(range(WIDTH)) - set(cols_by_idx))
        raise RuntimeError(f"expected {WIDTH} columns, got {len(cols_by_idx)}; missing={missing[:10]}")

    col_runs = [cols_by_idx[c] for c in range(WIDTH)]

    grid = solve_nonogram(row_runs, col_runs)

    s = flatten_grid(grid)
    if len(s) != N:
        raise RuntimeError("grid length mismatch")

    # Verify against the actual JS regex via Python re (should match exactly).
    # Python and JS regex syntax match for this pattern usage.
    if not re.fullmatch(full_re, s):
        raise RuntimeError("solution grid does not match regex")

    glyphs = extract_glyphs(grid)
    print(render_bands(grid))

    # Sanity-check common candidate transcriptions.
    c1 = "lactf{wh47_do_you_637_wh3n_you_cross_4_r363x_4nd_4_nono6r4m?_4_r363xo6r4m!}"
    c2 = "lactf{what_do_you_get_when_you_cross_a_regex_and_a_nonogram?_a_regexogram!}"
    check_candidate(glyphs, "leet", c1)
    check_candidate(glyphs, "decoded", c2)


if __name__ == "__main__":
    main()
```
