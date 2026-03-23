# error-correction

**Category:** misc

---

#### Description

We are given `chall.png`, a scrambled QR code (version 7, 45x45 modules, no border). The challenge script (`attachments/chall.py`) shows it was made by:

1. Generating a QR for the flag (`segno.make(..., mode='byte', error='L', boost_error=False, version=7)`).
2. Splitting the 45x45 module image into a 5x5 grid of 9x9 chunks (25 total).
3. Randomly shuffling the chunks and reassembling into a scrambled QR image.

Goal: recover the original chunk permutation and decode the QR to get the flag.

#### Solution

Phase 1 (already reflected in `progress.md`) uses QR *function patterns* (finders, timing, alignments, version info) to place 13 of 25 chunks uniquely.

The remaining 12 chunks lie entirely in the data area, so structural matching alone is insufficient.

Key trick to finish:

* For a fixed QR configuration (v7, EC=L, mask pattern), and a fixed *payload length* `nbytes`, many of the *placed codewords* are **invariant** across different payload contents of that same length (they correspond to padding-only regions and their Reed-Solomon EC).
* We can discover these invariant codewords empirically by generating a few random payloads of length `nbytes` with `segno`, extracting the raw (unmasked) placed codewords from the generated matrices, and taking the positions that are identical across all samples.
* Those invariant codewords imply exact expected module colors at many matrix coordinates. That creates strong per-position constraints, which lets us solve the remaining chunk permutation via backtracking.
* The only unknown is the payload length, so we iterate `nbytes` until reconstruction yields a decodable `lactf{...}`.

Running the solver prints the decoded flag and writes the reconstructed QR to `/tmp/qr_solve_solved.png`.

Solution code:

```python
#!/usr/bin/env python3
"""
Solve: error-correction (LA CTF)

The QR (v7, EC=L) was split into 25 (9x9) chunks, shuffled, and reassembled.

Phase 1 (already done in progress.md) identifies 13 chunk placements using
function-pattern (structural) constraints.

Phase 2 (this script) uses a stronger constraint:
For v7-L with a fixed payload length, many placed codewords are deterministic
padding/EC and therefore invariant across different payload contents.
"""

from __future__ import annotations

import os
from typing import Dict, List, Tuple

import numpy as np
from PIL import Image
import segno

SIZE = 45
CHUNK = 9

HERE = os.path.dirname(os.path.abspath(__file__))
ATTACH = os.path.join(HERE, "attachments")
CHALL_PNG = os.path.join(ATTACH, "chall.png")


def load_chunks() -> List[np.ndarray]:
    img = Image.open(CHALL_PNG).convert("L")
    small = img.resize((SIZE, SIZE), Image.Resampling.NEAREST)
    arr = np.array(small, dtype=np.uint8)
    out: List[np.ndarray] = []
    for cy in range(5):
        for cx in range(5):
            out.append(arr[CHUNK * cy : CHUNK * (cy + 1), CHUNK * cx : CHUNK * (cx + 1)].copy())
    assert len(out) == 25
    return out


def dark(pixel: int) -> int:
    # chall.png uses 0 for black, 255 for white.
    return 1 if pixel == 0 else 0


def mask_func(r: int, c: int, pattern: int) -> bool:
    if pattern == 0:
        return (r + c) % 2 == 0
    if pattern == 1:
        return r % 2 == 0
    if pattern == 2:
        return c % 3 == 0
    if pattern == 3:
        return (r + c) % 3 == 0
    if pattern == 4:
        return (r // 2 + c // 3) % 2 == 0
    if pattern == 5:
        return ((r * c) % 2 + (r * c) % 3) == 0
    if pattern == 6:
        return (((r * c) % 2 + (r * c) % 3) % 2) == 0
    if pattern == 7:
        return (((r + c) % 2 + (r * c) % 3) % 2) == 0
    raise ValueError("bad mask pattern")


def read_format_info_from_tl_chunk(chunk_tl: np.ndarray) -> Tuple[str, int]:
    """
    Read format info from the (top-left) finder block region.

    Returns (ec_level_name, mask_pattern).
    """
    bits_raw: List[int] = []

    # Copy 1 around top-left finder:
    # row 8: cols 0-5
    for c in range(6):
        bits_raw.append(dark(int(chunk_tl[8, c])))
    # row 8: col 7 (skip col 6 timing)
    bits_raw.append(dark(int(chunk_tl[8, 7])))
    # row 8: col 8
    bits_raw.append(dark(int(chunk_tl[8, 8])))
    # col 8: rows 7,5,4,3,2,1,0 (skip row 6 timing)
    for r in [7, 5, 4, 3, 2, 1, 0]:
        bits_raw.append(dark(int(chunk_tl[r, 8])))

    # Unmask (XOR) with 0b101010000010010
    fmt_mask = [1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0]
    bits = [a ^ b for a, b in zip(bits_raw, fmt_mask)]

    ec_level = bits[0] * 2 + bits[1]
    mask_pattern = bits[2] * 4 + bits[3] * 2 + bits[4]

    ec_names = {0: "M", 1: "L", 2: "H", 3: "Q"}
    return ec_names.get(ec_level, "?"), mask_pattern


def build_function_mask_v7() -> np.ndarray:
    """
    True where modules are NOT data modules (finder/timing/alignment/version/format/etc).
    """
    m = np.zeros((SIZE, SIZE), dtype=bool)

    # Finder patterns + separators (9x9 incl. separator)
    m[0:9, 0:9] = True
    m[0:9, SIZE - 8 : SIZE] = True
    m[SIZE - 8 : SIZE, 0:9] = True

    # Timing patterns
    m[6, 8 : SIZE - 8] = True
    m[8 : SIZE - 8, 6] = True

    # Alignment patterns (v7: centers at 6, 22, 38)
    for ar in [6, 22, 38]:
        for ac in [6, 22, 38]:
            if ar <= 8 and ac <= 8:
                continue
            if ar <= 8 and ac >= SIZE - 8:
                continue
            if ar >= SIZE - 8 and ac <= 8:
                continue
            m[ar - 2 : ar + 3, ac - 2 : ac + 3] = True

    # Version info (v7+)
    m[0:6, SIZE - 11 : SIZE - 8] = True
    m[SIZE - 11 : SIZE - 8, 0:6] = True

    # Dark module (row 4*version + 9, col 8) => (37,8) for v7
    m[SIZE - 8, 8] = True

    # Format info areas (mark the common bounding parts; these positions are never data)
    m[8, 0:9] = True
    m[0:9, 8] = True
    m[8, SIZE - 8 : SIZE] = True
    m[SIZE - 8 : SIZE, 8] = True

    return m


def data_placement_order(is_function: np.ndarray) -> List[Tuple[int, int]]:
    """
    List of (r,c) for data modules in placement order (bit order).
    """
    place: List[Tuple[int, int]] = []
    col = SIZE - 1
    going_up = True
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(SIZE - 1, -1, -1) if going_up else range(0, SIZE)
        for r in rows:
            for dc in (0, -1):
                c = col + dc
                if c >= 0 and not is_function[r, c]:
                    place.append((r, c))
        going_up = not going_up
        col -= 2
    return place


def extract_codewords_from_segno(payload: bytes, mask_pattern: int) -> List[int]:
    """Extract the 196 raw (unmasked) placed codewords from a segno-generated QR."""
    qr = segno.make(payload, mode="byte", error="L", boost_error=False, version=7, mask=mask_pattern)
    ref = np.array(qr.matrix, dtype=np.uint8)  # 1=dark
    assert ref.shape == (SIZE, SIZE)

    is_function = build_function_mask_v7()
    place = data_placement_order(is_function)
    assert len(place) == 196 * 8

    bits: List[int] = []
    for r, c in place:
        mod = int(ref[r, c])
        raw = mod ^ (1 if mask_func(r, c, mask_pattern) else 0)
        bits.append(raw)

    codewords: List[int] = []
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        codewords.append(b)
    assert len(codewords) == 196
    return codewords


def invariant_codewords_for_length(nbytes: int, mask_pattern: int, samples: int = 4) -> Dict[int, int]:
    """
    For a fixed payload length, generate a few random payloads and find which
    *placed* codeword positions are invariant (same across all samples).
    """
    rng = np.random.default_rng(0xC0DEF00D)  # deterministic
    cws_samples: List[List[int]] = []
    for _ in range(samples):
        payload = bytes(int(x) for x in rng.integers(0, 256, size=nbytes, dtype=np.uint16))
        cws_samples.append(extract_codewords_from_segno(payload, mask_pattern))

    inv: Dict[int, int] = {}
    for i in range(196):
        vals = {s[i] for s in cws_samples}
        if len(vals) == 1:
            inv[i] = next(iter(vals))
    return inv


def expected_pixels_for_invariant_codewords(mask_pattern: int, inv_cw: Dict[int, int]) -> Dict[Tuple[int, int], int]:
    """Map (r,c) -> expected pixel for all bits belonging to invariant placed codewords."""
    is_function = build_function_mask_v7()
    place = data_placement_order(is_function)
    exp: Dict[Tuple[int, int], int] = {}
    for cw_idx, cw_val in inv_cw.items():
        for bit_in_cw in range(8):
            bit_idx = cw_idx * 8 + bit_in_cw
            r, c = place[bit_idx]
            raw_bit = (cw_val >> (7 - bit_in_cw)) & 1
            mod = raw_bit ^ (1 if mask_func(r, c, mask_pattern) else 0)
            exp[(r, c)] = 0 if mod == 1 else 255
    return exp


def solve_assignment(chunks: List[np.ndarray], exp: Dict[Tuple[int, int], int]) -> Dict[int, int]:
    # Known placements (position index pi = cy*5+cx -> scrambled chunk index ci)
    known: Dict[int, int] = {
        0: 24,  # (0,0)
        1: 21,  # (1,0)
        2: 10,  # (2,0)
        3: 9,  # (3,0)
        4: 15,  # (4,0)
        5: 11,  # (0,1)
        10: 0,  # (0,2)
        12: 1,  # (2,2)
        14: 7,  # (4,2)
        15: 3,  # (0,3)
        20: 5,  # (0,4)
        22: 20,  # (2,4)
        24: 19,  # (4,4)
    }

    used = set(known.values())
    remaining_chunks = [i for i in range(25) if i not in used]
    remaining_positions = [i for i in range(25) if i not in known]

    # Build per-position constraints from expected pixels
    pos_constraints: Dict[int, Dict[Tuple[int, int], int]] = {}
    for pi in remaining_positions:
        cy, cx = divmod(pi, 5)
        cons: Dict[Tuple[int, int], int] = {}
        for lr in range(CHUNK):
            for lc in range(CHUNK):
                r = cy * CHUNK + lr
                c = cx * CHUNK + lc
                v = exp.get((r, c))
                if v is not None:
                    cons[(lr, lc)] = v
        pos_constraints[pi] = cons

    # Candidate chunks for each remaining position
    candidates: Dict[int, List[int]] = {}
    for pi in remaining_positions:
        cons = pos_constraints[pi]
        cand: List[int] = []
        for ci in remaining_chunks:
            ok = True
            ch = chunks[ci]
            for (lr, lc), v in cons.items():
                if int(ch[lr, lc]) != v:
                    ok = False
                    break
            if ok:
                cand.append(ci)
        candidates[pi] = cand

    # Backtrack (MRV)
    order = sorted(remaining_positions, key=lambda p: len(candidates[p]))
    assign: Dict[int, int] = dict(known)
    used2 = set(known.values())

    def bt(idx: int) -> bool:
        if idx == len(order):
            return True
        pi = order[idx]
        for ci in candidates[pi]:
            if ci in used2:
                continue
            assign[pi] = ci
            used2.add(ci)
            if bt(idx + 1):
                return True
            used2.remove(ci)
            del assign[pi]
        return False

    if not bt(0):
        raise RuntimeError("No assignment found under constraints")
    if len(assign) != 25:
        raise RuntimeError(f"Incomplete assignment: {len(assign)}/25")
    return assign


def reconstruct_matrix(chunks: List[np.ndarray], assign: Dict[int, int]) -> np.ndarray:
    out = np.zeros((SIZE, SIZE), dtype=np.uint8)
    for pi, ci in assign.items():
        cy, cx = divmod(pi, 5)
        out[CHUNK * cy : CHUNK * (cy + 1), CHUNK * cx : CHUNK * (cx + 1)] = chunks[ci]
    return out


def decode_qr(qr_mat: np.ndarray) -> str | None:
    img = Image.fromarray(qr_mat).resize((450, 450), Image.Resampling.NEAREST)

    try:
        from pyzbar.pyzbar import decode as zdecode

        res = zdecode(img)
        if res:
            return res[0].data.decode("utf-8", errors="replace")
    except Exception:
        pass

    try:
        import cv2

        det = cv2.QRCodeDetector()
        data, _, _ = det.detectAndDecode(np.array(img))
        if data:
            return data
    except Exception:
        pass

    return None


def main() -> None:
    chunks = load_chunks()

    # Determine mask pattern from TL chunk (chunk 24 at pos (0,0))
    known_tl = 24
    chunk_tl = chunks[known_tl]
    ec_level, mask_pattern = read_format_info_from_tl_chunk(chunk_tl)
    if ec_level != "L":
        raise RuntimeError(f"Unexpected EC level: {ec_level}")

    # Search payload length by leveraging segno invariants.
    for nbytes in range(1, 160):
        try:
            inv = invariant_codewords_for_length(nbytes, mask_pattern, samples=4)
        except Exception:
            # Too long (or otherwise invalid) for v7-L.
            break

        # Need a decent number of invariants to constrain anything.
        if len(inv) < 24:
            continue

        exp = expected_pixels_for_invariant_codewords(mask_pattern, inv)
        try:
            assign = solve_assignment(chunks, exp)
        except RuntimeError:
            continue

        qr = reconstruct_matrix(chunks, assign)
        decoded = decode_qr(qr)
        if decoded and decoded.startswith("lactf{") and decoded.endswith("}"):
            out_path = "/tmp/qr_solve_solved.png"
            Image.fromarray(qr).resize((450, 450), Image.Resampling.NEAREST).save(out_path)
            print(decoded)
            return

    raise SystemExit("Failed to decode for any tested length")


if __name__ == "__main__":
    main()
```
