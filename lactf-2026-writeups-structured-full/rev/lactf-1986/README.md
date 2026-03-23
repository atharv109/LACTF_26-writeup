# lactf-1986

**Category:** rev

---

#### Description

We are given a floppy disk image (`attachments/CHALL.IMG`) containing a DOS executable that checks a flag.

#### Solution

**1) Extract the DOS executable from the FAT12 floppy image**

```bash
mdir -i attachments/CHALL.IMG ::
mcopy -i attachments/CHALL.IMG ::CHALL.EXE extracted/CHALL.EXE
```

**2) Identify the flag-check algorithm**

`CHALL.EXE` is a 16-bit MZ executable. The program’s `main` (in the unpacked load image) does:

1. Reads a line (up to 73 chars), strips the trailing newline.
2. Verifies the input begins with `lactf{`.
3. Computes a 20-bit hash of the full input string:

* State is 20 bits (`0 .. 2^20-1`).
* Update per byte `b`:
  * `state = (state * 67 + b) mod 2^20`

4. Uses that 20-bit state as the seed to generate a keystream using a 20-bit LFSR:

* Let bits be numbered with bit 0 = LSB and bit 19 = MSB.
* Feedback bit:
  * `fb = bit0(state) XOR bit3(state)`
* Update:
  * `state = (state >> 1) | (fb << 19)`

5. For each position `i` (0..72), the program advances the LFSR once, takes the low byte of the new state, XORs it with the input byte, and compares it against a fixed 73-byte table embedded in the program:

```
state = lfsr(state)
expected[i] == (state & 0xff) XOR input[i]
```

Rearrange:

```
input[i] == expected[i] XOR (state & 0xff)
```

So for a *given* seed state, the entire 73-byte plaintext is uniquely determined. The only remaining constraint is self-consistency: the seed must equal the 20-bit hash of the derived plaintext. The state space is only `2^20`, so we can brute-force the seed.

**3) Brute-force the 20-bit seed (single fixed point)**

The ciphertext/expected table is stored in the EXE’s data segment at offset `0x146` and is 0x49 (73) bytes long.

Solver (standalone, includes extraction of the load image and the brute force):

```python
#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

MASK20 = (1 << 20) - 1


def lfsr_step(state: int) -> int:
    # 20-bit LFSR, feedback = bit0 XOR bit3, shift right, insert feedback at bit19.
    fb = (state ^ (state >> 3)) & 1
    return ((state >> 1) | (fb << 19)) & MASK20


def hash20(buf: bytes) -> int:
    # Matches the helper at load-image offset 0x10:
    # state = (state * 67 + byte) mod 2^20
    s = 0
    for c in buf:
        s = (s * 67 + c) & MASK20
    return s


def extract_payload(exe_path: Path) -> bytes:
    # MZ header: e_cparhdr at offset 0x08 is header size in paragraphs (16-byte units).
    exe = exe_path.read_bytes()
    if exe[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    hdr_paras = int.from_bytes(exe[0x08:0x0A], "little")
    hdr_size = hdr_paras * 16
    return exe[hdr_size:]


def main() -> None:
    payload = extract_payload(Path("extracted/CHALL.EXE"))

    # In the flat payload, the data segment starts at 0x2390 (seg_001).
    # The 73-byte expected table is at DS:0x146 => payload offset 0x2390 + 0x146.
    ds_base = 0x2390
    expected = payload[ds_base + 0x146 : ds_base + 0x146 + 0x49]
    if len(expected) != 0x49:
        raise ValueError("bad expected table length")

    prefix = b"lactf{"

    for seed in range(1 << 20):
        # Early prune: enforce the fixed prefix for the first 6 bytes.
        s = seed
        ok = True
        for i, want in enumerate(prefix):
            s = lfsr_step(s)
            got = (s & 0xFF) ^ expected[i]
            if got != want:
                ok = False
                break
        if not ok:
            continue

        # Derive the full 73-byte candidate flag for this seed.
        s = seed
        cand = bytearray(0x49)
        for i in range(0x49):
            s = lfsr_step(s)
            cand[i] = (s & 0xFF) ^ expected[i]

        # Must not contain NUL/newlines (input is line-based).
        if 0 in cand or 10 in cand or 13 in cand:
            continue

        # Self-consistency: hash(cand) must equal seed.
        if hash20(cand) != seed:
            continue

        print(cand.decode("ascii"))
        return

    raise SystemExit("no solution found")


if __name__ == "__main__":
    main()
```

Running it yields the flag:

```
lactf{3asy_3nough_7o_8rute_f0rce_bu7_n0t_ea5y_en0ugh_jus7_t0_brut3_forc3}
```
