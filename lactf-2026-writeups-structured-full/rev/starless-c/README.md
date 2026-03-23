# starless-c

**Category:** rev

---

#### Description

We are given a single weird ELF (`starless_c`) and a remote service (`nc chall.lac.tf 32223`). The program acts like a tiny "maze": it reads single-character moves (`w`, `a`, `s`, `d`) and an action key (`f`).

The goal is to reach the code that prints `flag.txt`.

#### Solution

**1) Identify the flag-print routine**

Disassembling the mapped page at `0x42069000` shows it prints some text, then does:

* `sys_open("flag.txt", 0)`
* `sys_sendfile(1, fd, NULL, 0x100)`
* `sys_exit(0)`

So if we can transfer control to `0x42069000`, we get the flag from the remote filesystem.

**2) Understand the "doors": patching NOP pages**

The interactive loop exists at pages like `0x6767900c`. For each move key, the code:

1. Reads the first byte of the *target* page base (e.g. `0x6768a000`).
2. If that byte is `0x90` (NOP), it:
   * Overwrites the target page's first 4 bytes with `31 c0 88 00` (`xor eax,eax; mov [rax],al`) so executing that page base will crash.
   * Stores the original 4 bytes (often `0x90909090`) into some other page base (a 4-byte write).
3. Jumps to the target page's room loop at `target+0xc`.

This effectively lets you "move" a 4-byte NOP sled (`0x90909090`) around between page bases, while consuming the NOP-ness of pages you step into.

**3) The win condition is a chain of base jumps to the flag routine**

Some page bases contain `jmp rel32` at offset `+4`. If we replace their first 4 bytes with `0x90909090`, they stop crashing and the jump executes.

There is a direct chain to the flag routine:

* `0x6767a000` (base) `jmp` -> `0x67682000`
* `0x67682000` (base) `jmp` -> `0x6768a000`
* `0x6768a000` (base) `jmp` -> `0x67691000`
* `0x67691000` (base) `jmp` -> `0x67692000`
* `0x67692000` (base) `jmp` -> `0x42069000`

The `f` key jumps to `0x6767a000` (the "final door"). So we need the first 4 bytes of these bases to be NOPs at the moment we press `f`: `0x6767a000`, `0x67682000`, `0x6768a000`, `0x67691000`, `0x67692000`.

**4) Automate the maze with BFS (room + bitmask state)**

We can treat each room base as a node. The only mutable state that matters is which room bases currently start with NOP (`0x90`) versus crash (`0x31`).

So we do a BFS over:

* `room`: current room base address
* `mask`: bitmask of NOP-status for each room base

Transitions are extracted from disassembly: for each room and each move key, record `(target, dest)` where `dest` is where the 4-byte copy goes *if* the target starts with NOP.

When a move goes to a target whose base is currently NOP:

* clear the target's NOP bit (it gets patched to crash)
* set the dest's NOP bit (it receives `0x90909090`)

Once the required five bases are NOP, append `f` and the program jumps through the chain to `0x42069000`.

Below is a complete solver that:

1. Uses `gdb` once to list the mapped RWX room pages.
2. Disassembles each room's handler to extract the `(target, dest)` pairs.
3. Runs BFS to find the shortest winning input string.
4. Optionally connects to the remote service and prints the flag.

```python
#!/usr/bin/env python3
import collections
import re
import socket
import subprocess
import sys

BIN = "attachments/starless_c"
HOST = "chall.lac.tf"
PORT = 32223

KEYS = "wsad"

REQUIRED_CHAIN = {
    0x6767A000,
    0x67682000,
    0x6768A000,
    0x67691000,
    0x67692000,
}


def run_gdb_disasm() -> str:
    # Start at entry (so mappings exist), then:
    # - info proc mappings: find all rwxp pages mapped from our binary
    # - disassemble 160 insns at base+0xc for each room (enough to include all move cases)
    base = [
        "set pagination off",
        f"file {BIN}",
        "starti",
        "info proc mappings",
    ]
    out = subprocess.check_output(
        ["gdb", "-q", "-batch"] + sum([["-ex", x] for x in base], []),
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Parse mappings to find room bases (rwxp pages from our file).
    maps = []
    for line in out.splitlines():
        m = re.match(
            r"\s*(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+([rwxp-]{4})\s+(.*)",
            line,
        )
        if not m:
            continue
        start = int(m.group(1), 16)
        perms = m.group(5)
        obj = m.group(6)
        if BIN not in obj:
            continue
        if perms != "rwxp":
            continue
        maps.append(start)

    rooms = sorted(set(maps))
    if not rooms:
        raise RuntimeError("no rwxp room mappings found (gdb parse failed?)")

    # Now disassemble all rooms in one gdb run for speed and stable formatting.
    cmds = ["set pagination off", f"file {BIN}", "starti"]
    for r in rooms:
        cmds.append(f"echo \\n== {r:#x} ==\\n")
        cmds.append(f"x/160i {r+0xc:#x}")

    out2 = subprocess.check_output(
        ["gdb", "-q", "-batch"] + sum([["-ex", x] for x in cmds], []),
        stderr=subprocess.STDOUT,
        text=True,
    )
    return out2


def parse_rooms(gdb_text: str):
    # Split sections by markers: "== 0x... =="
    sections = {}
    cur = None
    for line in gdb_text.splitlines():
        m = re.match(r"== (0x[0-9a-f]+) ==", line.strip())
        if m:
            cur = int(m.group(1), 16)
            sections[cur] = []
            continue
        if cur is not None:
            sections[cur].append(line)

    rooms = {}
    for base, lines in sections.items():
        targets = []
        dests = []
        for ln in lines:
            m = re.search(r"mov\s+.*,%eax\s+#\s+(0x[0-9a-f]+)", ln)
            if m:
                targets.append(int(m.group(1), 16))
            m = re.search(r"mov\s+%eax,.*#\s+(0x[0-9a-f]+)", ln)
            if m:
                dests.append(int(m.group(1), 16))

        # The handler has 4 move cases in the order: w, s, a, d
        if len(targets) < 4 or len(dests) < 4:
            continue
        targets = targets[:4]
        dests = dests[:4]

        rooms[base] = {
            "w": (targets[0], dests[0]),
            "s": (targets[1], dests[1]),
            "a": (targets[2], dests[2]),
            "d": (targets[3], dests[3]),
        }

    if not rooms:
        raise RuntimeError("failed to parse any rooms from gdb disassembly")
    return rooms


def initial_nop_mask(pages):
    # Read the first byte of each mapped page from the file and mark NOP-start pages (0x90).
    # We can infer file offsets via a quick gdb info proc mappings parse again, but simplest:
    # just use the known initial NOP pages for this challenge.
    init_nop = {0x67689000, 0x6768A000, 0x6768C000, 0x6768D000, 0x67694000}
    idx = {p: i for i, p in enumerate(pages)}
    mask = 0
    for p in pages:
        if p in init_nop:
            mask |= 1 << idx[p]
    return mask


def bfs_solution(rooms):
    pages = sorted(rooms.keys())
    idx = {p: i for i, p in enumerate(pages)}

    start_room = 0x67679000
    if start_room not in rooms:
        raise RuntimeError("start room not found in parsed rooms")

    mask0 = initial_nop_mask(pages)

    req_mask = 0
    for p in REQUIRED_CHAIN:
        req_mask |= 1 << idx[p]

    def ready(mask):
        return (mask & req_mask) == req_mask

    q = collections.deque([(start_room, mask0)])
    prev = {(start_room, mask0): (None, None)}  # state -> (prev_state, key)

    while q:
        room, mask = q.popleft()
        if ready(mask):
            # reconstruct path
            path = []
            st = (room, mask)
            while prev[st][0] is not None:
                st, k = prev[st]
                path.append(k)
            return "".join(reversed(path)) + "f"

        for k in KEYS:
            t, d = rooms[room][k]
            if t not in idx:
                continue  # unmapped => would SIGSEGV

            newmask = mask
            # If the target page starts with NOP, the program patches it and copies those bytes to dest.
            if (mask >> idx[t]) & 1:
                if d not in idx:
                    continue  # dest unmapped => would SIGSEGV on the store
                newmask &= ~(1 << idx[t])  # target patched to crash
                newmask |= 1 << idx[d]     # dest receives NOPs

            st2 = (t, newmask)
            if st2 in prev:
                continue
            prev[st2] = ((room, mask), k)
            q.append(st2)

    raise RuntimeError("no solution found")


def fetch_remote(seq: str) -> str:
    with socket.create_connection((HOST, PORT), timeout=10) as s:
        s.sendall(seq.encode())
        s.shutdown(socket.SHUT_WR)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode(errors="replace")


def main():
    gdb_text = run_gdb_disasm()
    rooms = parse_rooms(gdb_text)
    seq = bfs_solution(rooms)
    print(seq)

    if "--remote" in sys.argv:
        print(fetch_remote(seq))


if __name__ == "__main__":
    main()
```

Running the solver produces an input sequence; sending it to the remote service prints the flag: `lactf{starless_c_more_like_starless_0xcc}`.
