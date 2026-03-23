# ttyspin

**Category:** crypto

---

#### Description

The challenge is a terminal Tetris clone over SSH. You can export/import a save state. Import is protected by a checksum:

```py
sha256((SECRET + username + save_bytes).strip()).hexdigest()
```

The flag is printed only if the in-memory board equals a fixed `winning_board`.

#### Solution

There are two key observations.

**Observation 1: you cannot reach the winning board by playing.** Each placed tetromino adds 4 blocks and each cleared line removes 10 blocks, so the board's non-zero cell count stays even. The provided `winning_board` has 19 blocks (odd), so the only viable path is to **import a crafted save** whose decoded board equals `winning_board`.

**Observation 2: SHA-256 length extension works because glue padding can go in `username`.** The MAC is `SHA256(SECRET || message)` (not HMAC), and `len(SECRET) == 40` is known. The imported `save_bytes` must be valid UTF-8 because `Board.start()` does `save.decode().split("|")`, but `username` is never decoded (it's raw bytes from `sys.stdin.buffer.readline()`), so it can contain arbitrary bytes, including `0x80` and NULs. That lets us do a classic length extension: get a checksum for `SECRET||m`, then forge a checksum for `SECRET||m||glue_padding||ext`, by placing `m||glue_padding` in `username` and `ext` in the imported save (still valid UTF-8).

Practical detail: the code hashes `(SECRET + username + save_bytes).strip()`. If we export with an *empty username* and an *empty board*, the save string ends with many spaces and `.strip()` truncates it, leaving a very short `m` (ending right after the `|` before the board). That keeps `username = m || glue_padding` under the 32-byte username limit.

One more practical constraint: the game only shows the export screen after you have a non-zero score. So you need to score while keeping the board empty; the easiest way is to play until you get a **perfect clear / full clear** (clear lines so the board returns to all-spaces) and then export immediately.

Below is a complete solver that:

* builds a valid save whose board equals `winning_board` (and appends a 1-byte sentinel so `.strip()` won’t trim trailing spaces),
* performs SHA-256 length extension from an exported checksum where username was empty,
* logs in via SSH (Paramiko) and imports the forged save to print the flag.

```py
#!/usr/bin/env python3
import base64
import re
import struct
import sys
import time

import paramiko


# --- Target ---
HOST = "chall.lac.tf"
PORT = 32123
SSH_USER = "ttyspin"
SSH_PASS = "ttyspin"

# From attachments/game.py
WINNING_BOARD = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [7, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 4, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 6, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 3, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 5, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 2, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 7, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 4, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 6],
    [0, 0, 0, 0, 0, 0, 0, 0, 3, 0],
    [0, 0, 0, 0, 0, 0, 0, 5, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 2, 0, 0, 0, 0],
    [0, 0, 0, 0, 7, 0, 0, 0, 0, 0],
    [0, 0, 0, 4, 0, 0, 0, 0, 0, 0],
    [0, 0, 6, 0, 0, 0, 0, 0, 0, 0],
    [0, 3, 0, 0, 0, 0, 0, 0, 0, 0],
    [5, 0, 0, 0, 0, 0, 0, 0, 0, 0],
]


WHITESPACE = b" \t\r\n\v\f"


def board_to_save_text(board):
    # board tiles are integers 0..7; save format uses letters for 1..7:
    # 1=T 2=J 3=L 4=S 5=Z 6=O 7=I, and space for 0.
    # piece_to_type in board.py: {"T":0,"J":1,"L":2,"S":3,"Z":4,"O":5,"I":6}
    letters = ["T", "J", "L", "S", "Z", "O", "I"]
    out = []
    for row in board:
        for v in row:
            out.append(" " if v == 0 else letters[v - 1])
    return "".join(out)


def build_winning_save_bytes():
    # Any valid header is fine; the win check only compares the board.
    # Save format: current|hold|nexts(4)|queue|board(200 chars)
    current = "T"
    hold = " "
    nexts = "TTTT"
    queue = ""
    board_txt = board_to_save_text(WINNING_BOARD)
    assert len(board_txt) == 200

    # Sentinel to stop .strip() from removing trailing spaces from the board.
    # Board.start() only reads the first 200 chars.
    sentinel = "X"

    s = f"{current}|{hold}|{nexts}|{queue}|{board_txt}{sentinel}"
    return s.encode("utf-8")


# --- Minimal SHA-256 with state injection (for length extension) ---
K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def _rotr(x, n):
    return ((x >> n) | ((x & 0xFFFFFFFF) << (32 - n))) & 0xFFFFFFFF


def _ch(x, y, z):
    return (x & y) ^ (~x & z)


def _maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def _bsig0(x):
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


def _bsig1(x):
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


def _ssig0(x):
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


def _ssig1(x):
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def sha256_glue_padding(msg_len_bytes):
    # Standard SHA-256 padding for a message of length msg_len_bytes.
    ml_bits = msg_len_bytes * 8
    pad = b"\x80"
    # pad with zeros until length ≡ 56 (mod 64)
    pad += b"\x00" * ((56 - (msg_len_bytes + 1) % 64) % 64)
    pad += struct.pack(">Q", ml_bits)
    return pad


def sha256_compress(state, block64):
    w = list(struct.unpack(">16I", block64)) + [0] * 48
    for i in range(16, 64):
        w[i] = (w[i - 16] + _ssig0(w[i - 15]) + w[i - 7] + _ssig1(w[i - 2])) & 0xFFFFFFFF

    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + _bsig1(e) + _ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
        t2 = (_bsig0(a) + _maj(a, b, c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    return [
        (state[0] + a) & 0xFFFFFFFF,
        (state[1] + b) & 0xFFFFFFFF,
        (state[2] + c) & 0xFFFFFFFF,
        (state[3] + d) & 0xFFFFFFFF,
        (state[4] + e) & 0xFFFFFFFF,
        (state[5] + f) & 0xFFFFFFFF,
        (state[6] + g) & 0xFFFFFFFF,
        (state[7] + h) & 0xFFFFFFFF,
    ]


def sha256_continue_from_digest(digest_hex, extra, total_prehashed_len_bytes):
    # Continue SHA-256 from an existing digest (internal state), assuming
    # total_prehashed_len_bytes bytes have already been hashed.
    state = list(struct.unpack(">8I", bytes.fromhex(digest_hex)))
    msg = extra + sha256_glue_padding(total_prehashed_len_bytes + len(extra))
    for off in range(0, len(msg), 64):
        state = sha256_compress(state, msg[off : off + 64])
    return struct.pack(">8I", *state).hex()


def forge_from_export(export_save_b64, export_checksum_hex, *, secret_len=40):
    # We export with empty username, so the MAC is sha256((SECRET + save).strip()).
    save = base64.b64decode(export_save_b64)
    m = save.rstrip(WHITESPACE)

    pad1 = sha256_glue_padding(secret_len + len(m))
    if len(m) + len(pad1) > 32:
        raise RuntimeError(
            f"Need shorter stripped export: len(m)={len(m)} pad={len(pad1)} total={len(m)+len(pad1)} > 32"
        )

    ext = build_winning_save_bytes()

    # Server will hash: SECRET || (m||pad1) || ext, then .strip() (our ext ends with 'X', so no trimming).
    forged_username = m + pad1
    forged_save = ext
    total_prehashed = secret_len + len(m) + len(pad1)
    forged_checksum_hex = sha256_continue_from_digest(export_checksum_hex, ext, total_prehashed)

    return forged_username, base64.b64encode(forged_save), forged_checksum_hex.encode()


def import_and_print_flag(username_bytes, save_b64_bytes, checksum_hex_bytes):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        HOST,
        port=PORT,
        username=SSH_USER,
        password=SSH_PASS,
        look_for_keys=False,
        allow_agent=False,
    )

    chan = client.get_transport().open_session()
    chan.get_pty(term="xterm-256color", width=120, height=40)
    chan.invoke_shell()
    chan.settimeout(2.0)

    def recv_all_until_quiet(quiet_seconds=0.6, hard_timeout=10.0):
        buf = b""
        start = time.time()
        last = time.time()
        while True:
            now = time.time()
            if now - start > hard_timeout:
                break
            if chan.recv_ready():
                chunk = chan.recv(65535)
                if not chunk:
                    break
                buf += chunk
                last = now
            else:
                if now - last >= quiet_seconds:
                    break
                time.sleep(0.05)
        return buf

    time.sleep(0.2)
    _ = recv_all_until_quiet(quiet_seconds=0.2, hard_timeout=1.0)

    chan.sendall(username_bytes + b"\n")
    chan.sendall(save_b64_bytes + b"\n")
    chan.sendall(checksum_hex_bytes + b"\n")

    out = recv_all_until_quiet(quiet_seconds=0.8, hard_timeout=12.0)
    m = re.search(br"lactf\{[^}\n]+\}", out, flags=re.IGNORECASE)
    if not m:
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        raise RuntimeError("flag not found in output")
    print(m.group(0).decode("ascii", errors="ignore"))

    chan.close()
    client.close()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <export_save_b64> <export_checksum_hex>")
        print("Tip: export with empty username, and aim for an empty board so the stripped export is short.")
        return 2

    export_save_b64 = sys.argv[1].encode()
    export_checksum_hex = sys.argv[2].strip()
    username, save_b64, checksum = forge_from_export(export_save_b64, export_checksum_hex)
    import_and_print_flag(username, save_b64, checksum)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Flag: `lactf{T3rM1n4L_g4mE5_R_a_Pa1N_2e075ab9ae6ae098}`

***
