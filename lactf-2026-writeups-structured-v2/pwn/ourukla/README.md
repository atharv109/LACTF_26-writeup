# ourukla

**Category:** Pwn  
**Primary source:** inline exploit script by `z0v3r1n_` preserved in the Discord export.

## Summary

The exploit script shows a heap attack that leaks both heap and libc, then pivots into an FSOP-style payload using `_IO_list_all` and `_IO_wfile_jumps` to reach `system("sh")`.

## Step-by-step

1. Allocate and free an entry to leak a heap pointer.
2. Build allocator state with repeated add/free cycles.
3. Leak libc from a later object view.
4. Poison or redirect metadata toward `_IO_list_all - 0x10`.
5. Forge a fake FILE structure in heap memory.
6. Set the fake vtable / jump target so the stream machinery eventually calls `system`.
7. Trigger the final action and pop a shell.

## What the script makes clear

- Heap leak is derived from a shifted pointer.
- libc base is recovered from a known offset subtraction.
- Final payload uses classic FILE-structure corruption fields such as `_IO_stdfile_0_lock`, `_IO_list_all`, and `_IO_wfile_jumps`.
