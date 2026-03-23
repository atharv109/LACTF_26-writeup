# tcademy

**Category:** Pwn  
**Primary sources:** inline exploit script by `z0v3r1n_` and extra note by `frederik8921` preserved in the Discord export.

## Summary

This is a glibc 2.35 heap challenge. The extra note says the core bug is an **integer underflow leading to a massive heap overflow**. From there, solvers could either overwrite a libc GOT target or use **House of Apple 2 / FSOP**.

## Step-by-step

1. Use the size bug / underflow to get an oversized overwrite.
2. Leak libc by viewing a corrupted chunk and subtracting the known libc offset.
3. Leak heap base from a safe-linked pointer.
4. Corrupt chunk metadata so allocation paths can be steered.
5. Redirect control toward `_IO_list_all`.
6. Build a fake FILE object with `system` as the interesting function target.
7. Trigger the program path that walks the corrupted stream state.

## Notes

The supplied exploit script clearly follows the FSOP route, not the simpler GOT route.
