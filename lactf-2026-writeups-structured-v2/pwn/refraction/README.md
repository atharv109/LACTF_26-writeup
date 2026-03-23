# refraction

**Category:** Pwn  
**Primary source:** call4pwn notes from the Discord export.

## Summary

This solve abuses exception / unwinding metadata. The note says to create **two FDEs** so the runtime accepts the structure as a real LSDA table, then point execution to the **`call system` instruction inside `g()`** instead of directly to `system@plt`.

## Key insight

A type check expects `(const char *)`. The bypass uses a valid type table that points to `_ZTIPKc`, which satisfies the runtime type expectations and keeps the unwinder happy.

## High-level plan

1. Forge unwind metadata that looks structurally valid.
2. Include two FDEs so the parser accepts the table.
3. Use a compatible type entry for `const char *`.
4. Redirect the landing logic to the `call system` instruction inside `g()`.

## Why point inside `g()`?

The notes specifically call out that using the in-function `call system` instruction is more reliable than jumping to the PLT directly in this exploit setup.
