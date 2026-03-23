# misdirection

**Category:** Crypto / Misc crossover in the exported notes  
**Primary source:** SenequeZ writeup and extra summary notes preserved inline.

## Summary

The critical bug is in the **quicksilver multiplication check**. It should be blinded with a fresh VOLE triple, but it is not. That leaks enough structure to break the intended soundness assumptions.

## Important nuance

The exported notes specifically say that a “for-loop-only-runs-once” bug reduces proof soundness in a way that benefits the prover, but that is **not** the main attacker bug. The real issue is the missing blinding in the multiplication check.

## Extra note

According to the author note preserved in the export, the working solve differs by only a few lines in `ostriple`, where elements are printed.
