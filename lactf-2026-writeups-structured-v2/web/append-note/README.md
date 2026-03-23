# append-note

**Category:** Web  
**Primary source:** challenge-author repo reference from the Discord export.

## Summary

The solve path noted in the export is an XSS on the `400` error page. The bug triggers when a URL fails the application’s violation check, but the error page reflects attacker-controlled data unsafely.

## Attack flow

1. Submit a crafted URL that intentionally fails validation.
2. The application returns a `400` error page.
3. The error page reflects untrusted input without proper escaping.
4. The reflected payload executes as JavaScript.

## Why it matters

Even though the “main” feature path blocks invalid input, the error-handling path becomes the real vulnerability surface.
