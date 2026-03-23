# blogler

**Category:** Web  
**Primary source:** krauq master writeup and a dedicated blogler writeup listed in the Discord export.  
**Other references:** frederik8921 blogler writeup; challenge-author repo for related web solves.

## Summary

The main bug was a YAML alias / anchor trick. A shared YAML reference let the attacker bypass path validation by mutating `display_name` after validation. That created a path traversal-style effect and exposed the flag path through profile customization logic.

## Key idea

- The application accepts YAML configuration.
- YAML anchors and aliases create shared references.
- Validation happened on one view of the data, but later mutations through an alias changed the effective value.
- By abusing that shared object behavior, the final path used by the app was different from the path that had been checked.

## Why it works

This is a classic “validate one representation, execute another” bug. The dangerous part is not plain YAML itself, but the fact that anchors / aliases can preserve object identity and make two fields point to the same underlying object.

## Notes

- This matches the Discord-export summary that “YAML anchor aliasing creates a shared reference that bypasses path validation via `display_name` mutation.”
- The exported notes also point to the full krauq LACTF page as the main source that covered most challenges.
