# ooo

**Category:** rev

---

#### Description

We are given `attachments/ooo.py`, which asks for a guess (flag) and validates it with a loop over adjacent character pairs. The core trick is that the script uses multiple different Unicode characters that look like `o` as distinct function names.

#### Solution

In `attachments/ooo.py`:

* `о(a, b)` returns `a + b`.
* `ὄ(a, b)` returns `a`.
* `ὂ(a, b)` returns `b`.

So the left side of the check is:

```python
о(ὄ(ό,ὃ),ὂ(ό,ὃ)) == ord(guess[i]) + ord(guess[i+1])
```

The right side indexes the list `ὁ` with:

```python
ơ(i, ȯ(օ(ό,ὃ),ό))
```

Using the function definitions:

* `օ(x, y) = x * y`
* `ȯ(x, y) = x % y`
* `ơ(x, y) = x ^ y` (XOR)

So:

```python
ȯ(օ(ό,ὃ),ό) = (ord(guess[i]) * ord(guess[i+1])) % ord(guess[i])
            = 0
```

because `a*b` is always divisible by `a` for nonzero `a` (and `ord(...)` is nonzero for normal characters).

Therefore the index simplifies to:

```python
ơ(i, 0) = i ^ 0 = i
```

So the loop condition becomes, for `i = 0..25`:

```python
ord(guess[i]) + ord(guess[i+1]) == H[i]
```

where `H` is the list `ὁ`. This gives a recurrence:

```python
c[i+1] = H[i] - c[i]
```

We also know the flag starts with `lactf{`, which determines `c[0] = ord('l')` and uniquely fixes the rest.

Solver (prints a valid flag; the checker only constrains the first 27 characters, so we append `}` to match the usual flag format):

```python
#!/usr/bin/env python3
H = [205, 196, 215, 218, 225, 226, 1189, 2045, 2372, 9300, 8304, 660, 8243, 16057, 16113, 16057, 16004, 16007, 16006, 8561, 805, 346, 195, 201, 154, 146, 223]

cs = [ord("l")]               # flag starts with lactf{
for i in range(len(H) - 1):   # checker iterates range(len(H)-1)
    cs.append(H[i] - cs[-1])

flag = "".join(map(chr, cs)) + "}"
print(flag)
```

Flag:

```
lactf{gоοօỏơóὀόὸὁὃὄὂȯöd_j0b}
```
