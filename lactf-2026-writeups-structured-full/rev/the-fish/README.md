# the-fish

**Category:** rev

---

#### Description

We are given `fish.py`, which implements a 1D esolang interpreter and runs a single-line program (`fisherator`) over the input flag. The program ultimately executes instruction `n`, which pops an integer and checks it against a fixed huge constant; if equal, it prints “Indeed, that is the flag!”.

#### Solution

The input string is first converted to a stack of ASCII codes. The `fisherator` program does two main phases:

1. **Parse flag bytes into an integer `n` (big-endian base-256).**
   * The stack is reversed (`r`) so popping reads the flag left-to-right.
   * A loop performs: `n = n*256 + next_byte`.
2. **Run a Collatz-style process on `n` while building an accumulator `acc`.**
   * Initialize `acc = 1`.
   * Repeat until `n == 1`:
     * `acc = acc*2`
     * If `n` is odd: set `n = (3*n + 1)//2` and `acc = acc + 1`
     * Else: set `n = n//2`
   * Finally, the program checks `acc` against the embedded constant.

So the constant is exactly the final `acc`. Since the loop updates `acc` as `acc = (acc<<1) | (n&1)`, the **binary representation of `acc` encodes the parity bits of `n` along the path to 1** (with a leading `1`).

This is reversible from the end state `n = 1`:

* Extract bits from `acc` least-significant-bit first while `acc > 1` (these correspond to the parities in reverse order).
* Rebuild the previous `n`:
  * If the extracted bit is `0` (even-step), previous `n = 2*current`.
  * If the bit is `1` (odd-step), previous `n = (2*current - 1) / 3` (must divide evenly).

Once the starting `n` is recovered, convert it back to bytes (big-endian) to get the original flag string.

```python
#!/usr/bin/env python3

ACC = 996566347683429688961961964301023586804079510954147876054559647395459973491017596401595804524870382825132807985366740968983080828765835881807124832265927076916036640789039576345929756821059163439816195513160010797349073195590419779437823883987351911858848638715543148499560927646402894094060736432364692585851367946688748713386570173685483800217158511326927462877856683551550570195482724733002494766595319158951960049962201021071499099433062723722295346927562274516673373002429521459396451578444698733546474629616763677756873373867426542764435331574187942918914671163374771769499428478956051633984434410838284545788689925768605629646947266017951214152725326967051673704710610619169658404581055569343649552237459405389619878622595233883088117550243589990766295123312113223283666311520867475139053092710762637855713671921562262375388239616545168599659887895366565464743090393090917526710854631822434014024

def recover_flag_from_acc(acc: int) -> str:
    # Bits appended each iteration are the parity (n&1). Because the program does:
    # acc = acc*2 + (n&1), acc's LSB is the last parity bit.
    bits = []
    while acc > 1:
        bits.append(acc & 1)
        acc >>= 1

    # Reverse the Collatz-style step from terminal n=1 back to the initial n.
    n = 1
    for b in bits:  # already in reverse chronological order
        if b == 0:
            n *= 2
        else:
            t = 2 * n - 1
            if t % 3 != 0:
                raise ValueError("invalid bit sequence: (2*n-1) not divisible by 3")
            n = t // 3

    # Convert big-endian integer back to bytes (original flag chars).
    out = []
    while n > 0:
        out.append(n & 0xFF)
        n >>= 8
    out.reverse()
    return bytes(out).decode("utf-8")

if __name__ == "__main__":
    flag = recover_flag_from_acc(ACC)
    print(flag)
```

Recovered flag: `lactf{7h3r3_m4y_83_50m3_155u35_w17h_7h15_1f_7h3_c011472_c0nj3c7ur3_15_d15pr0v3n}`
