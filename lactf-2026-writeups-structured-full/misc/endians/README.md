# endians

**Category:** misc

---

#### Description

I was reading about Unicode character encodings until one day, my flag turned into Japanese! Does little-endian mean the little byte's at the end or that the characters start with the little byte?

Files: `chall.txt`, `gen.py`

#### Solution

The provided `attachments/gen.py` shows the flag was turned into "Japanese" by encoding/decoding with opposite UTF-16 endianness:

```python
text = "lactf{REDACTED}"
endian = text.encode(encoding="???").decode(encoding="???")
with open("chall.txt", "wb") as file:
    file.write(endian.encode())
```

In `attachments/chall.txt`, each displayed CJK character is actually a single Unicode code point whose bytes look like `0xXX 0x00` (ASCII byte as the high byte, `0x00` as the low byte). That happens when UTF-16-LE bytes like `6c 00` (for `'l'`) are mis-decoded as UTF-16-BE, producing `U+6C00` (`氀`).

So the forward transform is:

* `encode("utf-16-le")` then `decode("utf-16-be")`

To reverse it, do the opposite:

* `encode("utf-16-be")` then `decode("utf-16-le")`

```python
from pathlib import Path

data = Path("attachments/chall.txt").read_text(encoding="utf-8").strip()
print(data.encode("utf-16-be").decode("utf-16-le"))
```

Flag: `lactf{1_sur3_h0pe_th1s_d0es_n0t_g3t_l0st_1n_translati0n!}`
