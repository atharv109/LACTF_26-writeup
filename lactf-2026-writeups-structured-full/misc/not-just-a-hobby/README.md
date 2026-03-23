# not-just-a-hobby

**Category:** misc

---

#### Description

"It's not just a hobby!!!" - A single Verilog file `v.v` is provided.

#### Solution

The challenge provides a Verilog VGA module with 7-bit inputs (`input [6:0] x, input [6:0] y`) but comparisons against values that exceed the 7-bit range (0-127). The key insight is understanding Verilog bit-width semantics:

* `7'd588`: A 7-bit decimal literal — 588 gets truncated to `588 % 128 = 76`. This comparison **can** match.
* `588` (no width prefix): A 32-bit literal. Since `x` is only 7 bits (0-127), `x == 588` **never** matches.

A pixel coordinate is only "active" (drawn black) when **both** the x and y comparisons are satisfiable with 7-bit inputs. This means:

* Values with `7'd` prefix: truncate via `value % 128`, always reachable
* Bare values ≤ 127: directly reachable
* Bare values > 127: unreachable, the pixel comparison is dead code

Applying this filter and rendering the valid pixels on a 128x128 canvas reveals an image of the "Graphic Design Is My Passion" meme rendered in leet speak, with a stick figure holding an LACTF flag and a small creature.

The text reads across four lines: `lactf{graph1c_d3sign_` / `is_My_` / `PA55i0N!!1!}`

The leet speak substitutions are: `i→1` (graphic), `e→3` (design), `S→5` (PASSION), `O→0` (PASSION).

**Flag:** `lactf{graph1c_d3sign_is_My_PA55i0N!!1!}`

**Solver script:**

```python
import re
from PIL import Image

with open('attachments/v.v', 'r') as f:
    content = f.read()

# Parse all (x == VALUE && y == VALUE) coordinate pairs
pattern = r"\(x\s*==\s*(7'd)?(\d+)\s*&&\s*y\s*==\s*(7'd)?(\d+)\)"
matches = re.findall(pattern, content)

pixels = set()
for x_prefix, x_val, y_prefix, y_val in matches:
    x_val, y_val = int(x_val), int(y_val)

    # Apply 7-bit truncation for 7'd prefixed values
    if x_prefix == "7'd":
        x_actual = x_val % 128
    elif x_val <= 127:
        x_actual = x_val
    else:
        continue  # Unreachable with 7-bit input

    if y_prefix == "7'd":
        y_actual = y_val % 128
    elif y_val <= 127:
        y_actual = y_val
    else:
        continue  # Unreachable with 7-bit input

    pixels.add((x_actual, y_actual))

# Render 128x128 image
img = Image.new('RGB', (128, 128), 'white')
for x, y in pixels:
    img.putpixel((x, y), (0, 0, 0))

img_scaled = img.resize((512, 512), Image.NEAREST)
img_scaled.save('output.png')
print(f"Rendered {len(pixels)} pixels")
```

***
