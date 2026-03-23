# grammar

**Category:** misc

---

#### Description

Inspired by CS 131 Programming Languages, I decided to make a context-free grammar in EBNF for my flag! But it looks like some squirrels have eaten away at the parse tree...

Provided files: `grammar-notes.txt` (EBNF grammar + notes about the tree) and `tree.png` (parse tree with opaque terminal boxes).

#### Solution

The challenge provides an EBNF grammar that generates flags and a parse tree image where the terminal characters (boxes at the bottom) are blacked out. The goal is to reconstruct the flag by reading the nonterminal chain depths from the tree.

**Grammar analysis:**

The grammar produces flags of the form `lactf{word1_word2_...}` where each word is composed of fragments. Each fragment is one of 5 types:

* `cd` (consonant + digit) - 2 characters
* `vc` (vowel + consonant) - 2 characters
* `vd` (vowel + digit) - 2 characters
* `c` (consonant) - 1 character
* `d` (digit) - 1 character

Each character type chains through numbered nonterminals, so the chain depth determines the specific character:

* Consonants: depth 1=f, 2=g, 3=p, 4=t, 5=r
* Vowels: depth 1=e, 2=o, 3=u
* Digits: depth 1=0, 2=1, 3=4, 4=5

**Tree analysis:**

The notes state colored circles represent fragment types with sequence `ABACDE BC EAEA` (3 words). The image is 1920x1080 with 28 terminal boxes at the bottom.

Step 1: Determine which fragment types are 1-char vs 2-char by checking if colored circle x-positions align with 1 or 2 terminal boxes:

* For 2-char fragments, the colored circle sits at the midpoint of its two terminal boxes
* Spatial analysis confirmed: **A, D = 1-char; B, C, E = 2-char**

This gives 6+9+1+4+1+6+1 = 28 terminal boxes, matching the image.

Step 2: Count black circle depths above each terminal box. The tree has 5 rows of black circles between the colored circles (y~~400) and terminal boxes (y~~1000). Circles stack from the bottom up: depth-1 chains have 1 circle at the bottom row, depth-5 chains fill all 5 rows.

Step 3: Determine fragment type assignments using depth constraints:

* **B** has a left branch with depth 5: only `cd` allows con(5)=r on the left (vowels max at depth 3) → **B = cd**
* **E** has a right branch with depth 5: only `vc` allows con(5)=r on the right → **E = vc**
* By elimination → **C = vd**
* **A = c** (consonant), **D = d** (digit) chosen because it produces readable text

Step 4: Decode each fragment:

| Fragment | Depths   | Type | Characters |
| -------- | -------- | ---- | ---------- |
| A1       | 3        | c    | p          |
| B1       | L:5, R:1 | cd   | r0         |
| A2       | 1        | c    | f          |
| C1       | L:1, R:4 | vd   | e5         |
| D1       | 4        | d    | 5          |
| E1       | L:2, R:5 | vc   | or         |
| B2       | L:3, R:3 | cd   | p4         |
| C2       | L:3, R:2 | vd   | u1         |
| E2       | L:1, R:2 | vc   | eg         |
| A3       | 2        | c    | g          |
| E3       | L:1, R:5 | vc   | er         |
| A4       | 4        | c    | t          |

Result: `pr0fe55or` \_ `p4u1` \_ `eggert` = "professor paul eggert" (the UCLA professor who teaches CS 131).

```python
from PIL import Image
import numpy as np

img = Image.open('attachments/tree.png')
arr = np.array(img)
gray = np.mean(arr[:,:,:3], axis=2)

# Circle row y-centers (row1=top/deepest chains, row5=bottom/all chains)
row_centers = [610, 690, 770, 845, 920]
threshold = 500
window_x, window_y = 15, 20

# Content terminal box x-centers and fragment assignments
# A,D = 1-char; B=cd, C=vd, E=vc
content_map = [
    ("A1", 474, "c"), ("B1_L", 538, "con"), ("B1_R", 603, "dig"),
    ("A2", 668, "c"), ("C1_L", 732, "vow"), ("C1_R", 797, "dig"),
    ("D1", 862, "d"), ("E1_L", 927, "vow"), ("E1_R", 991, "con"),
    ("B2_L", 1121, "con"), ("B2_R", 1186, "dig"),
    ("C2_L", 1250, "vow"), ("C2_R", 1315, "dig"),
    ("E2_L", 1444, "vow"), ("E2_R", 1509, "con"),
    ("A3", 1574, "c"), ("E3_L", 1639, "vow"), ("E3_R", 1703, "con"),
    ("A4", 1768, "c"),
]

char_maps = {
    'con': {1:'f', 2:'g', 3:'p', 4:'t', 5:'r'},
    'vow': {1:'e', 2:'o', 3:'u'},
    'dig': {1:'0', 2:'1', 3:'4', 4:'5'},
    'c':   {1:'f', 2:'g', 3:'p', 4:'t', 5:'r'},  # consonant
    'd':   {1:'0', 2:'1', 3:'4', 4:'5'},           # digit
}

flag_chars = []
for label, cx, ctype in content_map:
    depth = 0
    for i in range(4, -1, -1):  # Check rows bottom to top
        ry = row_centers[i]
        x_lo, x_hi = max(0, cx - window_x), min(1919, cx + window_x)
        y_lo, y_hi = max(0, ry - window_y), min(1079, ry + window_y)
        dark = np.sum(gray[y_lo:y_hi+1, x_lo:x_hi+1] < 50)
        if dark > threshold:
            depth += 1
        else:
            break
    flag_chars.append(char_maps[ctype][depth])

# Assemble: word1(9 chars) _ word2(4 chars) _ word3(6 chars)
w1 = ''.join(flag_chars[0:9])
w2 = ''.join(flag_chars[9:13])
w3 = ''.join(flag_chars[13:19])
print(f"lactf{{{w1}_{w2}_{w3}}}")
```

**Flag: `lactf{pr0fe55or_p4u1_eggert}`**
