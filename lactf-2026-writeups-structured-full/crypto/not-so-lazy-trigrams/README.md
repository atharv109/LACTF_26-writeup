# not-so-lazy-trigrams

**Category:** crypto

---

#### Description

Finally got the energy to write a trigram substitution cipher. Surely three shuffles are better than one!

Files: `ct.txt`, `chall.py`

#### Solution

**Analysis of the cipher:**

The challenge implements a "trigram substitution cipher" using three independent alphabet shuffles (`shufflei`, `shufflej`, `shufflek`). The key insight is that despite appearing to operate on trigrams (3-letter blocks), the cipher actually decomposes into **three independent monoalphabetic substitution ciphers** based on character position mod 3:

* Position 0, 3, 6, ... → substituted by `shufflei`
* Position 1, 4, 7, ... → substituted by `shufflej`
* Position 2, 5, 8, ... → substituted by `shufflek`

This is because `sub_trigrams[a*676 + b*26 + c] = chr(shufflei[a]) + chr(shufflej[b]) + chr(shufflek[c])`, meaning each character in a trigram is substituted independently.

The `formatter` function removes spaces from the output but preserves all other punctuation from the original plaintext.

**Cracking approach:**

1. The ciphertext ends with a visible flag structure: `zjlel{heqmz_dgk_tevr_tk_vnnds_c_imcqaeyde_ug_byndu_e_jjaogy_rqqnisoqe_cwtnamd}`
2. We know `zjlel` → `lactf`, which gives us initial mappings across all three ciphers.
3. From the flag word length pattern `[5, 3, 4, 2, 5, 1, 9, 2, 5, 1, 6, 9, 7]` and the challenge theme ("not so lazy"), we hypothesize the flag content is: `still_too_lazy_to_write_a_plaintext_so_heres_a_random_wikipedia_article`
4. Verifying this hypothesis against the ciphertext shows **perfect consistency** across all three cipher mappings — no contradictions.
5. Partial decryption of the main text confirms it's a Wikipedia article about circular polarization, validating the hypothesis.

**Flag:** `lactf{still_too_lazy_to_write_a_plaintext_so_heres_a_random_wikipedia_article}`

**Solver code:**

```python
import re
from collections import Counter
import string
import random
import math

ct_raw = open('attachments/ct.txt').read()

# Extract all alpha characters
ct_alpha = re.sub(r'[^a-zA-Z]', '', ct_raw).lower()

# Flag content between { and }
flag_start_raw = ct_raw.find('zjlel{')
flag_content_raw = ct_raw[flag_start_raw+6:ct_raw.find('}')]

# Word lengths: [5, 3, 4, 2, 5, 1, 9, 2, 5, 1, 6, 9, 7]
# Hypothesis based on challenge theme and word pattern
hypothesis = "still_too_lazy_to_write_a_plaintext_so_heres_a_random_wikipedia_article"
hyp_alpha = re.sub(r'[^a-zA-Z]', '', hypothesis).lower()
flag_content_alpha = re.sub(r'[^a-zA-Z]', '', flag_content_raw).lower()

# Determine starting position in alpha stream for flag content
alpha_before = re.sub(r'[^a-zA-Z]', '', ct_raw[:flag_start_raw+6]).lower()
flag_alpha_start = len(alpha_before)

# Build and verify cipher mappings
mappings = [{}, {}, {}]
consistent = True
for i, (ct_c, pt_c) in enumerate(zip(flag_content_alpha, hyp_alpha)):
    cidx = (flag_alpha_start + i) % 3
    if ct_c in mappings[cidx]:
        if mappings[cidx][ct_c] != pt_c:
            print(f"INCONSISTENCY: cipher {cidx}, {ct_c} -> {mappings[cidx][ct_c]} vs {pt_c}")
            consistent = False
    else:
        mappings[cidx][ct_c] = pt_c

# Also add "lactf" -> "zjlel" mappings
lactf_start = len(re.sub(r'[^a-zA-Z]', '', ct_raw[:flag_start_raw]).lower())
for i, (ct_c, pt_c) in enumerate(zip('zjlel', 'lactf')):
    cidx = (lactf_start + i) % 3
    mappings[cidx][ct_c] = pt_c

print(f"All mappings consistent: {consistent}")
print(f"Flag: lactf{{{hypothesis}}}")
```
