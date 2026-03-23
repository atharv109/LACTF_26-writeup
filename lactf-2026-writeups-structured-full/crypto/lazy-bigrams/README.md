# lazy-bigrams

**Category:** crypto

---

#### Description

We are given `attachments/chall.py` and a ciphertext `attachments/ct.txt`.

`chall.py` does:

1. `pt = phonetic_mapping(phonetic_mapping(flag))`
2. `ct = encryption(pt)`

`phonetic_mapping()` replaces each allowed character with its NATO-style word (plus words for `_{}0-9`), and if the resulting mapped string length is odd it appends a single padding letter `"X"`.

`encryption()` removes non-letters, groups the plaintext into disjoint 2-letter blocks (bigrams), and substitutes each plaintext bigram via a random permutation of all 26^2 possible bigrams. The ciphertext is emitted as 2-letter bigrams.

Flag format is `lactf{...}` and is all lowercase.

#### Solution

Model this as a substitution cipher over the set of ciphertext bigrams that appear.

Let each distinct ciphertext bigram be a “symbol”. Each symbol maps injectively to a plaintext bigram in `AA..ZZ` (0..675). Expanding those plaintext bigrams yields the full plaintext letter stream `s2`.

Key observation: `s2` is (almost always) a pure concatenation of NATO phonetic words for letters `A-Z`, because it is the output of the *second* `phonetic_mapping()` (the only possible exception is a single trailing padding letter `X`, which is appended to make the length even).

Constraints used:

1. **Injective mapping**: ciphertext symbol -> plaintext bigram (all-different).
2. **Known prefix crib**: because the flag starts with `lactf{`, the start of `s2 = phonetic_mapping(phonetic_mapping("lactf{"))` is fully known, which fixes many symbol->bigram assignments immediately.
3. **Regular-language constraint**: `s2` must be accepted by a DFA for “concatenation of NATO words” (or that plus a final padding `X`). This is enforced with OR-Tools CP-SAT `AddAutomaton`.

Once `s2` is recovered, decode:

* `s2` -> `s1` by tokenizing NATO words back into letters.
* `s1` -> `flag` by tokenizing the full `PHONETIC_MAP` words back into characters.

All code (solver + decoding) is below:

```python
#!/usr/bin/env python3
import re
from dataclasses import dataclass
from pathlib import Path

from ortools.sat.python import cp_model

HERE = Path(__file__).resolve().parent
CT_PATH = HERE / "attachments" / "ct.txt"

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPH)}
I2A = {i: c for i, c in enumerate(ALPH)}

# From attachments/chall.py
PHONETIC_MAP = {
    "A": "ALPHA",
    "B": "BRAVO",
    "C": "CHARLIE",
    "D": "DELTA",
    "E": "ECHO",
    "F": "FOXTROT",
    "G": "GOLF",
    "H": "HOTEL",
    "I": "INDIA",
    "J": "JULIETT",
    "K": "KILO",
    "L": "LIMA",
    "M": "MIKE",
    "N": "NOVEMBER",
    "O": "OSCAR",
    "P": "PAPA",
    "Q": "QUEBEC",
    "R": "ROMEO",
    "S": "SIERRA",
    "T": "TANGO",
    "U": "UNIFORM",
    "V": "VICTOR",
    "W": "WHISKEY",
    "X": "XRAY",
    "Y": "YANKEE",
    "Z": "ZULU",
    "_": "UNDERSCORE",
    "{": "OPENCURLYBRACE",
    "}": "CLOSECURLYBRACE",
    "0": "ZERO",
    "1": "ONE",
    "2": "TWO",
    "3": "THREE",
    "4": "FOUR",
    "5": "FIVE",
    "6": "SIX",
    "7": "SEVEN",
    "8": "EIGHT",
    "9": "NINE",
}

NATO_WORDS = [PHONETIC_MAP[chr(ord("A") + i)] for i in range(26)]


def clean_alpha(s: str) -> str:
    return "".join(ch for ch in s.upper() if ch in ALPH)


def phonetic_mapping_no_pad(ptext: str) -> str:
    """phonetic_mapping() but without appending trailing 'X' padding."""
    cleanptext = re.sub(r"[^a-zA-Z0-9_{}]", "", ptext).upper()
    return "".join(PHONETIC_MAP[c] for c in cleanptext)


def phonetic_mapping_letters_no_pad(ptext: str) -> str:
    """phonetic_mapping() but restricted to A-Z input and without trailing pad."""
    cleanptext = re.sub(r"[^A-Z]", "", ptext.upper())
    return "".join(PHONETIC_MAP[c] for c in cleanptext)


def s2_prefix_for_flag_prefix(flag_prefix: str) -> str:
    """Compute s2 = phonetic_mapping(phonetic_mapping(flag_prefix)) without pad."""
    s1 = phonetic_mapping_no_pad(flag_prefix)
    return phonetic_mapping_letters_no_pad(s1)


def build_constraints_from_prefix(ct_pairs: list[str], flag_prefix: str) -> tuple[dict[str, str], str]:
    s2_pref = clean_alpha(s2_prefix_for_flag_prefix(flag_prefix))
    pref_pairs = [s2_pref[i : i + 2] for i in range(0, (len(s2_pref) // 2) * 2, 2)]
    m: dict[str, str] = {}
    for i, pp in enumerate(pref_pairs):
        cp = ct_pairs[i]
        if cp in m and m[cp] != pp:
            raise RuntimeError(f"prefix constraint conflict at pos={i}: {cp} -> {m[cp]} vs {pp}")
        m[cp] = pp
    return m, s2_pref


class TrieNode:
    __slots__ = ("nxt", "term")

    def __init__(self):
        self.nxt: dict[int, int] = {}
        self.term: bool = False


@dataclass
class Automaton:
    initial_state: int
    final_states: list[int]
    transitions: list[tuple[int, int, int]]


def build_nato_automaton() -> Automaton:
    # Deterministic DFA: trie of words + "restart at root after finishing a word".
    nodes: list[TrieNode] = [TrieNode()]  # root=0
    for w in NATO_WORDS:
        cur = 0
        for ch in w:
            a = A2I[ch]
            nxt = nodes[cur].nxt.get(a)
            if nxt is None:
                nxt = len(nodes)
                nodes[cur].nxt[a] = nxt
                nodes.append(TrieNode())
            cur = nxt
        nodes[cur].term = True

    root = 0
    dead = len(nodes)
    transitions: list[tuple[int, int, int]] = []

    # Dead state loops.
    for a in range(26):
        transitions.append((dead, a, dead))

    # Trie transitions; from terminal states, missing edges behave like root edges.
    for s, node in enumerate(nodes):
        for a in range(26):
            if a in node.nxt:
                transitions.append((s, a, node.nxt[a]))
                continue
            if node.term and (a in nodes[root].nxt):
                transitions.append((s, a, nodes[root].nxt[a]))
            else:
                transitions.append((s, a, dead))

    final_states = [i for i, n in enumerate(nodes) if n.term]
    return Automaton(initial_state=root, final_states=final_states, transitions=transitions)


def decode_by_words(s: str, word_to_val: dict[str, str], *, allow_trailing_x: bool = True) -> str:
    # Greedy longest-match using a trie (word sets are prefix-free here).
    inv_trie: dict[str, dict] = {}
    for w, v in word_to_val.items():
        cur = inv_trie
        for ch in w:
            cur = cur.setdefault(ch, {})
        cur[""] = v  # terminal marker

    i = 0
    out: list[str] = []
    while i < len(s):
        cur = inv_trie
        j = i
        found = None
        found_j = None
        while j < len(s) and s[j] in cur:
            cur = cur[s[j]]
            j += 1
            if "" in cur:
                found = cur[""]
                found_j = j
        if found is None:
            if allow_trailing_x and (i == len(s) - 1) and (s[i] == "X"):
                break
            raise ValueError(f"decode failed at offset {i}: {s[i:i+60]}")
        out.append(found)
        i = found_j
    return "".join(out)


def solve(max_time: float = 180.0, workers: int = 8) -> str:
    ct = clean_alpha(CT_PATH.read_text())
    assert len(ct) % 2 == 0
    ct_pairs = [ct[i : i + 2] for i in range(0, len(ct), 2)]
    n_pairs = len(ct_pairs)

    uniq = sorted(set(ct_pairs))
    sym_id = {bg: i for i, bg in enumerate(uniq)}
    ct_syms = [sym_id[p] for p in ct_pairs]

    crib, s2_pref = build_constraints_from_prefix(ct_pairs, "lactf{")
    fixed: dict[int, int] = {}
    for c_bg, p_bg in crib.items():
        sid = sym_id[c_bg]
        pid = A2I[p_bg[0]] * 26 + A2I[p_bg[1]]
        fixed[sid] = pid

    aut = build_nato_automaton()

    def try_solve(*, pad_x: bool) -> str | None:
        model = cp_model.CpModel()

        # Cipher-symbol -> plaintext bigram id in [0, 675].
        bg = [model.NewIntVar(0, 26 * 26 - 1, f"bg_{s}") for s in range(len(uniq))]
        model.AddAllDifferent(bg)
        for sid, pid in fixed.items():
            model.Add(bg[sid] == pid)

        # Bigram -> letters.
        first_arr = [i // 26 for i in range(26 * 26)]
        second_arr = [i % 26 for i in range(26 * 26)]
        l0 = [model.NewIntVar(0, 25, f"l0_{s}") for s in range(len(uniq))]
        l1 = [model.NewIntVar(0, 25, f"l1_{s}") for s in range(len(uniq))]
        for s in range(len(uniq)):
            model.AddElement(bg[s], first_arr, l0[s])
            model.AddElement(bg[s], second_arr, l1[s])

        # Decrypted s2 letters.
        L = [model.NewIntVar(0, 25, f"L_{i}") for i in range(2 * n_pairs)]
        for k, sid in enumerate(ct_syms):
            model.Add(L[2 * k] == l0[sid])
            model.Add(L[2 * k + 1] == l1[sid])

        # Known s2 prefix from lactf{
        for i, ch in enumerate(s2_pref):
            model.Add(L[i] == A2I[ch])

        # Handle possible final padding 'X' by trying both cases.
        if pad_x:
            model.Add(L[-1] == A2I["X"])
            model.AddAutomaton(L[:-1], aut.initial_state, aut.final_states, aut.transitions)
        else:
            model.AddAutomaton(L, aut.initial_state, aut.final_states, aut.transitions)

        err = model.Validate()
        if err:
            raise RuntimeError(err)

        solver = cp_model.CpSolver()
        solver.parameters.max_time_in_seconds = max_time
        solver.parameters.num_search_workers = workers
        res = solver.Solve(model)
        if res not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
            return None

        return "".join(I2A[int(solver.Value(v))] for v in L)

    s2 = try_solve(pad_x=False) or try_solve(pad_x=True)
    if s2 is None:
        raise RuntimeError("no solution")

    # Decode s2 -> s1 letters (A-Z)
    inv_az = {PHONETIC_MAP[chr(ord("A") + i)]: chr(ord("A") + i) for i in range(26)}
    s1 = decode_by_words(s2, inv_az, allow_trailing_x=True)

    # Decode s1 -> flag characters
    inv_full = {v: k for k, v in PHONETIC_MAP.items()}
    flag = decode_by_words(s1, inv_full, allow_trailing_x=True).lower()
    return flag


if __name__ == "__main__":
    print(solve())
```

Running it prints the flag: `lactf{n0t_r34lly_4_b1gr4m_su8st1tu7ion_bu7_1_w1ll_tak3_1t_f0r_n0w}`
