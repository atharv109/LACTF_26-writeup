# slow-gold

**Category:** crypto

---

#### Description

The server (EMP-ZK arithmetic) commits to two secret length-10 vectors `vec1`, `vec2` over `F_p` where `p = 2^61-1`, and proves in zero-knowledge that they are a permutation by checking: `prod_i (vec1[i] + X) == prod_i (vec2[i] + X)` for verifier-chosen `X`.

After the proof, the verifier must submit the 10 elements of `vec1` (order doesn’t matter) to get the flag.

#### Solution

**Bug 1: Broken Batched Multiplication Check Only Checks One Gate**

In `attachments/dist/emp-zk/emp-zk/emp-zk-arith/ostriple.h`, the challenge modified the coefficient generation for the multiplication-gate batch check:

```cpp
uni_hash_coeff_gen(chi, seed, 1);
```

This should have been `task_n`, but with `1` only `chi[0]` is derived from the seed and the rest of the check is effectively not covered.

Worse, the loop bounds are broken:

```cpp
for (uint32_t i = start + task_n - 1, k = 0; i < start + task_n; ++i, ++k)
```

Because `i` is `uint32_t`, starting at `start + task_n - 1` combined with the `< start + task_n` condition makes the loop execute exactly once: it “checks” only the last multiplication gate in that batch.

So, per connection, the verifier learns data about exactly one multiplication gate.

**Bug 2: Verifier MAC Key `delta` Can Be Forced to 0**

EMP-ZK’s arithmetic backend uses an information-theoretic MAC: `mac = key + delta * value (mod p)`, where `delta` is sampled by the verifier.

Nothing prevents choosing `delta = 0`. With `delta=0`, `mac == key` and the broken one-gate check becomes a linear relation between the (unknown) gate inputs instead of a quadratic.

We patch the verifier to set `delta=0` and to record the one checked multiplication gate’s transcript `(seed, V, ka, kb, kc)` plus `delta` (sanity).

**What The One-Gate Leak Gives**

Let the checked multiplication gate have secret inputs `a`, `b`, output `c = a*b`. The verifier’s per-wire keys are `ka`, `kb`, `kc` and the prover sends `V`.

From the check derivation, with `delta=0`:

`kb*a + ka*b = (V/seed) + kc (mod p)`

In this circuit, the checked gate is the final multiplication gate for `vec2`:

`a = g(X) = prod_{i=0..8} (vec2[i] + X)`\
`b = last + X` where `last = vec2[9]`

So each connection at chosen `X` yields:

`kb*g(X) + ka*(last + X) = rhs (mod p)` where `rhs = (V/seed) + kc`.

**Solve With One 10x10 Linear System (10 Connections)**

Write `g(X)` as a monic degree-9 polynomial:

`g(X) = c0 + c1*X + ... + c8*X^8 + X^9`

Rearrange the leaked equation into a linear equation in the 10 unknowns `(c0..c8, last)`:

`sum_{j=0..8} (kb*X^j)*c_j + ka*last = rhs - ka*X - kb*X^9`

Collect this for 10 distinct `X` values (we used `X=0..9`), solve the resulting 10x10 system over `F_p` with Gaussian elimination to recover:

1. `last = vec2[9]`
2. the coefficients `c0..c8` of `g(X)`

**Factor To Recover The Other 9 Elements**

`g(X) = prod_{i=0..8} (vec2[i] + X)` so its roots are `X = -vec2[i]` for `i=0..8`.

Factor `g(X)` over `F_p` to get these linear factors, recover `vec2[i] = -root (mod p)`, and then submit the 10-element multiset `{vec2[0..9]}` as the guess for `vec1`.

This works because `vec1` is a permutation of `vec2`.

**Notes On Connectivity**

EMP `NetIO` uses `inet_addr()` and does not resolve DNS hostnames. Use an IP (for LACTF it was `34.169.138.235`) via `--host` or `SLOW_GOLD_HOST`.

**Final Flag**

`lactf{1_h0p3_y0u_l1v3_th1s_0ne_t0_th3_fullest}`

***

#### Code

Below is all code used for the solve (patches + solver).

**1) Leak Struct (new)**

File: `attachments/dist/emp-zk/emp-zk/emp-zk-arith/leak.h`

```cpp
#ifndef EMP_ZK_ARITH_LEAK_H__
#define EMP_ZK_ARITH_LEAK_H__
// Minimal transcript capture for CTF solving (verifier-side).
// This is intentionally tiny and only records the broken mult-check's single gate.

#include <cstdint>

namespace emp {

struct EmpZkAndGateLeak {
  bool have = false;
  uint64_t delta = 0;

  // The coefficient used in the (broken) linear combination.
  uint64_t seed = 0;

  // Prover-sent check sums (before verifier mutates V).
  uint64_t U = 0;
  uint64_t V = 0;

  // Verifier-side keys for the single checked multiplication gate.
  uint64_t ka = 0;
  uint64_t kb = 0;
  uint64_t kc = 0;

  // Index in the andgate buffers (useful for sanity).
  uint32_t gate_i = 0;
};

extern EmpZkAndGateLeak g_emp_zk_andgate_leak;

} // namespace emp

#endif
```

**2) Define Global (new)**

File: `attachments/dist/emp-zk/emp-zk/emp-zk-arith/emp-zk-arith.cpp`

```cpp
#include "emp-zk/emp-zk-arith/leak.h"
#include "emp-zk/emp-zk-arith/zk_fp_exec.h"

ZKFpExec *ZKFpExec::zk_exec = nullptr;

namespace emp {
EmpZkAndGateLeak g_emp_zk_andgate_leak;
} // namespace emp
```

**3) Patch EMP-ZK: Force `delta=0` and Capture One-Gate Transcript**

File: `attachments/dist/emp-zk/emp-zk/emp-zk-arith/ostriple.h`

```cpp
// (snippet of the relevant changes only)

void andgate_correctness_check_manage() {
  io->flush();

  if (party == BOB) {
    emp::g_emp_zk_andgate_leak = emp::EmpZkAndGateLeak{};
    emp::g_emp_zk_andgate_leak.delta = LOW64(delta);
  }

  ...

  if (party == ALICE) {
    uint64_t check_sum[2];
    check_sum[0] = U;
    check_sum[1] = V;
    io->send_data(check_sum, 2 * sizeof(uint64_t));
  } else {
    uint64_t check_sum[2];
    io->recv_data(check_sum, 2 * sizeof(uint64_t));

    // Capture prover-sent values before mutating V.
    emp::g_emp_zk_andgate_leak.U = check_sum[0];
    emp::g_emp_zk_andgate_leak.V = check_sum[1];

    check_sum[1] = mult_mod(check_sum[1], delta);
    check_sum[1] = add_mod(check_sum[1], W);
    if (check_sum[0] != check_sum[1])
      error("multiplication gates check fails");
  }
  io->flush();
}

void andgate_correctness_check(uint64_t *ret, int thr_idx, uint32_t start,
                               uint32_t task_n, block *chi_seed) {
  ...
  uint64_t *chi = new uint64_t[task_n];
  uint64_t seed = mod(LOW64(chi_seed[thr_idx]));
  uni_hash_coeff_gen(chi, seed, 1);  // challenge bug: only 1 coefficient

  if (party == ALICE) {
    ...
  } else {
    for (uint32_t i = start + task_n - 1, k = 0; i < start + task_n; ++i, ++k) {
      ka = LOW64(left[i]);
      kb = LOW64(right[i]);
      kc = LOW64(gateout[i]);

      // Record verifier-side view of the single checked multiplication gate.
      emp::g_emp_zk_andgate_leak.have = true;
      emp::g_emp_zk_andgate_leak.seed = seed;
      emp::g_emp_zk_andgate_leak.ka = ka;
      emp::g_emp_zk_andgate_leak.kb = kb;
      emp::g_emp_zk_andgate_leak.kc = kc;
      emp::g_emp_zk_andgate_leak.gate_i = i;

      B = add_mod(mult_mod(ka, kb), mult_mod(kc, delta));
      W = add_mod(W, mult_mod(B, chi[k]));
    }
    ret[thr_idx] = W;
  }

  delete[] chi;
}

void delta_gen() {
  // Verifier-side only. Challenge exploit forces delta=0, making mac==key.
  // This is not validated by the protocol implementation.
  delta = 0;
}
```

**4) Patched Client: JSON Transcript Dump + Non-interactive Flag Fetch**

File: `attachments/dist/emp-zk/test/arith/client.cpp`

```cpp
#include "emp-tool/emp-tool.h"
#include "emp-zk/emp-zk-arith/leak.h"
#include "emp-zk/emp-zk.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace emp;

static constexpr int kThreads = 1;

static void die_usage(const char *prog) {
  std::cerr << "usage: " << prog
            << " [--host HOST] [--port PORT] <X> dump|getflag [g0 g1 ... g9]\n";
  std::exit(2);
}

static uint64_t parse_u64(const char *s) {
  char *end = nullptr;
  errno = 0;
  unsigned long long v = std::strtoull(s, &end, 0);
  if (errno != 0 || end == s || (end && *end != '\0')) {
    std::cerr << "error: invalid u64: " << s << "\n";
    std::exit(2);
  }
  return static_cast<uint64_t>(v);
}

static int parse_i32(const char *s) {
  char *end = nullptr;
  errno = 0;
  long v = std::strtol(s, &end, 0);
  if (errno != 0 || end == s || (end && *end != '\0') || v < 0 ||
      v > 65535) {
    std::cerr << "error: invalid port: " << s << "\n";
    std::exit(2);
  }
  return static_cast<int>(v);
}

static void run_proof(BoolIO<NetIO> *ios[kThreads], int party, uint64_t X) {
  setup_zk_arith<BoolIO<NetIO>>(ios, kThreads, party);

  // Alice commits to two secret vectors; Bob uses dummy placeholders.
  std::vector<IntFp> array1;
  std::vector<IntFp> array2;
  array1.reserve(10);
  array2.reserve(10);
  for (int i = 0; i < 10; i++) {
    array1.emplace_back(0, ALICE);
    array2.emplace_back(0, ALICE);
  }

  // Challenge sends X over the arithmetic channel (not via stdio text).
  ZKFpExec::zk_exec->send_data(&X, sizeof(uint64_t));

  IntFp acc1 = IntFp(1, PUBLIC);
  IntFp acc2 = IntFp(1, PUBLIC);
  for (int i = 0; i < 10; i++) {
    acc1 = acc1 * (array1[i] + X);
    acc2 = acc2 * (array2[i] + X);
  }
  IntFp final_zero = acc1 + acc2.negate();
  batch_reveal_check_zero(&final_zero, 1);

  finalize_zk_arith<BoolIO<NetIO>>();
}

static void send_guesses(BoolIO<NetIO> *ios[kThreads],
                         const std::vector<uint64_t> &guesses) {
  if (guesses.size() != 10) {
    std::cerr << "internal error: expected 10 guesses\n";
    std::exit(2);
  }
  for (int i = 0; i < 10; i++) {
    uint64_t g = guesses[i];
    ios[0]->io->send_data(&g, sizeof(uint64_t));
  }
}

static void dump_json() {
  const auto &t = emp::g_emp_zk_andgate_leak;

  // One JSON object per line (consumed by solve.py).
  std::cout << "{";
  std::cout << "\"have\":" << (t.have ? "true" : "false");
  std::cout << ",\"delta\":" << t.delta;
  std::cout << ",\"seed\":" << t.seed;
  std::cout << ",\"U\":" << t.U;
  std::cout << ",\"V\":" << t.V;
  std::cout << ",\"ka\":" << t.ka;
  std::cout << ",\"kb\":" << t.kb;
  std::cout << ",\"kc\":" << t.kc;
  std::cout << ",\"gate_i\":" << t.gate_i;
  std::cout << "}\n";
  std::cout.flush();
}

int main(int argc, char **argv) {
  std::string host =
      std::getenv("SLOW_GOLD_HOST") ? std::getenv("SLOW_GOLD_HOST")
                                   : "chall.lac.tf";
  int port =
      std::getenv("SLOW_GOLD_PORT") ? parse_i32(std::getenv("SLOW_GOLD_PORT"))
                                   : 31183;

  int idx = 1;
  while (idx < argc) {
    if (std::strcmp(argv[idx], "--host") == 0) {
      if (idx + 1 >= argc)
        die_usage(argv[0]);
      host = argv[idx + 1];
      idx += 2;
      continue;
    }
    if (std::strcmp(argv[idx], "--port") == 0) {
      if (idx + 1 >= argc)
        die_usage(argv[0]);
      port = parse_i32(argv[idx + 1]);
      idx += 2;
      continue;
    }
    break;
  }

  if (idx + 2 > argc)
    die_usage(argv[0]);

  const uint64_t X = parse_u64(argv[idx]);
  const std::string mode = argv[idx + 1];
  idx += 2;

  std::vector<uint64_t> guesses;
  if (mode == "dump") {
    guesses.assign(10, 0);
  } else if (mode == "getflag") {
    if (idx + 10 != argc)
      die_usage(argv[0]);
    guesses.reserve(10);
    for (int i = 0; i < 10; i++)
      guesses.push_back(parse_u64(argv[idx + i]));
  } else {
    die_usage(argv[0]);
  }

  const int party = BOB;
  BoolIO<NetIO> *ios[kThreads];
  for (int i = 0; i < kThreads; ++i) {
    ios[i] = new BoolIO<NetIO>(new NetIO(host.c_str(), port), false);
  }

  run_proof(ios, party, X);
  send_guesses(ios, guesses);

  if (mode == "dump") {
    dump_json();
  } else {
    // Server sends exactly 46 bytes when guesses are correct.
    char flag[46];
    ios[0]->io->recv_data(flag, sizeof(flag));
    std::cout.write(flag, sizeof(flag));
    std::cout.flush();
  }

  for (int i = 0; i < kThreads; ++i) {
    delete ios[i]->io;
    delete ios[i];
  }
  return 0;
}
```

**5) Solver Script**

File: `solve.py`

```python
#!/usr/bin/env python3
import json
import os
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


P = 2305843009213693951  # 2^61 - 1
BIN = "attachments/dist/emp-zk/bin/test_arith_client"
## emp-tool's NetIO uses inet_addr() and does not resolve DNS names; use an IP.
HOST = os.environ.get("SLOW_GOLD_HOST", "34.169.138.235")
PORT = int(os.environ.get("SLOW_GOLD_PORT", "31183"))
LOCAL_CHALL_BIN = os.environ.get("SLOW_GOLD_LOCAL_CHALL_BIN")

## Keep concurrency low by default (remote services often rate-limit or queue).
WORKERS = int(os.environ.get("SLOW_GOLD_WORKERS", "1"))
DUMP_TIMEOUT_S = int(os.environ.get("SLOW_GOLD_DUMP_TIMEOUT_S", "1200"))
GETFLAG_TIMEOUT_S = int(os.environ.get("SLOW_GOLD_GETFLAG_TIMEOUT_S", "1200"))
RETRIES = int(os.environ.get("SLOW_GOLD_RETRIES", "3"))
DELAY_S = float(os.environ.get("SLOW_GOLD_DELAY_S", "0.25"))


def mod(x: int) -> int:
    return x % P


def inv(a: int) -> int:
    a %= P
    if a == 0:
        raise ZeroDivisionError("inv(0)")
    return pow(a, P - 2, P)


def run_dump(X: int) -> dict:
    # The binary prints exactly one JSON line in dump mode.
    last_err = None
    for attempt in range(1, RETRIES + 1):
        srv = None
        try:
            if LOCAL_CHALL_BIN:
                srv = subprocess.Popen(
                    [LOCAL_CHALL_BIN, str(PORT)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    text=False,
                )
                time.sleep(0.2)
            proc = subprocess.run(
                [BIN, "--host", HOST, "--port", str(PORT), str(X), "dump"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True,
                # The remote ZK proof is intentionally slow; keep this generous.
                timeout=DUMP_TIMEOUT_S,
            )
            lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
            for ln in reversed(lines):
                if ln.startswith("{") and ln.endswith("}"):
                    return json.loads(ln)
            raise RuntimeError(f"no JSON in output for X={X!r}: {proc.stdout!r}")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, json.JSONDecodeError, RuntimeError) as e:
            last_err = e
        finally:
            if srv is not None:
                try:
                    srv.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    srv.kill()
        # small backoff to avoid hammering
        time.sleep(0.25 * attempt)
    raise RuntimeError(f"run_dump failed for X={X} after {RETRIES} attempts: {last_err!r}")


def solve_linear_system_mod(A: list[list[int]], b: list[int]) -> list[int]:
    """Solve A x = b over F_p (Gaussian elimination)."""
    n = len(A)
    assert n > 0
    assert all(len(row) == n for row in A)
    assert len(b) == n

    M = [list(map(lambda x: x % P, row)) + [b[i] % P] for i, row in enumerate(A)]

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if M[row][col] % P != 0:
                pivot = row
                break
        if pivot is None:
            raise RuntimeError("singular system")
        if pivot != col:
            M[col], M[pivot] = M[pivot], M[col]

        inv_p = inv(M[col][col])
        for j in range(col, n + 1):
            M[col][j] = mod(M[col][j] * inv_p)

        for row in range(n):
            if row == col:
                continue
            factor = M[row][col] % P
            if factor == 0:
                continue
            for j in range(col, n + 1):
                M[row][j] = mod(M[row][j] - factor * M[col][j])

    return [M[i][n] % P for i in range(n)]


def factor_roots_mod_prime(coeffs: list[int]) -> list[int]:
    from sympy import Poly, symbols

    x = symbols("x")
    poly = Poly(sum(int(coeffs[i]) * x**i for i in range(len(coeffs))), x, modulus=P)
    _, facs = poly.factor_list()
    roots = []
    for fac, exp in facs:
        if exp != 1:
            # Shouldn't happen here (distinct elements), but handle anyway.
            pass
        if fac.degree() == 1:
            a, b = [int(c) for c in fac.all_coeffs()]  # a*x + b
            r = mod((-b) * inv(a))
            roots.append(r)
        else:
            raise RuntimeError(f"unexpected non-linear factor: {fac.as_expr()}")
    return roots


def main() -> int:
    # Unknowns: g(X)=c0+...+c8 X^8 + X^9 and last=vec2[9].
    # Each transcript at X gives:
    #   kb*g(X) + ka*(last + X) = (V/seed) + kc  (mod p)
    # which is linear in (c0..c8,last).
    xs = list(range(10))

    print(f"[+] fetching {len(xs)} transcripts with {WORKERS} workers...", flush=True)
    transcripts: dict[int, dict] = {}
    if WORKERS == 1:
        for X in xs:
            transcripts[X] = run_dump(X)
            print(f"[+] got transcript X={X}", flush=True)
            if DELAY_S:
                time.sleep(DELAY_S)
    else:
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futs = {ex.submit(run_dump, X): X for X in xs}
            for fut in as_completed(futs):
                X = futs[fut]
                transcripts[X] = fut.result()
                print(f"[+] got transcript X={X}", flush=True)
                if DELAY_S:
                    time.sleep(DELAY_S)

    A: list[list[int]] = []
    bvec: list[int] = []
    for X in xs:
        t = transcripts[X]
        if not t.get("have"):
            raise RuntimeError(f"missing leak (have=false) at X={X}")
        if int(t["delta"]) != 0:
            raise RuntimeError("expected delta=0 (patched client)")
        seed = int(t["seed"]) % P
        V = int(t["V"]) % P
        ka = int(t["ka"]) % P
        kb = int(t["kb"]) % P
        kc = int(t["kc"]) % P
        if seed == 0:
            raise RuntimeError("seed=0 (extremely unlikely), re-run")

        rhs = mod(mod(V * inv(seed)) + kc)  # (V/seed) + kc

        # kb*(sum_{j=0..8} c_j X^j + X^9) + ka*(last + X) = rhs
        # => sum_{j=0..8} (kb*X^j)*c_j + ka*last = rhs - ka*X - kb*X^9
        row = []
        xpow = 1
        for _j in range(9):
            row.append(mod(kb * xpow))
            xpow = mod(xpow * X)
        row.append(ka)  # last
        A.append(row)
        bvec.append(mod(rhs - ka * X - kb * xpow))  # xpow currently X^9

    sol = solve_linear_system_mod(A, bvec)
    coeffs = sol[:9] + [1]  # monic degree-9
    last_elem = sol[9]

    roots = factor_roots_mod_prime(coeffs)  # roots of g(x)==0 => x == -vec2[i] for i<9
    if len(roots) != 9:
        raise RuntimeError(f"expected 9 roots, got {len(roots)}")

    elems = [mod(-r) for r in roots] + [last_elem]
    elems = [int(e) for e in elems]
    if len(set(elems)) != 10:
        raise RuntimeError("elements not distinct; something went wrong")

    elems_sorted = sorted(elems)
    print("Recovered set (10 elements):")
    for e in elems_sorted:
        print(e)

    proc = subprocess.run(
        [BIN, "--host", HOST, "--port", str(PORT), "0", "getflag", *[str(e) for e in elems_sorted]],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=True,
        timeout=GETFLAG_TIMEOUT_S,
    )
    m = re.search(r"lactf\\{[^}]*\\}", proc.stdout)
    flag = m.group(0) if m else proc.stdout.strip()
    print("FLAG:", flag)
    if not (flag.startswith("lactf{") and flag.endswith("}")):
        raise RuntimeError("did not get a flag-shaped string")

    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```
