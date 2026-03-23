# the-three-sat-problem

**Category:** rev

---

#### Description

The provided binary `attachments/three_sat_problem` asks for a solution to a 3-SAT instance. If the input satisfies the embedded constraints, it prints the flag.

#### Solution

1. Static reversing (`objdump -d`) shows:

* The program reads a line into a global buffer at `.bss` address `0x15060`.
* It requires the input length to be exactly `0x4ff` (1279) characters.
* Each character must be `'0'` or `'1'`.
* It calls a large, straight-line checker function at `0x1289` and requires it to return success (`AL==1`).
* It additionally requires input byte `0x2f2` to be `'1'` (the main function does `test byte [0x15352], 1`).
* On success it prints a 40-byte string built by selecting 320 bits from the 1279-bit input using the 320-entry dword table at `.rodata` `0x13080`.

2. Because the checker is straight-line (no conditional branches), we can solve it with symbolic execution:

* Create a blank call-state at `0x1289`.
* Make the 1279 input bytes symbolic, constrain each to `{0x30, 0x31}`.
* Constrain `input[0x2f2] == '1'`.
* Execute to a concrete return address.
* Constrain the return value to `AL==1`.
* Extract a model, then apply the output-bit mapping to recover the printed flag.

Running the script below produces the flag `lactf{is_the_three_body_problem_np_hard}` and also prints the full 1279-character certificate bitstring (second line) which can be fed back into the binary to verify.

```python
#!/usr/bin/env python3
import struct
import angr
import claripy

BIN = './attachments/three_sat_problem'
N = 0x4FF  # 1279
FUNC_OFF = 0x1289
RET_OFF = 0x12982  # one byte past end of .text, safe as concrete return target
INP_OFF = 0x15060
MAP_OFF = 0x13080
MAP_N = 0x140  # 320 bits


def load_map(p: angr.Project) -> list[int]:
    base = p.loader.main_object.mapped_base
    blob = p.loader.memory.load(base + MAP_OFF, 4 * MAP_N)
    return list(struct.unpack('<' + 'I' * MAP_N, blob))


def pack_flag(inp: bytes, mapping: list[int]) -> bytes:
    out = bytearray((MAP_N + 7) // 8)
    for i, idx in enumerate(mapping):
        bit = inp[idx] & 1
        out[i >> 3] |= (bit << (i & 7))
    return bytes(out)


def main():
    p = angr.Project(BIN, auto_load_libs=False)
    base = p.loader.main_object.mapped_base

    func = base + FUNC_OFF
    ret = base + RET_OFF
    inp_addr = base + INP_OFF

    state = p.factory.call_state(func, ret_addr=ret)

    # Symbolic input bytes in .bss where the program stored them.
    inp = [claripy.BVS(f'b{i}', 8) for i in range(N)]
    for i, b in enumerate(inp):
        state.memory.store(inp_addr + i, b)
        state.solver.add(claripy.Or(b == 0x30, b == 0x31))

    # Main also requires this byte's LSB set (i.e. '1')
    state.solver.add(inp[0x2F2] == 0x31)

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=ret)
    if not simgr.found:
        raise SystemExit('did not reach ret')

    st = simgr.found[0]

    # Checker returns in AL; require success.
    st.solver.add((st.regs.rax & 0xFF) == 1)

    if not st.solver.satisfiable():
        raise SystemExit('unsat')

    concrete = bytes(st.solver.eval(b, cast_to=int) for b in inp)

    mapping = load_map(p)
    flag_bytes = pack_flag(concrete, mapping)

    # The binary uses puts(), so flag should be a C-string. Strip trailing nulls.
    flag = flag_bytes.split(b'\x00', 1)[0]

    print(flag.decode('ascii', 'replace'))

    # Also print the required bitstring (so we can run the binary to cross-check).
    # This is large; keep it last.
    print(concrete.decode('ascii'))


if __name__ == '__main__':
    main()
```

***
