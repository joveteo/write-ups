# 05 — ogic checker — NAND-SAT


> **logic · NAND-SAT · 78 chars · port 30010**
>
> The file is not encryption. It is a 245-gate NAND circuit over 65 bits that must accept a CYBERLEAGUE flag made only of L and l. I translated the assert into Z3, got a unique model, and sent it to the box on port 30010.

## 01 — Verdict: the flag is the satisfying assignment

A wrong string dumps an `AssertionError` traceback. The unique SAT model is accepted with no extra output — the input *is* the flag.

```
CYBERLEAGUE{llLlLllLLLLllLlllLLLLLlLlllLlLLllLLLLllLLLLLlLLLllLlLlllLLLLllLlL}
```

| Metric | Value | Note |
|--------|-------|------|
| Gates | 245 | `ogic` calls in the assert |
| Bits | 65 | indices 12–76, alphabet `Ll` |
| Models | 1 | Z3, then blocked → unsat |

## 02 — The checker: three lines, one circuit

The program reads a line and asserts a single nested call. There is no key, no ciphertext, no signing oracle. If the assert holds, the process exits 0. That is the whole challenge.

```python
ogic = lambda x, y=-1: not (x & (y if y > -1 else x))
lL = input(">> ")
assert ogic( ogic(...), ogic(format_checks) )
```

## 03 — What ogic is: NAND, and NOT when used unary

**The first thing to pin down is what the lambda actually computes.** For a boolean second argument, `y > -1` is always true (`False` is `0`). So binary `ogic` is NAND:

```
ogic(x, y) = not (x & y) = NAND(x, y)
ogic(x)    = not (x & x) = NOT(x)
```

NAND is functionally complete, so the giant nest can encode any boolean constraint on the character tests `lL[i]=='l'`. I did not simplify it by hand — I let a SAT solver eat the circuit.

## 04 — Flag format: `CYBERLEAGUE{`, then 65 letters, then `}`

The last conjunct (still written with `ogic`) forces:

- length 78
- prefix `CYBERLEAGUE{` (12 chars)
- suffix `}`
- every inner character in `Ll`

That leaves 65 free bits, one per index 12…76. Every one of those indices appears as a leaf. Brute force is `2^65`; SAT is instant.

65 inner bits, indices 12–76 (`29 l · 36 L`):

```
l l L l L l l L L L L l l
L l l l L L L L L l L l l
l L l L L l l L L L L l l
L L L L L l L L L l l L l
L l l l L L L L l l L l L
```

## 05 — SAT: parse the AST, assert it, read the model

I parsed the assert with Python's `ast` module, mapped each `lL[i]=='l'` to a Z3 Bool, mapped `ogic` to `Not`/`And`, and assumed the format predicates (we only search inside the 65-bit box). Z3 returned one model. **Blocking it made the solver unsat, so the assignment is unique** — that uniqueness check is what lets me trust the string without a remote round-trip.

```bash
python3 solver/nand_sat.py
python3 solver/nand_sat.py --remote
```

## 06 — The remote: port 30010 is the same checker

`nc …amazonaws.com 30010` prints `>>` and runs `/app/logic.py`. A bad string raises `AssertionError`; the SAT string does not. There is no second envelope — the L/l payload is the CYBERLEAGUE flag.

## 07 — Checks: what I verified

- **Local eval.** `exec` the original `ogic` lambda, `eval` the assert body on the model — `True`. Flip the inner string to all `L` — `False`.
- **Uniqueness.** One SAT model; the blocking clause is unsat.
- **Remote differential.** Wrong flag → traceback from `/app/logic.py`. This flag → prompt only, exit clean.

> Challenge: `challenge/temp.py` · Solver: `solver/nand_sat.py`
