# 03 — XZ ladder — twist oracle


> **Brier–Joye XZ ladder · quadratic twist · Pohlig–Hellman · AES-192-CBC**
>
> The challenge publishes `Q = kG` on a 256-bit Weierstrass curve whose order has a 125-bit prime factor, then encrypts the flag with the same 40-byte `k` as AES-192-CBC. Offline ECDLP is out. One static-DH query on the quadratic twist is not.

## 01 — Verdict: the flag

Same flag on every connection. `G` is hardcoded; `Q` and `ct` rotate with `randbytes(40)`.

```
CYBERLEAGUE{Cooke_c00k3d_iN_h1S_hymns}
```

Live service: `cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com:30009`

## 02 — The scheme: one buffer, two jobs

Short Weierstrass curve over the NUMS prime `p = 2^256 − 189`, scalar multiplication via the Brier–Joye XZ ladder (BJ02 §4). **The key observation that frames everything:** the 40-byte secret is *both* the elliptic scalar and the AES material.

```python
key = randbytes(40)          # 320-bit integer k
k   = int.from_bytes(key, "big")
Q   = mul(G, k)              # XZ output, not affine
ct  = AES-192-CBC(key[16:], IV=key[:16]).encrypt(pad(flag))
# then one query:
P   = mul((x, z), k)
```

`G = (4106702, 2026)` is just the affine point `x = 2027` written with `Z = 2026` (since `2027·2026 = 4106702`). Printing raw XZ leaks no extra discrete-log bits after reduction mod `p`; it does mean the service never checks that the queried point lies on `E`.

## 03 — Curve order: almost Pohlig–Hellman

PARI `ellap` (SEA, with seadata) gives the trace. `ellcard` on this build lied and returned 5, which violates Hasse; `nG = ∞` and cofactor checks confirm the SEA order. Both `E` and its quadratic twist have odd order.

`G` and `Q` both have full order `#E`. The 125-bit subgroup kills offline PH: embedding degree is `q−1`, the curve is not anomalous, CM discriminant is 258-bit, and `2^62` Pollard rho is not a CTF. **From `Q` alone you only get `k` modulo the 132-bit smooth cofactor** — not enough. That gap is what forces the oracle.

| Group | Factor | Bits | PH? |
|-------|--------|-----:|-----|
| `#E`  | 1 676 029 | 21 | yes |
| `#E`  | 466 284 593 | 29 | yes |
| `#E`  | 21 245 890 343 | 35 | yes |
| `#E`  | 223 956 225 540 659 | 48 | yes (~3 min) |
| `#E`  | 31…377 (prime) | 125 | no |
| `#E′` | 797 · 3803 · 12329 | 10–14 | yes |
| `#E′` | 256 731 925 819 | 38 | yes |
| `#E′` | 129 777 959 241 617 | 47 | yes |
| `#E′` | 253 284 721 942 639 | 48 | yes |
| `#E′` | 367…921 (prime) | 88 | skip |

## 04 — The bug: XZ arithmetic does not see `y`

Brier–Joye differential addition is x-only and uses the curve coefficients `a, b` that *also* define the unique quadratic twist. An x-coordinate whose `x³+ax+b` is a non-residue is a point of `E′`. The ladder still computes `kP`. **That is a static Diffie–Hellman oracle on a group whose smooth part is 168 bits.**

```
x0 = 4                         # rhs non-residue, full #E′ order
d  = x0³ + a·x0 + b            # twist by d
E′:  Y² = X³ + a·d²·X + b·d³
X(P) = d · x0                  # (d·x0, d²) lies on E′
send x=4, z=1
read  P = k·(4:1)
map   X(kP) = d · X/Z
```

Skip the 88-bit prime. Pohlig–Hellman on the remaining twist factors, plus the four smooth factors of `#E` from `Q = kG`, gives `k` modulo a 300-bit integer `M`. x-only arithmetic only determines `±k` in each group, so there are four sign combinations; then lift `k = k0 + t·M` through `t < 2^21` until AES-192-CBC decrypts a `CYBERLEAGUE{}` blob.

## 05 — The query: one shot, then disconnect

The service has no alarm in the source we were given, but the 48-bit discrete logs take minutes, so I grab the oracle output immediately and finish offline.

```bash
python3 solver/xz_ladder.py \
  --host cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com \
  --port 30009
```

```
>> 4
>> 1
```

Recovered 40-byte `k` (this session):

```
3b6829a30c1225aae6abf4e15fd7dad54b3f7a7edfe00d6cd3dfabbafe0204a25e97b46ce989a4df
```

`IV` = first 16 bytes, AES-192 key = last 24. A new connection mints a new `k`; rerun the solver rather than reusing this hex.

## 06 — Red herrings: what did not work

- **Offline 125-bit ECDLP.** MOV, Smart, GLV/CM, twist-without-oracle, projective `Z` as a division polynomial — none reduce that subgroup to CTF size.
- **Invalid-curve `a,b` swap.** The ladder bakes in the published `a, b`. You only get the one quadratic twist, not a family of smooth curves.
- **`random.randbytes`.** MT19937 is a bad CSPRNG, but CPython seeds from 256 bits of urandom. Forty output bytes do not clone the state.
- **AES as the oracle.** The known prefix `CYBERLEAGUE{` only becomes useful *after* `k` is reduced to a 21-bit lift.

## 07 — Checks: what I verified

- Python XZ ladder on `x=4` matches PARI scalar multiplication on the isomorphic twist `E′`.
- Cofactor clearing: `[n/f]G ≠ ∞` for every prime `f` dividing `#E`.
- Four 48-bit-class `elllog` calls plus CRT produced a 40-byte key that decrypts the live ciphertext to the flag above (residue 1, `t = 422690`).
- Unit tests cover twist mapping, banner parse, CRT sign combinations, and AES lifting without the long `elllog` run.

> Challenge: `challenge/xzladder.py` · Solver: `solver/xz_ladder.py`
