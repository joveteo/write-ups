# 02 — TrustVerify — Schnorr challenge-hash


> **Schnorr · Fiat–Shamir · `c = H(msg)` only · 60s alarm**
>
> The gateway asks for a Schnorr proof that you know `x` with `y = g^x`. The challenge hash never sees the commitment `R`, so the equation is linear in a public unknown. Pick `z`, solve for `R`. No discrete log required.

## 01 — Verdict: proof for the pasted session

Session `92f51fa07ca9fbdd` · action `grant_admin_access`. The algebra checks: `g^z ≡ R · y^c (mod p)`. The process dies after 60s and `y` is fresh each connection, so if the session is gone, re-forge from the new banner `y`.

```
R = 1227963619241035278176030041222256513157892273253876322602688403319168958877640475435704179
    2486231603773919868722753025304848088018775865703177158930935156297116490069928461633090137
    1379186659255135428332589951682788641408803900416520866196497165035334995721542044563367567
    483569390167051027123952689986798106

z = 1
```

## 02 — The scheme: Schnorr identification, almost

Safe-prime group, `p = 2q + 1`, `g = 2`, fresh secret `x`, public `y = g^x mod p`. An honest prover would send:

```
R = g^r
c = H(R || msg)     ← this is what Schnorr actually uses
z = r + c·x  (mod q)
check  g^z ≡ R · y^c  (mod p)
```

## 03 — The bug: the challenge is independent of `R`

Reading the verifier, the hash is **not** the one Schnorr specifies:

```python
c   = int(sha256(msg).hexdigest(), 16) % q
lhs = pow(g, z, p)
rhs = R * pow(y, c, p) % p
```

Fiat–Shamir only works if the challenge binds the commitment. Here `c` is a public function of `b'grant_admin_access'` **alone**. That is the entire opening. Anyone can rearrange the verification equation:

```
g^z ≡ R · y^c         (mod p)
R   ≡ g^z · y^{-c}    (mod p)
```

Choose `z = 1` (any unit in `1…q−1` works), invert `y^c` in `Z_p*`, done. You never learn `x`.

## 04 — The forge: one modular multiply

```bash
python3 solver/schnorr_forge.py --y <banner y>
```

The 60-second alarm is the only time pressure — the forge is a single modular inverse and multiply.

## 05 — This session: what to type at the prompts

```
R = <the long integer above>
z = 1
```

If `Proof verified!` does not appear, the session already rotated `y` — forge again from the new banner.

## 06 — Red herrings: what I did not attack

- **HMAC session token.** `generate_session_token` is only printed; verification never reads it.
- **The secret `x`.** 512-bit safe-prime DLOG is not the intended path and is not needed.
- **Order of `g`.** The comments say `g` has order `q`. For the pasted `y`, `y^q ≠ 1`, so that claim is shaky — but the forge still holds in `Z_p*` regardless.

## 07 — Checks: what I verified

- Recomputed `c` from `SHA-256(grant_admin_access) mod q`.
- For the banner `y`, confirmed `g^z ≡ R·y^c (mod p)` with `z = 1`.
- For a random honest `y = g^x`, a forged pair passes the same predicate as `verify()` in `temp.py`; `z+1` is rejected.

> Challenge: `challenge/temp.py` · Solver: `solver/schnorr_forge.py`
