# 01 — Embassy terminal — truncated-nonce ECDSA


> **ECDSA · secp256k1 · 240-bit nonces · 25 operations**
>
> The service is an ECDSA oracle with a fresh secp256k1 key per session. I ignored the FIPS and certificate theatre, asked it to sign 20 cables, and recovered the ambassador key from the truncated nonces with a 22-dimensional LLL lattice.

## 01 — Verdict: the leak is 16 missing nonce bits

Submit the recovered `d`, get `ACCESS GRANTED`. The distribution copy redacts the flag behind `DYN_FLAG`; against the same terminal locally, the attack prints the env value after `ACCESS GRANTED`. LLL on 20 signatures took ~1.2 seconds.

```
ACCESS GRANTED. $DYN_FLAG
```

| Metric | Value | Note |
|--------|-------|------|
| Nonce | 240 bits | 30 bytes of urandom, then `% n` |
| Signatures | 20 | 18 already recovered in tests |
| LLL | ~1.2 s | 22 × 22 integer lattice, sympy |

## 02 — The terminal: a signing oracle, not a puzzle box

**First decision — read the protocol before touching crypto.** On connect the service prints an uncompressed secp256k1 public key, claims the session is authenticated, and accepts three commands for at most 25 turns (plus a 300-second alarm):

```
SIGN    →  provide cable hex, receive (r, s, h)
SUBMIT  →  provide ambassador_key_hex; if it equals d, print FLAG
EXIT    →  hang up
```

The private key is fresh every process:

```python
privkey = int.from_bytes(os.urandom(32), 'big') % (n - 2) + 1
pubkey  = privkey * G
```

Signing is textbook ECDSA. `h` is SHA-256 of the cable, reduced mod `n`, and the server even returns `h`, so I did not have to rehash. The only secret in the signature equation is the pair `(k, d)`:

```
s ≡ k⁻¹ (h + r·d)  (mod n)
k ≡ s⁻¹ (h + r·d)  (mod n)
```

The reasoning that set the whole direction: **if I learn `k`, `d` falls out directly. If I only learn that every `k` is *short*, then `d` becomes a hidden number and many signatures give a lattice.** So before attacking anything, I needed to know whether the nonces were short.

## 03 — Red herrings: what I did *not* attack

The file is padded with security-sounding machinery. I ruled each piece out deliberately:

- **Certificate chain.** `_TRUSTED_ROOTS` is initialised to the terminal's own random 32-byte "cert". The SHA-256 compare always succeeds and never runs again after bootstrap.
- **Constant-time compare.** Real, and irrelevant — there is no secret in those fingerprints.
- **hmac / signal / FIPS 140-3.** `hmac` is imported and unused. `security_level=128` is stored and unused. The alarm is a timeout, not a crypto primitive.
- **"Conditioning."** `condition_output` is just `int.from_bytes(..., 'big')`. No hash, no truncation function, no extractor.

The name `HASH_TRUNCATION = 16` is the whole bug — just not where the comment points. It only subtracts 16 from 256 to set `EFFECTIVE_BITS`.

## 04 — The nonce bug: `k` is uniformly 240-bit, not 256-bit

The RNG asks `os.urandom` for 240 bits (30 bytes), then reduces modulo the curve order. secp256k1's order is

```
n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE
    BAAEDCE6 AF48A03B BFD25E8C D0364141
  ≈ 2^256
```

`2^240` is `2^16` times smaller than `n`, so `k % n` never wraps. Every nonce is an integer in `(0, 2^240)` — the sixteen most significant bits of a 256-bit nonce are identically zero.

That realisation — 16 known MSBs per signature — is the pivot. It is the Howgrave-Graham–Smart / Nguyen–Shparlinski setting: ECDSA with known most-significant nonce bits. Breitner and Heninger measured it on secp256k1: 20 signatures with 242-bit nonces recovered the key with a 21-dimensional lattice, every time. Here the nonces are two bits shorter, and the protocol lets me take up to 24 signatures.

**Decision on sample count:** at 240 bits, roughly 16 signatures already over-determine a 256-bit secret. The protocol gives 25 operations, so I asked for **20** signatures and submitted on the 21st command — enough margin that one noisy LLL run is not fatal, with headroom to spare.

## 05 — Hidden number problem: each signature is one linear sample of `d`

Rearrange the signing equation:

```
k − (r·s⁻¹)·d − (h·s⁻¹)  ≡  0  (mod n)
k − t·d + a              ≡  0  (mod n)
```

with public `t = r/s` and `a = −h/s`, and unknown `k` known to be shorter than `2^240`. That is Boneh–Venkatesan HNP: a secret `α = d`, public multipliers `t_i`, and a short remainder.

**One small optimisation, taken deliberately:** I recentre each nonce as `k′ = k − 2^239` so the hidden remainder sits in `(−2^239, 2^239)` instead of `(0, 2^240)`. That is the "always-positive MSB" trick from the 2019 paper — one extra bit of bias for free.

## 06 — The lattice: SVP embedding, then LLL, then check against the public key

For `m` signatures I build an `(m+2)`-dimensional integer lattice (columns scaled so every coordinate of the target vector is ~`2^256`):

```
rows 0..m-1 :  n·2^16 on the diagonal
row  m      :  (t_i · 2^16)_i    ,  1,   0
row  m+1    :  (a_i · 2^16)_i    ,  0,   2^256

short vector ≈  (2^16·k′_i,  d,  ±2^256)
```

sympy's LLL reduces a 22-dimensional basis in about a second. I scan the reduced rows for a coordinate that is a plausible `d`, or reconstruct `d` from a recovered nonce via `d = (s·k − h)·r⁻¹`, and accept the first candidate whose `d·G` matches the printed public point. In every local trial with 18, 20, or 22 signatures, that candidate sat in **row 1** of the reduced basis.

```bash
python3 solver/recover.py
```

## 07 — Talking to it: 20 × SIGN, then SUBMIT

Each loop iteration is one command, so SIGN twenty times costs twenty of the twenty-five operations. Cables are `00`, `01`, … as hex. I parse `r=… s=… h=…`, check that `h` really is SHA-256 of the cable, reduce the lattice, then submit:

```
TERMINAL> SUBMIT
ambassador_key_hex: <d in hex>
ACCESS GRANTED. CYBERLEAGUE{…}
```

There is no remote host in the file itself. The solver spawns `challenge/temp.py` with `DYN_FLAG` set so the grant line is observable; point it at a live socket the same way — the banner, prompts, and math do not change.

## 08 — Checks: what I verified before calling it solved

- **Nonce length.** Direct instrumentation of the same RNG: every `k` had bit length ≤ 240, and `k < n` always, so the modular reduction is a no-op.
- **Public-key check.** The lattice candidate is accepted only when `d·G` equals the banner point — that rules out short-vector junk.
- **End-to-end grant.** `run_local_challenge` spawned the real terminal, collected 20 signatures over the real prompts, submitted `d`, and received `ACCESS GRANTED` plus the injected flag.
- **Margin on sample count.** 18 signatures already recovered `d` in repeated trials; I still collect 20 on the live path.
- **This is not a secp256k1 break.** RFC 6979 deterministic nonces, or 256 honest bits of entropy reduced with rejection sampling, kill the lattice. The terminal failed the nonce, not the curve.

> Challenge: `challenge/temp.py` · Solver: `solver/recover.py` · Tests: `python3 -m unittest solver.test_recover`
