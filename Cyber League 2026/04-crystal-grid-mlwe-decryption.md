# 04 — Crystal Grid — MLWE decryption


> **Module-LWE · n=8 · q=67 · k=2 · η=1 · 46 ciphertexts**
>
> The file is not an opaque "AI decrypt" blob. It is a Kyber-style public-key sample over a degree-8 cyclotomic ring with a secret small enough to list. I recovered that secret from the public key alone, then ran the decoder already in the file.

## 01 — Verdict: recovered plaintext

Unique ternary secret, 46-byte ASCII message. Search space `3^16 = 43,046,721` candidates; exactly one pair `(s, e)` satisfied the public-key equation. Both the helper decoder and the classical nearest-to-`q/2` rule agreed on every bit.

```
CYBERLEAGUE{cr7st4l_gr1d_m1n3r4l_d3c0d3d_e6a1}
```

| Metric | Value | Note |
|--------|-------|------|
| Hits | 1 | no second secret |
| Search | 8.6 s | batched NumPy enumeration |
| Decode gap | 13 / 20 | max \|c\| bit0 / min \|c\| bit1 vs 16 |

## 02 — The instance: what temp.py actually gives you

The docstring is the whole cryptosystem. Arithmetic lives in the polynomial ring

```
R_q = Z_67[x] / (x^8 + 1)
```

A public matrix `A` (2×2 polynomials) and a public vector `b` (2 polynomials) are the Module-LWE sample

```
b = A·s + e   (mod q),    |e_i| ≤ η = 1
```

```
A (rows × columns of R_q)
a00  33 21 30  2 55 48 30 52
a01  19 51 59 36 64 58 46 19
a10  28 49  6 44 52 18 62 10
a11   8 34  8 37 12 60  3 42

b (public LWE image)
b0   37 34  8 25 24 52 48 18
b1   47 52 18 36 66 42 45 31
```

Forty-six ciphertexts follow, each a pair `(u, v)` with `u ∈ R_q²` and `v ∈ R_q`. The file already implements ring multiplication (negacyclic convolution for `x⁸+1`), the module inner product, and a Kyber decoder that reads one byte from eight coefficients. The only thing it does *not* include is the secret `s` — which is the only missing input to

```
m = v − sᵀ·u   (mod q)
```

**So the whole job reduces to recovering a short module vector from `(A, b)`.** That is the decision point: everything else is already written.

## 03 — The scheme: Kyber CPA with the knobs turned to toy

Same skeleton as Kyber/ML-KEM, just with `n=8` and `q=67` instead of `n=256` and `q=3329`.

- **KeyGen.** Draw `s`, `e` with coefficients in `{-1,0,1}`. Publish `(A, b = As + e)`.
- **Encrypt.** A message bit is encoded as `0` or `⌊q/2⌋ = 33` and added into `v`. Fresh short noise hides the linear algebra. (We never needed the exact encryption formula.)
- **Decrypt.** `v − sᵀu` cancels the `A` terms and leaves the encoded bits plus a little noise.

The helper `decode_byte` marks bit `i` as 1 when the coefficient is farther from 0 than `q/4 = 16`:

```
bit_i = 1  iff  min(c_i, q − c_i) > q/4
```

Bits are packed least-significant first, eight bits to a byte, one byte per ciphertext. 46 blocks ⇒ 46 characters.

## 04 — Recovering s: enumerate the 16 ternary coefficients

With `η = 1` the secret is a vector in `{-1,0,1}^16`. That is 43,046,721 candidates — small enough to search, too large to type by hand. **I did not use lattice reduction; the instance is already in the brute-force regime.** That call is the crux: recognising the parameters are enumerable is worth more than any clever reduction.

Multiplication by a fixed polynomial in `Z[x]/(x⁸+1)` is an 8×8 *negacyclic* matrix: wrapping past degree 8 flips the sign, because `x⁸ ≡ −1`. Stacking the four blocks of `A` gives a 16×16 map

```
M_A · vec(s)  ≡  vec(b) − vec(e)   (mod 67)
```

For a candidate `s` I compute `ê = b − As` and accept it when every centred coefficient of `ê` has absolute value ≤ 1.

**Implementation decision for speed:** split `s = (s₀, s₁)`. There are `3⁸ = 6,561` choices for each half. I precomputed `A₀₁·s₁` and `A₁₁·s₁` for every `s₁`, then looped over `s₀` and checked both error polynomials with a batched NumPy matmul. The search finished in 8.61 seconds and returned a single hit. I let the loop run to the end; no second secret appeared.

```bash
python3 solver/recover.py
```

## 05 — The secret: the unique (s, e) pair

```
s (secret)
s0  -1  1  0  1 -1  0  1  0
s1   1 -1  0 -1 -1 -1  0  1

e (error)
e0   0 -1 -1  1 -1  1  1 -1
e1  -1  1  0  0 -1 -1  0 -1
```

Secret histogram: `−1 × 6, 0 × 5, +1 × 5`. Error histogram: `−1 × 8, 0 × 4, +1 × 4` — dense enough to look like a centered binomial sample, which is what Kyber would have drawn at `η = 1`.

Substituting these polynomials back into `As + e` recovers `b` exactly, coefficient for coefficient — not a near-miss, but the public-key equation over `R_q`.

## 06 — Decrypting: one inner product per ciphertext

For each of the 46 pairs I computed `m = v − sᵀu` in the ring and fed `m` to `decode_byte`. Worked example, ciphertext 00, which should be the letter `C`:

```
sᵀu       = (23, 33, 22, 66, 38, 37, 61, 15)
v         = (53,  0, 19,  8, 32, 37, 14, 12)
m         = (30, 34, 64,  9, 61,  0, 20, 64)   (mod 67)
centred m = (30, −33, −3,  9, −6,  0, 20, −3)
|c|       = (30,  33,  3,  9,  6,  0, 20,  3)
bits LSB  =   1    1   0   0   0   0   1   0
byte      = 1 + 2 + 64 = 67 = 0x43 = 'C'
```

`|c| > 16` decides a one; the rest are zeros. The same procedure on the remaining 45 blocks produces the full string.

Full byte table:

```
#  chr hex  bits(LSB→MSB)     #  chr hex  bits(LSB→MSB)
00  C  0x43 11000010          23  d  0x64 00100110
01  Y  0x59 10011010          24  _  0x5f 11111010
02  B  0x42 01000010          25  m  0x6d 10110110
03  E  0x45 10100010          26  1  0x31 10001100
04  R  0x52 01001010          27  n  0x6e 01110110
05  L  0x4c 00110010          28  3  0x33 11001100
06  E  0x45 10100010          29  r  0x72 01001110
07  A  0x41 10000010          30  4  0x34 00101100
08  G  0x47 11100010          31  l  0x6c 00110110
09  U  0x55 10101010          32  _  0x5f 11111010
10  E  0x45 10100010          33  d  0x64 00100110
11  {  0x7b 11011110          34  3  0x33 11001100
12  c  0x63 11000110          35  c  0x63 11000110
13  r  0x72 01001110          36  0  0x30 00001100
14  7  0x37 11101100          37  d  0x64 00100110
15  s  0x73 11001110          38  3  0x33 11001100
16  t  0x74 00101110          39  d  0x64 00100110
17  4  0x34 00101100          40  _  0x5f 11111010
18  l  0x6c 00110110          41  e  0x65 10100110
19  _  0x5f 11111010          42  6  0x36 01101100
20  g  0x67 11100110          43  a  0x61 10000110
21  r  0x72 01001110          44  1  0x31 10001100
22  1  0x31 10001100          45  }  0x7d 10111110
```

## 07 — Checks: what I verified before trusting the string

- **Public-key identity.** `As + e ≡ b (mod q)` holds for both module components. Tests in `solver/test_recover.py` recompute it from the challenge file.
- **Uniqueness in the ternary box.** The `3^16` enumeration produced one hit; a second `{-1,0,1}` secret would have printed, and did not.
- **Decode margin.** Every bit-0 coefficient had centred absolute value ≤ 13; every bit-1 coefficient had ≥ 20. The decision threshold is 16, so no coefficient sat on the fence.
- **Two decoders, one message.** The helper in `temp.py` and a "closer to 0 vs closer to q/2" rule produced the same 46 bytes.
- **The bytes are ASCII.** Printable characters, wrapping braces, a recognizable `CYBERLEAGUE` envelope.

## 08 — Why it worked: toy parameters, not a Kyber break

Real Kyber-512 uses `n = 256`, `q = 3329`, `k = 2`, and secrets from a centered binomial of width 2 or 3. The analogous search is then a 512-dimensional short-vector problem, not 16 ternary coefficients. **Nothing here transfers as an attack on ML-KEM.** What made *this* instance fall over:

1. The ring dimension is 8, so one polynomial is eight integers.
2. The module rank is 2, so the secret is only 16 integers.
3. `η = 1` forces those integers into a three-letter alphabet.
4. The public key is a noiseless linear image of `(s, e)` once you guess `s` — you do not need ciphertexts to find the key.

After that, decryption is exactly the function the challenge already documented. The "AI" part of the challenge is recognising the scheme, noticing the parameters are in the enumerable range, and not getting lost in the polynomial arithmetic.

> Challenge: `challenge/temp.py` · Solver: `solver/recover.py`
