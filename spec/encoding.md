# VTE v0.2.1 Encoding Specification

## 1. Limb Packing
To ensure consistency between Go, TypeScript, and Circuit implementations (BN254), we define a strict packing for 32-byte values into field elements.

-   **Limb Size**: 128 bits.
-   **Structure**: A 32-byte value `X` is split into two limbs, `X_hi` and `X_lo`.
-   **Endianness**:
    -   Wire format: Big-Endian.
    -   Limb interpretation: Big-Endian of the 16-byte slice.
-   **Mapping**:
    -   `X[0..16]` -> `X_hi`
    -   `X[16..32]` -> `X_lo`

**Constraint**: In the circuit, every limb MUST be constrained to `< 2^128`.

## 2. Commitment (`C`)
The commitment `C` binds the secret `r2` to the context `ctx_hash`.

**Formula**:
```
C_field = Poseidon(DST_hi, DST_lo, r2_hi, r2_lo, ctx_hi, ctx_lo)
```

-   **DST**: `VTE_TLOCK_v0.2.1` (UTF-8 bytes).
    -   Padded to 32 bytes with zeros (right-padding).
    -   Then packed into `DST_hi`, `DST_lo`.
-   **r2**: 32-byte scalar candidate.
-   **ctx_hash**: `BLAKE3(SessionID || RefundTxHash)` (32 bytes).

**Wire Encoding**:
`C` (32 bytes) is the canonical byte encoding of `C_field`.

## 3. Inputs for Proofs

### Proof_SECP Public Inputs
1.  `ctx_hash` (2 limbs)
2.  `C` (1 field element or 2 limbs, implementation dependent, preferably field element if native)
3.  `R2.x` (2 limbs)
4.  `R2.y` (2 limbs)

### Proof_TLE Public Inputs
1.  `round` (field element)
2.  `chainhash` (packed to limbs)
3.  `ciphertext_format_id` (hash or encoding)
4.  `ctx_hash` (2 limbs)
5.  `C` (field element)
6.  `cipher_fields` (derived limbs)

## 4. Context Hash
`ctx_hash` is computed off-circuit using **BLAKE3**.
`ctx_hash = BLAKE3(SessionID || RefundTxHash)`
