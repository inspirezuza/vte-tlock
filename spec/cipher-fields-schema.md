# VTE v0.2.1 Cipher Fields Schema

## 1. Rationale
`Proof_TLE` must bind to the *parsed* components of the ciphertext, not just the raw bytes. This ensures that the circuit verifies the mathematical relationship between the encryption components.

## 2. Ciphertext Format ID: `tlock_v1_age_pairing`
This format corresponds to `drand/tlock` v1.0.0+ using AGE for payload and pairing-based encryption for the header.

### 2.1 CipherFields Structure
```go
struct CipherFields {
    EphemeralPubKey [48]byte // G1 Point (Compressed)
    Mask            []byte   // Variable length, depending on scheme
    Tag             []byte   // Auth tag
    Ciphertext      []byte   // Encrypted payload (AGE)
}
```

### 2.2 Circuit Representation
To bind these fields in the circuit, they must be packed into field elements (limbs).

1.  **EphemeralPubKey**:
    -   Represents a G1 point on BLS12-381.
    -   Uncompressed in circuit: `(X, Y)`.
    -   Each coordinate is an element of Fp (381 bits).
    -   Packing: Split into 3 x 128-bit limbs + 1 remainder limb per coordinate?
    -   *Optimization*: If using emulated arithmetic, pass as CRT or native limbs defined by the emulation library.

2.  **Canonical Hash**:
    Since `CipherFields` can be large (ciphertext payload), we may perform a binding hash *outside* the expensive part of the circuit, or include the hash in the circuit.
    
    **Decision**: `Proof_TLE` takes `Hash(CipherFields)` as a public input IF the ciphertext is too large, BUT `Proof_TLE` needs to *verify* the decryption.
    
    **Refined Strategy**:
    -   `Proof_TLE` must operate on `EphemeralPubKey` and `Mask` directly to verify the timelock puzzle.
    -   The `One-Time Pad` / `AGE` payload part is symmetric. `Proof_TLE` must prove that `Ciphertext` decrypts to `r2` using the derived key.
    
    **Fields for Proof_TLE**:
    1.  `EphemeralPubKey`
    2.  `EncryptedKey` (or Mask)
    3.  `EncryptedPayload` (containing `r2`)

## 3. Serialization for Binding
For the `cipher_fields` hash or binding check:
`H(format_id || len(field1) || field1 || len(field2) || field2 ...)`

(Specific bit-packing details to be finalized in implementation phase M2).
