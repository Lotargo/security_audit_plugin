# Cryptographic Primitives & Key Management Standards

| Operation | Approved Modern Primitives | Deprecated / Broken Primitives |
| :--- | :--- | :--- |
| **Symmetric Bulk Encryption** | AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 | DES, 3DES, RC4, Blowfish, AES-ECB, AES-CBC without HMAC |
| **Asymmetric Signatures** | Ed25519, ECDSA (P-256, P-384), RSA >= 2048-bit (PSS preferred) | RSA < 2048-bit, DSA, ECDSA with non-standard curves |
| **Cryptographic Hashing** | SHA-256, SHA-384, SHA-512, SHA3-256, BLAKE3 | MD4, MD5, SHA-1 |
| **Password Hashing** | Argon2id (memory-hard), scrypt, bcrypt (cost >= 12) | Plain SHA-256, MD5, unsalted hashes, single-iteration PBKDF2 |
| **CSPRNG** | `crypto.randomBytes()`, `secrets` (Python), `crypto/rand` (Go) | `Math.random()`, `rand()`, `java.util.Random` |
