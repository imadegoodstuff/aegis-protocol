//! Aegis Core: chain-agnostic deterministic post-quantum key management.
//!
//! From a single BIP-39 mnemonic:
//!   1. Derive a SPHINCS+-192s keypair for daily signing (STUB in v0.1)
//!   2. Derive an independent secp256k1 keypair for the ECDSA fallback / EOA
//!   3. Expose per-chain address derivation helpers (EVM address + account addr)
//!
//! The same mnemonic -> same keypairs -> deterministic addresses on every
//! supported chain. This library has NO network I/O and NO filesystem access.
//!
//! **IMPORTANT - v0.1 CRYPTO IS A STUB.**
//! The "SPHINCS+" keypair is currently derived as `sha256(seed || info)`
//! for pk and sk material, and "signatures" are `sha256(pk || digest)`.
//! This matches `evm/src/SphincsVerifierStub.sol` so the entire pipeline
//! (wallet → chain adapter → on-chain verify) can be driven end-to-end
//! in tests before real cryptography is wired in.
//!
//! Replacing with real FIPS 205 SLH-DSA is tracked in ADAPTERS.md.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use k256::{
    ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey, signature::Signer},
    SecretKey as EcdsaSecretKey,
};
use sha2::{Digest, Sha256, Sha512};
use sha3::Keccak256;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SPHINCS_SEED_INFO: &[u8] = b"aegis/sphincs+/192s/v1";
pub const ECDSA_SEED_INFO:   &[u8] = b"aegis/ecdsa/fallback/v1";

/// A full Aegis identity derived from a mnemonic.
#[derive(ZeroizeOnDrop)]
pub struct Identity {
    pub pq_pk: Vec<u8>,                        // 48 bytes (stub matches real -192s pk size)
    pub pq_sk: Vec<u8>,                        // 96 bytes (stub matches real -192s sk size)
    pub ecdsa_sk: [u8; 32],
    pub ecdsa_pk_uncompressed: [u8; 65],
}

#[derive(Debug)]
pub enum AegisError {
    BadMnemonic,
    KeyGen,
    Sign,
}

impl core::fmt::Display for AegisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AegisError {}

/// Derive the full Aegis identity from a BIP-39 mnemonic and optional passphrase.
pub fn identity_from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Identity, AegisError> {
    let m = Mnemonic::parse_in(Language::English, mnemonic).map_err(|_| AegisError::BadMnemonic)?;
    let seed = m.to_seed(passphrase);

    // --- SPHINCS+-192s (STUB) ---
    // Real: SPHINCS+ KeyGen from 96-byte seed. Stub: expand seed into 48B pk + 96B sk.
    let hk = Hkdf::<Sha512>::new(None, &seed);
    let mut sphincs_mat = [0u8; 48 + 96];
    hk.expand(SPHINCS_SEED_INFO, &mut sphincs_mat)
        .map_err(|_| AegisError::KeyGen)?;
    let pq_pk = sphincs_mat[..48].to_vec();
    let pq_sk = sphincs_mat[48..].to_vec();
    sphincs_mat.zeroize();

    // --- ECDSA fallback (REAL secp256k1) ---
    let mut ecdsa_seed = [0u8; 32];
    hk.expand(ECDSA_SEED_INFO, &mut ecdsa_seed)
        .map_err(|_| AegisError::KeyGen)?;
    let sk = EcdsaSecretKey::from_slice(&ecdsa_seed).map_err(|_| AegisError::KeyGen)?;
    let signing = EcdsaSigningKey::from(sk);
    let verifying = signing.verifying_key();
    let encoded_point = verifying.to_encoded_point(false);
    let pk_bytes = encoded_point.as_bytes();
    let mut ecdsa_pk = [0u8; 65];
    ecdsa_pk.copy_from_slice(pk_bytes);
    let mut ecdsa_sk_out = [0u8; 32];
    ecdsa_sk_out.copy_from_slice(&ecdsa_seed);
    ecdsa_seed.zeroize();

    Ok(Identity {
        pq_pk,
        pq_sk,
        ecdsa_sk: ecdsa_sk_out,
        ecdsa_pk_uncompressed: ecdsa_pk,
    })
}

/// STUB SPHINCS+ sign. Matches `evm/src/SphincsVerifierStub.sol`:
///     sig = sha256(pk || digest)   (32 bytes)
/// Replace with real FIPS 205 detached_sign in v0.2.
pub fn pq_sign(identity: &Identity, digest: &[u8; 32]) -> Result<Vec<u8>, AegisError> {
    Ok(stub_sig(&identity.pq_pk, digest).to_vec())
}

/// STUB SPHINCS+ verify.
pub fn pq_verify(pk: &[u8], digest: &[u8; 32], signature: &[u8]) -> bool {
    if signature.len() < 32 { return false }
    let expected = stub_sig(pk, digest);
    &signature[..32] == &expected[..]
}

/// Produces the stub "signature" compatible with the Solidity stub verifier.
pub fn stub_sig(pk: &[u8], digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::default();
    h.update(pk);
    h.update(digest);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// Sign with the ECDSA fallback key over the Ethereum-prefixed digest.
pub fn ecdsa_sign_eth(identity: &Identity, digest: &[u8; 32]) -> Result<[u8; 65], AegisError> {
    let signing = EcdsaSigningKey::from_slice(&identity.ecdsa_sk).map_err(|_| AegisError::Sign)?;
    let mut hasher = Keccak256::default();
    hasher.update(b"\x19Ethereum Signed Message:\n32");
    hasher.update(digest);
    let eth_digest = hasher.finalize();
    let sig: EcdsaSignature = signing.sign(&eth_digest);
    let (r, s) = sig.split_bytes();
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&r);
    out[32..64].copy_from_slice(&s);
    out[64] = 27;
    Ok(out)
}

// --- address derivation ---

pub fn evm_pq_pk_hash(pk: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::default();
    h.update(pk);
    let out = h.finalize();
    let mut arr = [0u8; 32]; arr.copy_from_slice(&out); arr
}

pub fn evm_ecdsa_address(identity: &Identity) -> [u8; 20] {
    let mut h = Keccak256::default();
    h.update(&identity.ecdsa_pk_uncompressed[1..]);
    let digest = h.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..]);
    addr
}

pub fn evm_account_address(
    factory: &[u8; 20],
    pq_pk: &[u8],
    guardian: &[u8; 20],
    ecdsa_owner: &[u8; 20],
    account_init_code_hash: &[u8; 32],
) -> [u8; 20] {
    let pq_pk_hash = evm_pq_pk_hash(pq_pk);
    let mut salt_h = Keccak256::default();
    let mut tag = [0u8; 32];
    tag[..8].copy_from_slice(b"AEGIS_V1");
    salt_h.update(tag);
    salt_h.update(pq_pk_hash);
    let mut g = [0u8; 32]; g[12..].copy_from_slice(guardian); salt_h.update(g);
    let mut o = [0u8; 32]; o[12..].copy_from_slice(ecdsa_owner); salt_h.update(o);
    let salt = salt_h.finalize();

    let mut final_h = Keccak256::default();
    final_h.update([0xffu8]);
    final_h.update(factory);
    final_h.update(&salt);
    final_h.update(account_init_code_hash);
    let out = final_h.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[12..]);
    addr
}

/// Per-chain address derivation stubs (see ADAPTERS.md for the full spec per chain).
pub mod addr {
    use super::*;

    /// SHA256(pq_pk) truncated to 20 bytes, bech32-encoded with the given prefix.
    /// Returns the raw 20-byte payload; callers encode with their bech32 lib.
    pub fn cosmos_payload(pq_pk: &[u8]) -> [u8; 20] {
        let mut h = Sha256::default();
        h.update(pq_pk);
        let out = h.finalize();
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&out[..20]);
        arr
    }

    /// Hex(sha256(pq_pk)) — matches NEAR implicit account id format.
    pub fn near_implicit_hex(pq_pk: &[u8]) -> String {
        let mut h = Sha256::default();
        h.update(pq_pk);
        let out = h.finalize();
        let mut s = String::with_capacity(64);
        use core::fmt::Write;
        for b in out { let _ = write!(&mut s, "{:02x}", b); }
        s
    }

    /// TRON raw 21-byte: 0x41 || keccak256(secp256k1_pk_uncompressed[1..])[12..].
    pub fn tron_raw(ecdsa_pk_uncompressed: &[u8; 65]) -> [u8; 21] {
        let mut h = Keccak256::default();
        h.update(&ecdsa_pk_uncompressed[1..]);
        let d = h.finalize();
        let mut out = [0u8; 21];
        out[0] = 0x41;
        out[1..].copy_from_slice(&d[12..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn mnemonic_is_deterministic() {
        let a = identity_from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let b = identity_from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_eq!(a.pq_pk, b.pq_pk);
        assert_eq!(a.ecdsa_sk, b.ecdsa_sk);
    }

    #[test]
    fn pq_sign_verify_roundtrip() {
        let id = identity_from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let digest = [7u8; 32];
        let sig = pq_sign(&id, &digest).unwrap();
        assert!(pq_verify(&id.pq_pk, &digest, &sig));
        let bad = [8u8; 32];
        assert!(!pq_verify(&id.pq_pk, &bad, &sig));
    }

    #[test]
    fn evm_ecdsa_address_is_20_bytes() {
        let id = identity_from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let addr = evm_ecdsa_address(&id);
        assert_eq!(addr.len(), 20);
    }

    #[test]
    fn addr_derivation_shapes() {
        let id = identity_from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_eq!(addr::cosmos_payload(&id.pq_pk).len(), 20);
        assert_eq!(addr::near_implicit_hex(&id.pq_pk).len(), 64);
        assert_eq!(addr::tron_raw(&id.ecdsa_pk_uncompressed)[0], 0x41);
    }
}
