//! Minimal WASM API surface for the Aegis wallet.
//!
//! Build with:
//!   wasm-pack build core --target web --out-dir ../wallet/src/aegis_core_pkg --features wasm
//!
//! Exposes:
//!   derive(mnemonic, passphrase) -> { pqPkHex, evmAddress, cosmosPayloadHex, nearImplicit, tronRawHex }

#![cfg(feature = "wasm")]

use wasm_bindgen::prelude::*;
use crate::{identity_from_mnemonic, evm_pq_pk_hash, evm_ecdsa_address, addr};

#[wasm_bindgen]
pub struct Derived {
    pq_pk_hex: String,
    pq_pk_hash_hex: String,
    evm_ecdsa_address_hex: String,
    cosmos_payload_hex: String,
    near_implicit_hex: String,
    tron_raw_hex: String,
}

#[wasm_bindgen]
impl Derived {
    #[wasm_bindgen(getter)] pub fn pq_pk_hex(&self)             -> String { self.pq_pk_hex.clone() }
    #[wasm_bindgen(getter)] pub fn pq_pk_hash_hex(&self)        -> String { self.pq_pk_hash_hex.clone() }
    #[wasm_bindgen(getter)] pub fn evm_ecdsa_address_hex(&self) -> String { self.evm_ecdsa_address_hex.clone() }
    #[wasm_bindgen(getter)] pub fn cosmos_payload_hex(&self)    -> String { self.cosmos_payload_hex.clone() }
    #[wasm_bindgen(getter)] pub fn near_implicit_hex(&self)     -> String { self.near_implicit_hex.clone() }
    #[wasm_bindgen(getter)] pub fn tron_raw_hex(&self)          -> String { self.tron_raw_hex.clone() }
}

fn hex_of(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    use core::fmt::Write;
    for byte in b { let _ = write!(&mut s, "{:02x}", byte); }
    s
}

#[wasm_bindgen]
pub fn derive(mnemonic: &str, passphrase: &str) -> Result<Derived, JsValue> {
    let id = identity_from_mnemonic(mnemonic, passphrase)
        .map_err(|e| JsValue::from_str(&format!("{e}")))?;
    let pk_hash = evm_pq_pk_hash(&id.pq_pk);
    let evm = evm_ecdsa_address(&id);
    let cosmos = addr::cosmos_payload(&id.pq_pk);
    let near = addr::near_implicit_hex(&id.pq_pk);
    let tron = addr::tron_raw(&id.ecdsa_pk_uncompressed);
    Ok(Derived {
        pq_pk_hex: hex_of(&id.pq_pk),
        pq_pk_hash_hex: hex_of(&pk_hash),
        evm_ecdsa_address_hex: hex_of(&evm),
        cosmos_payload_hex: hex_of(&cosmos),
        near_implicit_hex: near,
        tron_raw_hex: hex_of(&tron),
    })
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
