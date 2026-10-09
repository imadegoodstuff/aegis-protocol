//! Compute-unit measurement of the `aegis_account` program in the BanksClient
//! runtime (`solana-program-test`), replaying the life cycle of
//! `evm/test/fixtures/cchs-c-20.json`:
//!
//! `create` → `cache_subtree(0)` → `execute` × 3 (leaves 0, 1, 2) →
//! `execute` at leaf 5 (skip inside subtree 0) → `cache_subtree(1)` →
//! `execute` at leaf 1024 (first leaf of subtree 1) → `recover`.
//!
//! The test loads the built SBF program (`target/deploy/aegis_account.so`,
//! produced by `cargo build-sbf`; override the directory with `SBF_OUT_DIR`),
//! asserts that every instruction succeeds, prints a markdown table with the
//! compute units consumed and the transaction size per instruction, and
//! fails if any instruction consumes more than 1 400 000 CU (the
//! per-transaction maximum).
//!
//! ## Which fixture values are used as-is, and which are re-signed
//!
//! The fixture's `execute` and `recovery` digests bind the placeholder
//! account `0xcc…cc`, while the program hashes the real `CchsAccount` PDA
//! into the digest (`execute_digest`, `recover_digest` in `lib.rs`), so the
//! fixture's `l0.wots` and `recovery.wots` chain values cannot verify on
//! chain. The fixture ships its master seed (`master`, `skInfo` =
//! `cchs/sk/c`), which is exactly what makes the vectors reproducible: this
//! test derives the same WOTS+ secret keys (HKDF-SHA256 as in
//! `wallet/src/aegis/cchsCompact.ts`) and signs the on-chain digest with
//! them. Everything that does not depend on the message is taken from the
//! fixture unchanged — the roots (`root`, `recRoot`, `bottomRoot0`,
//! `bottomRoot1`, `newRoot`, `newRecRoot`), every authentication path
//! (`l0.auth`, `recovery.auth`) and both complete top-layer proofs
//! (`ops[0].l1`, `skip.ops[1].l1`, which sign bottom roots, not digests, and
//! are sent to `cache_subtree` byte for byte). Each re-signed layer is
//! checked against the fixture root with `cchs_core` before it is sent, so a
//! derivation mismatch fails here and not as an opaque on-chain error.
//!
//! Compute-unit cost depends on the message only through the number of chain
//! steps `Σ (255 − d_c)`; the table reports that number per instruction and a
//! linear extrapolation to the 6 375-step worst case.

use std::path::{Path, PathBuf};

use aegis_account::{execute_digest, recover_digest, SolSha256, ACCOUNT_SEED, CACHE_SEED, VAULT_SEED};
use cchs_core::compact::{
    bottom_root, digits, verify_layer, verify_top_layer, Hash, LayerSig, H, LEN, N, REC_H, W,
};
use cchs_core::{adrs, LAYER_BOTTOM, LAYER_RECOVERY, TYPE_CHAIN};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use solana_program_test::{tokio, ProgramTest, ProgramTestContext};
use solana_sdk::instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::transaction::Transaction;
use solana_sdk::{system_instruction, system_program};

const FIXTURE: &str = include_str!("../../../evm/test/fixtures/cchs-c-20.json");

/// Per-transaction compute limit; every instruction must stay below it.
const CU_LIMIT: u64 = 1_400_000;
/// Legacy packet size.
const PACKET: usize = 1232;
/// Chain steps of the worst-case message (all-zero digest, checksum 0x17E8).
const WORST_STEPS: u64 = 6375;

// ------------------------------------------------------------- fixture

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("fixture parses")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn b24(v: &Value) -> Hash {
    let bytes = hex_bytes(v.as_str().expect("hex string"));
    assert_eq!(bytes.len(), N);
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    out
}

fn hashes(v: &Value) -> Vec<Hash> {
    v.as_array().expect("array").iter().map(b24).collect()
}

fn wots_array(v: &[Hash]) -> [Hash; LEN] {
    let mut out = [[0u8; N]; LEN];
    out.copy_from_slice(v);
    out
}

// ------------------------------------------------------------- signing
//
// HKDF-SHA256 with a zero salt, info = "cchs/sk/c" ‖ layer ‖ treeIdx(8 BE) ‖
// leafIdx(4 BE) ‖ chainIdx, first block only: sk = HMAC(PRK, info ‖ 0x01)[0..24),
// PRK = HMAC(zero32, master). Byte-exact with `sk()` in cchsCompact.ts.

type HmacSha256 = Hmac<Sha256>;

struct SigningKey {
    prk: [u8; 32],
}

impl SigningKey {
    fn from_master(master: &[u8]) -> Self {
        let mut mac = HmacSha256::new_from_slice(&[0u8; 32]).unwrap();
        mac.update(master);
        let mut prk = [0u8; 32];
        prk.copy_from_slice(&mac.finalize().into_bytes());
        SigningKey { prk }
    }

    fn sk(&self, layer: u8, tree_idx: u64, leaf_idx: u32, chain_idx: u8) -> Hash {
        let mut mac = HmacSha256::new_from_slice(&self.prk).unwrap();
        mac.update(b"cchs/sk/c");
        mac.update(&[layer]);
        mac.update(&tree_idx.to_be_bytes());
        mac.update(&leaf_idx.to_be_bytes());
        mac.update(&[chain_idx]);
        mac.update(&[0x01]);
        let mut out = [0u8; N];
        out.copy_from_slice(&mac.finalize().into_bytes()[..N]);
        out
    }

    /// WOTS+ signature on `msg`: chain `c` advanced `d_c` steps from its secret key.
    fn wots_sign(&self, layer: u8, tree_idx: u64, leaf_idx: u32, msg: &Hash) -> [Hash; LEN] {
        let d = digits(msg);
        let mut out = [[0u8; N]; LEN];
        let mut a = adrs(layer, tree_idx, TYPE_CHAIN, leaf_idx, 0, 0);
        for c in 0..LEN {
            a[14] = c as u8;
            let mut x = self.sk(layer, tree_idx, leaf_idx, c as u8);
            for s in 0..d[c] {
                a[15] = s;
                let mut h = Sha256::new();
                h.update(a);
                h.update(x);
                x.copy_from_slice(&h.finalize()[..N]);
            }
            out[c] = x;
        }
        out
    }
}

/// Chain steps a verifier spends on `msg`: `Σ (255 − d_c)` over the 26 digits.
fn verify_steps(msg: &Hash) -> u64 {
    digits(msg).iter().map(|&d| (W - 1) as u64 - d as u64).sum()
}

// ------------------------------------------------------------ encoding

fn discriminator(name: &str) -> [u8; 8] {
    let d = Sha256::digest(format!("global:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

fn push_layer(data: &mut Vec<u8>, wots: &[Hash], auth: &[Hash]) {
    for w in wots {
        data.extend_from_slice(w);
    }
    for a in auth {
        data.extend_from_slice(a);
    }
}

/// `CchsAccount` as stored on chain (after the 8-byte discriminator).
#[derive(Debug)]
struct State {
    root: Hash,
    rec_root: Hash,
    epoch: u64,
    next_idx: u64,
    nonce: u64,
    rec_nonce: u64,
}

fn parse_state(data: &[u8]) -> State {
    assert!(data.len() >= 8 + 106, "account too short: {}", data.len());
    let h = |o: usize| {
        let mut x = [0u8; N];
        x.copy_from_slice(&data[o..o + N]);
        x
    };
    let u = |o: usize| u64::from_le_bytes(data[o..o + 8].try_into().unwrap());
    State { root: h(32), rec_root: h(56), epoch: u(80), next_idx: u(88), nonce: u(96), rec_nonce: u(104) }
}

// ------------------------------------------------------------- harness

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Sbf,
}

struct Row {
    name: String,
    steps: Option<u64>,
    cu: u64,
    ix_bytes: usize,
    tx_bytes: usize,
}

fn locate_so() -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for var in ["SBF_OUT_DIR", "BPF_OUT_DIR"] {
        if let Ok(d) = std::env::var(var) {
            dirs.push(PathBuf::from(d));
        }
    }
    dirs.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/deploy"));
    dirs.into_iter().map(|d| d.join("aegis_account.so")).find(|p| p.is_file())
}

struct Harness {
    ctx: ProgramTestContext,
    rows: Vec<Row>,
}

impl Harness {
    /// Send one instruction in its own transaction (payer = fee payer and
    /// only signer), record compute units and size, fail on any error.
    async fn send(&mut self, name: &str, steps: Option<u64>, ix: Instruction) {
        let payer = self.ctx.payer.insecure_clone();
        let blockhash = self.ctx.banks_client.get_latest_blockhash().await.unwrap();
        let ix_bytes = ix.data.len();
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);
        let tx_bytes = bincode::serialize(&tx).unwrap().len();
        let out = self.ctx.banks_client.process_transaction_with_metadata(tx).await.unwrap();
        let meta = out.metadata;
        if let Err(e) = out.result {
            if let Some(m) = &meta {
                for l in &m.log_messages {
                    eprintln!("  {l}");
                }
            }
            panic!("{name} failed: {e:?}");
        }
        let cu = meta.map(|m| m.compute_units_consumed).unwrap_or(0);
        self.rows.push(Row { name: name.to_string(), steps, cu, ix_bytes, tx_bytes });
    }

    async fn state(&mut self, account: &Pubkey) -> State {
        let acc = self.ctx.banks_client.get_account(*account).await.unwrap().expect("account exists");
        parse_state(&acc.data)
    }

    async fn lamports(&mut self, key: &Pubkey) -> u64 {
        self.ctx.banks_client.get_account(*key).await.unwrap().map(|a| a.lamports).unwrap_or(0)
    }
}

// ---------------------------------------------------------------- test

#[tokio::test]
async fn compute_units_per_instruction() {
    let fx = fixture();
    // Convert `Pubkey`s between the program crate (anchor-lang) and the test
    // runtime (solana-sdk) by bytes, so the test does not depend on the two
    // resolving to one `solana-pubkey` version.
    let program_id = Pubkey::new_from_array(aegis_account::ID.to_bytes());
    let pk18 = |k: &Pubkey| anchor_lang::prelude::Pubkey::new_from_array(k.to_bytes());

    let mode = match locate_so() {
        Some(so) => {
            // Point solana-program-test at the directory that holds the .so.
            std::env::set_var("SBF_OUT_DIR", so.parent().unwrap());
            Mode::Sbf
        }
        None => panic!("aegis_account.so not found: run `cargo build-sbf` first (or set SBF_OUT_DIR)"),
    };
    let mut pt = match mode {
        Mode::Sbf => ProgramTest::new("aegis_account", program_id, None),
    };
    // Raise the per-transaction budget so no SetComputeUnitLimit instruction
    // is needed: each transaction below carries exactly one instruction, so
    // `compute_units_consumed` is the cost of that instruction alone.
    pt.set_compute_max_units(CU_LIMIT);
    let ctx = pt.start_with_context().await;
    let mut h = Harness { ctx, rows: Vec::new() };
    let payer = h.ctx.payer.pubkey();

    // ---- fixture values
    let key = SigningKey::from_master(&hex_bytes(fx["master"].as_str().unwrap()));
    assert_eq!(fx["skInfo"].as_str().unwrap(), "cchs/sk/c");
    let root = b24(&fx["root"]);
    let rec_root = b24(&fx["recRoot"]);
    let bottom0 = b24(&fx["bottomRoot0"]);
    let bottom1 = b24(&fx["bottomRoot1"]);
    let new_root = b24(&fx["recovery"]["newRoot"]);
    let new_rec_root = b24(&fx["recovery"]["newRecRoot"]);

    // ---- PDAs
    let (account, _) = Pubkey::find_program_address(&[ACCOUNT_SEED, &root], &program_id);
    let (vault, _) = Pubkey::find_program_address(&[VAULT_SEED, account.as_ref()], &program_id);
    let cache_pda = |epoch: u64, tree_idx: u64| {
        Pubkey::find_program_address(
            &[CACHE_SEED, account.as_ref(), &epoch.to_le_bytes(), &tree_idx.to_le_bytes()],
            &program_id,
        )
        .0
    };

    // ---- create
    let mut data = discriminator("create").to_vec();
    data.extend_from_slice(&root);
    data.extend_from_slice(&rec_root);
    h.send(
        "create",
        None,
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account, false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        },
    )
    .await;
    let st = h.state(&account).await;
    assert_eq!((st.root, st.rec_root, st.epoch, st.next_idx, st.nonce), (root, rec_root, 0, 0, 0));

    // Fund the vault so the executed inner instruction (a SOL transfer from
    // the vault to the payer) has something to move. Not part of the table.
    {
        let blockhash = h.ctx.banks_client.get_latest_blockhash().await.unwrap();
        let fee_payer = h.ctx.payer.insecure_clone();
        let tx = Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&payer, &vault, 1_000_000_000)],
            Some(&payer),
            &[&fee_payer],
            blockhash,
        );
        h.ctx.banks_client.process_transaction(tx).await.unwrap();
    }

    // ---- cache_subtree: the fixture's top-layer proofs, byte for byte.
    let cache_subtree = |tree_idx: u64, l1: &Value, r0: Hash| {
        let wots = hashes(&l1["wots"]);
        let auth = hashes(&l1["auth"]);
        assert_eq!((wots.len(), auth.len()), (LEN, H));
        let mut sh = SolSha256::default();
        verify_top_layer(&mut sh, &root, tree_idx, &r0, LayerSig { wots: &wots_array(&wots), auth: &auth })
            .expect("fixture top layer reaches root");
        let mut data = discriminator("cache_subtree").to_vec();
        data.extend_from_slice(&tree_idx.to_le_bytes());
        push_layer(&mut data, &wots, &auth);
        data.extend_from_slice(&r0);
        Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new_readonly(account, false),
                AccountMeta::new(cache_pda(0, tree_idx), false),
                AccountMeta::new(payer, true),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        }
    };
    let steps_r0 = verify_steps(&bottom0);
    h.send("cache_subtree(0)", Some(steps_r0), cache_subtree(0, &fx["ops"][0]["l1"], bottom0)).await;

    // ---- execute: fixture leaf + auth path, chain values re-signed over the
    // on-chain digest; the inner instruction is a 12-byte SOL transfer
    // vault -> payer through the system program.
    let transfer_data = system_instruction::transfer(&vault, &payer, 1_000).data;
    assert_eq!(transfer_data.len(), 12);

    let execute = |op: &Value, expect_root: Hash, nonce: u64| {
        let idx = op["idx"].as_u64().unwrap();
        let auth = hashes(&op["l0"]["auth"]);
        assert_eq!(auth.len(), H);
        let mut sh = SolSha256::default();
        let msg = execute_digest(&mut sh, &pk18(&account), nonce, idx, &pk18(&system_program::id()), &transfer_data);
        let wots = key.wots_sign(LAYER_BOTTOM, idx >> H, (idx & 1023) as u32, &msg);
        let r0 = bottom_root(&mut sh, idx, &msg, LayerSig { wots: &wots, auth: &auth })
            .expect("bottom layer");
        assert_eq!(r0, expect_root, "re-signed leaf {idx} reaches the fixture bottom root");
        let mut data = discriminator("execute").to_vec();
        data.extend_from_slice(&idx.to_le_bytes());
        push_layer(&mut data, &wots, &auth);
        data.extend_from_slice(&(transfer_data.len() as u32).to_le_bytes());
        data.extend_from_slice(&transfer_data);
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(account, false),
                AccountMeta::new_readonly(cache_pda(0, idx >> H), false),
                AccountMeta::new_readonly(system_program::id(), false),
                // remaining accounts: the inner transfer's accounts
                AccountMeta::new(vault, false),
                AccountMeta::new(payer, true),
            ],
            data,
        };
        (format!("execute(idx={idx})"), verify_steps(&msg), ix)
    };

    let vault_before = h.lamports(&vault).await;
    let mut nonce = 0u64;
    for i in 0..3 {
        let (name, steps, ix) = execute(&fx["ops"][i], bottom0, nonce);
        h.send(&name, Some(steps), ix).await;
        nonce += 1;
        let st = h.state(&account).await;
        assert_eq!((st.next_idx, st.nonce), (i as u64 + 1, nonce));
    }

    // skip inside subtree 0: leaf 5
    let (name, steps, ix) = execute(&fx["skip"]["ops"][0], bottom0, nonce);
    h.send(&name, Some(steps), ix).await;
    nonce += 1;
    let st = h.state(&account).await;
    assert_eq!((st.next_idx, st.nonce), (6, nonce));

    // register subtree 1, then its first leaf
    let steps_r1 = verify_steps(&bottom1);
    h.send("cache_subtree(1)", Some(steps_r1), cache_subtree(1, &fx["skip"]["ops"][1]["l1"], bottom1)).await;
    let (name, steps, ix) = execute(&fx["skip"]["ops"][1], bottom1, nonce);
    h.send(&name, Some(steps), ix).await;
    nonce += 1;
    let st = h.state(&account).await;
    assert_eq!((st.next_idx, st.nonce, st.epoch), (1025, nonce, 0));
    assert_eq!(h.lamports(&vault).await, vault_before - 5 * 1_000, "five inner transfers landed");

    // ---- recover: fixture auth path, chain values re-signed over the digest
    {
        let rec = &fx["recovery"];
        assert_eq!(rec["recNonce"].as_u64().unwrap(), 0);
        let auth = hashes(&rec["auth"]);
        assert_eq!(auth.len(), REC_H);
        let mut sh = SolSha256::default();
        let msg = recover_digest(&mut sh, &pk18(&account), 0, &new_root, &new_rec_root);
        let wots = key.wots_sign(LAYER_RECOVERY, 0, 0, &msg);
        let r = verify_layer(&mut sh, LAYER_RECOVERY, 0, 0, &msg, &wots, &auth, REC_H);
        assert_eq!(r, rec_root, "re-signed recovery leaf reaches recRoot");
        let mut data = discriminator("recover").to_vec();
        data.extend_from_slice(&new_root);
        data.extend_from_slice(&new_rec_root);
        push_layer(&mut data, &wots, &auth);
        let ix = Instruction {
            program_id,
            accounts: vec![AccountMeta::new(account, false)],
            data,
        };
        h.send("recover", Some(verify_steps(&msg)), ix).await;
    }
    let st = h.state(&account).await;
    assert_eq!(
        (st.root, st.rec_root, st.epoch, st.next_idx, st.nonce, st.rec_nonce),
        (new_root, new_rec_root, 1, 0, nonce, 1)
    );

    // ---- report
    let table = render(&h.rows, mode);
    println!("\n{table}");
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).create(true).open(path) {
            let _ = writeln!(f, "### aegis_account compute units (BanksClient, SBF build)\n\n{table}");
        }
    }

    if mode == Mode::Sbf {
        for r in &h.rows {
            assert!(r.cu <= CU_LIMIT, "{} consumed {} CU > {}", r.name, r.cu, CU_LIMIT);
        }
    }
}

fn render(rows: &[Row], mode: Mode) -> String {
    let mut s = String::new();
    s.push_str("| Instruction | Chain steps | Compute units | Instruction data (B) | Transaction (B, legacy, 1 signature) |\n");
    s.push_str("|---|---:|---:|---:|---:|\n");
    for r in rows {
        let steps = r.steps.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        let fits = if r.tx_bytes <= PACKET { "" } else { " (exceeds 1 232)" };
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {}{} |\n",
            r.name, steps, r.cu, r.ix_bytes, r.tx_bytes, fits
        ));
    }
    match mode {
        Mode::Sbf => {
            // Least-squares fit CU = a + b * steps over the execute rows, then
            // extrapolate to the worst-case message.
            let ex: Vec<(f64, f64)> = rows
                .iter()
                .filter(|r| r.name.starts_with("execute"))
                .filter_map(|r| r.steps.map(|st| (st as f64, r.cu as f64)))
                .collect();
            if ex.len() >= 2 {
                let n = ex.len() as f64;
                let mx = ex.iter().map(|p| p.0).sum::<f64>() / n;
                let my = ex.iter().map(|p| p.1).sum::<f64>() / n;
                let sxx: f64 = ex.iter().map(|p| (p.0 - mx) * (p.0 - mx)).sum();
                let sxy: f64 = ex.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
                if sxx > 0.0 {
                    let b = sxy / sxx;
                    let a = my - b * mx;
                    let worst = a + b * WORST_STEPS as f64;
                    s.push_str(&format!(
                        "\n`execute` fit: CU ≈ {:.0} + {:.1} × steps; worst case ({} steps) ≈ {:.0} CU ({}).\n",
                        a,
                        b,
                        WORST_STEPS,
                        worst,
                        if worst <= CU_LIMIT as f64 { "within 1 400 000" } else { "EXCEEDS 1 400 000" }
                    ));
                }
            }
            s.push_str(
                "\nTransactions carry one instruction and no `SetComputeUnitLimit` (the budget is raised \
                 in the test runtime); a real transaction adds that instruction (+1 key, +8 data bytes).\n",
            );
        }
    }
    s
}
