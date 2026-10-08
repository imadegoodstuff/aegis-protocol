# Aegis

**全网首个 "一粒种子 → 所有链同一 PQ 智能账户" 的协议。**

一个 BIP-39 助记词，确定性派生出 SPHINCS+ 密钥，在 30+ 条 EVM 链同一地址 + Starknet / Solana / Cosmos 等非 EVM 链独立地址上，为你的资产提供 hash-only 的量子/AI 抗性签名层。

无桥。无池。无托管。无管理员。无团队钱包。无预售。

---

## CCHS — 协议核心（新）

**Chain-Cached Hypertree Signatures**：hash-only 的 PQ 账户授权。WOTS+ 两层超树（2^20 签名容量），上层证明每个子树只验一次、缓存到链上，之后的 1023 次签名只带底层。

| | Keygen | 签名（摊销） | 客户端状态 | 假设 |
|---|---|---|---|---|
| 平铺 XMSS | ~10^9 hash | 2.8 KB | 有 | SHA-256 |
| XMSS^MT | ~10^6 hash | 4.9 KB | 有 | SHA-256 |
| SPHINCS+ | ~10^6 hash | 7.8 KB | 无 | SHA-256 |
| **CCHS** | **~10^6 hash** | **2.5 KB** | **无（链持有）** | SHA-256 |

单 tx、无 commit-reveal。实测（EVM，SHA-256 预编译）：缓存路径 ~275K gas 全包、子树首签 ~580K，合约 4 750 B，无外部验证器。已在 EVM 中完成 TS 客户端 ↔ 合约互操作验证。规范 [`CCHS.spec.md`](CCHS.spec.md)，合约 `evm/src/AegisCCHS.sol`，客户端 `wallet/src/aegis/cchs.ts`，测试 `evm/test/AegisCCHS.t.sol`。

---

## 为什么存在

2026/10/7，Vitalik Buterin 和 Justin Drake 公开警告：AI 加速的数学进展可能在 2 年内严重削弱 lattice 密码学，并让 ECDSA 比预期更早被破解。Ethereum Lean Roadmap 的 PQ 基础设施目标是 2029。

**用户今天就需要一个 PQ 签名层**。Aegis 用已经成熟的 hash-based 签名 (SPHINCS+) 立刻把用户的账户签名提升到 Lean Ethereum 2029 才会提供的水平。

## 唯一的信任假设

1. SHA2 / SHA3 / BLAKE3 的抗碰撞
2. 用户自己的 guardian 地址没写错
3. 用户设备的 OPSEC

**没有**：可信启动、委员会、admin key、团队金库、预售、代币治理可以改核心账户逻辑。

## 用户 10 秒内可自己验证的 7 条承诺

1. **非托管**：资产在用户 `AegisAccount`，`balanceOf()` 在任何 explorer 查
2. **不可升级**：bytecode 无 proxy / 无 selfdestruct / 无 upgradeTo
3. **费率有硬顶**：`MAX_FEE_BPS = 2000` 是 `constant`，治理也改不了
4. **退出免费**：ECDSA fallback 不收任何协议费
5. **Guardian immutable**：部署时写死，任何人不可改
6. **部署 key 已烧**：发射当天公开直播烧毁
7. **前端去中心化**：IPFS CID + ENS contenthash

## 支持范围（所有适配器已 scaffold；SPHINCS+ verify 为 TODO）

| 链家族 | 骨架状态 | 地址派生 | 真实 verify 工时 | 目录 |
|---|---|---|---|---|
| EVM × 30+ (ETH / BSC / Polygon / Arb / Op / Base / Avalanche / Linea / Scroll / Mantle / Blast / Mode …) | ✅ 账户 + factory 跑通，测试通过 | CREATE2 同地址 | 2 w (fork C13) | `evm/` |
| Starknet | 🟡 constructor + storage | pedersen 独立地址 | 4 w | `cairo/` |
| TRON | 🟡 复用 EVM 字节码 | base58check (同 20 B) | 1 w (地址编码) | `tron/` |
| Solana | 🟡 Anchor 程序 + state machine | PDA(seed) 独立地址 | 4 w | `solana/` |
| Cosmos (CosmWasm) | 🟡 完整 state machine | bech32 独立地址 | 3 w | `cosmwasm/` |
| Aptos | 🟡 Move module | sha3-256 独立地址 | 6 w | `aptos/` |
| Sui | 🟡 Move module (shared object) | blake2b-256 独立地址 | 6 w | `sui/` |
| NEAR | 🟡 near-sdk 合约 | subaccount 独立地址 | 4 w | `near/` |
| TON | 🟡 FunC 合约 (完整 state) | hash(StateInit) 独立地址 | 6 w | `ton/` |
| Bitcoin | 📝 设计文档 only | — | 等 BIP-360 激活 | `bitcoin/` |

详见 [`ADAPTERS.md`](ADAPTERS.md) 的完整矩阵。

## 诚实限制

1. **各链共识层我们管不了**。Aegis 保证用户签名层的 PQ 性，不保证某条链本身不被攻陷。
2. **"全链"是 roadmap，不是 launch day 所有链都在**。见上表。
3. **Launch day 不提供隐私层**。可选的链下 note relay (Classic McEliece KEM) 作为后续模块。
4. **SPHINCS+ 签名验证 gas 在 L1 偏贵**。L2 可忽略；L1 建议日常走 L2，L1 仅存值。

## 架构

```
BIP-39 seed
    │
    ▼
AegisCore (Rust / WASM)
    │  ├─ SPHINCS+ keygen (hash-only)
    │  ├─ 消息签名 (chain-agnostic)
    │  └─ 各链地址派生
    │
    ├──→ EVM adapter (Solidity, 30+ chains, CREATE2 same addr)
    ├──→ Cairo adapter (Starknet)
    ├──→ SVM adapter (Solana Anchor program)
    ├──→ CosmWasm adapter (Cosmos SDK chains)
    ├──→ Move adapter (Aptos / Sui)
    └──→ 后续: FunC (TON), NEAR Rust, Taproot (Bitcoin)
          │
          ▼
    Unified Wallet UI (Tauri + React)
      - 一屏显示所有链 PQ 账户和余额
      - 一个种子控制所有链
      - 紧急退出按钮 (ECDSA fallback → 7d → guardian)
```

## 快速开始

```bash
# EVM 合约
cd evm
forge install
forge build
forge test

# 核心 Rust 库
cd core
cargo build --release
cargo test

# Starknet
cd cairo
scarb build
```

## 代码地图

```
aegis/
├── README.md                  (这里)
├── SPEC.md                    1 页技术规范
├── ADAPTERS.md                每条链适配器状态矩阵
├── core/                      Rust/WASM 核心 (BIP-39 → SPHINCS+ + ECDSA fallback)
├── evm/                       Foundry 工程 (智能账户 + 验证器 + 部署脚本)  ✅ 跑通
├── cairo/                     Starknet 账户 (Cairo 1)                      🟡
├── tron/                      TRON 适配 (复用 EVM 字节码)                   🟡
├── solana/                    Anchor 工作区 (SVM program)                   🟡
├── cosmwasm/                  CosmWasm 合约 (Osmosis/Neutron/Injective ...) 🟡
├── aptos/                     Move 模块                                    🟡
├── sui/                       Move 2024 (shared object)                   🟡
├── near/                      near-sdk Rust 合约                          🟡
├── ton/                       FunC 合约                                   🟡
├── bitcoin/                   设计文档 (等 BIP-360)                        📝
├── wallet/                    Vite + React UI (已部署到 fly)
└── docs/                      白皮书 / 威胁模型 / 用户自验指南
```

## 许可

MIT (核心库) + GPL-3.0 (钱包 UI)。合约部署后 immutable，所有权永久放弃。

## Status

Pre-launch · 单元测试覆盖中 · 未审计 · **不要用于主网**

当前阶段：工程骨架 + 规格冻结。审计 + testnet 后才会公开发射。
