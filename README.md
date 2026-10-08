# Aegis

**全网首个 "一粒种子 → 所有链同一 PQ 智能账户" 的协议。**

一个 BIP-39 助记词，确定性派生出 SPHINCS+ 密钥，在 30+ 条 EVM 链同一地址 + Starknet / Solana / Cosmos 等非 EVM 链独立地址上，为你的资产提供 hash-only 的量子/AI 抗性签名层。

无桥。无池。无托管。无管理员。无团队钱包。无预售。

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

## 支持范围（launch day 真实版本）

| 链家族 | 覆盖 | 时间 |
|---|---|---|
| EVM (ETH / BSC / Polygon / Arb / Op / Base / Avalanche / Linea / Scroll / Mantle / Blast / Mode 等 30+) | ✅ Launch day | 同地址 (CREATE2) |
| Starknet | ✅ Launch day | 独立地址 (同种子派生) |
| Solana | 🔜 Launch + 3 月 | 独立地址 |
| Cosmos (CosmWasm) | 🔜 Launch + 3 月 | 独立地址 |
| TRON | 🔜 Launch + 2 月 | 同 EVM 地址 |
| Aptos / Sui | 🔜 Launch + 6 月 | 独立地址 |
| NEAR | 🔜 Launch + 4 月 | 独立地址 |
| TON | 🔜 Launch + 6 月 | 独立地址 |
| Bitcoin | ⏸ 等 BIP-360 激活 | - |

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
├── core/                      Rust/WASM 核心 (SPHINCS+ 密钥派生 + 签名)
├── evm/                       Foundry 工程 (智能账户 + 验证器 + 部署脚本)
├── cairo/                     Starknet 账户 (Cairo 1)
├── wallet/                    Tauri + React 钱包
└── docs/                      白皮书 / 威胁模型 / 用户自验指南
```

## 许可

MIT (核心库) + GPL-3.0 (钱包 UI)。合约部署后 immutable，所有权永久放弃。

## Status

Pre-launch · 单元测试覆盖中 · 未审计 · **不要用于主网**

当前阶段：工程骨架 + 规格冻结。审计 + testnet 后才会公开发射。
