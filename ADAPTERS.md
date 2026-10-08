# Chain Adapters — Status Matrix

Aegis 使用"核心库 + 链适配器"架构。核心 `aegis-core` (Rust/WASM) 是 chain-agnostic
的 BIP-39 → SPHINCS+ 密钥派生和签名；每条链有独立适配器，用该链的原生语言实现
账户合约 + SPHINCS+ 验证器 + 一致性 ABI。

**本仓库 v0.1 的所有非 EVM 适配器都是"可编译的骨架 + SPHINCS+ verify 的 TODO stub"。**
每条链的真实 SPHINCS+ 验证实现估计工时见下表最后一列。地址派生在 README 里有确定性
规范，可被独立验证。

## 覆盖矩阵

| # | Chain      | Family    | Dir            | 语言     | 地址派生 spec | 账户合约 | SPHINCS+ 验证 | 真实实现工时 |
|---|------------|-----------|----------------|----------|--------------|---------|--------------|------------|
| 1 | Ethereum   | EVM       | `evm/`         | Solidity | CREATE2      | ✅ ready | 🟡 stub      | 2 w (fork nconsigny C13) |
| 2 | BSC        | EVM       | `evm/`         | Solidity | CREATE2      | ✅       | 🟡           | — (same artifact) |
| 3 | Polygon    | EVM       | `evm/`         | Solidity | CREATE2      | ✅       | 🟡           | — |
| 4 | Arbitrum   | EVM       | `evm/`         | Solidity | CREATE2      | ✅       | 🟡           | — |
| 5 | Optimism   | EVM       | `evm/`         | Solidity | CREATE2      | ✅       | 🟡           | — |
| 6 | Base       | EVM       | `evm/`         | Solidity | CREATE2      | ✅       | 🟡           | — |
| 7 | Avalanche  | EVM       | `evm/`         | Solidity | CREATE2      | ✅       | 🟡           | — |
| 8 | Linea/Scroll/Mantle/Blast/Mode | EVM | `evm/` | Solidity | CREATE2 | ✅ | 🟡 | — |
| 9 | TRON       | TVM       | `tron/`        | Solidity | base58check  | ✅ shared with EVM | 🟡 | 1 w (address encoder) |
| 10| Starknet   | Cairo VM  | `cairo/`       | Cairo 1  | class hash + pedersen | 🟡 constructor only | ❌ TODO | 4 w |
| 11| Solana     | SVM       | `solana/`      | Rust/Anchor | PDA(seed, program_id) | 🟡 stub | ❌ TODO | 4 w |
| 12| Cosmos     | CosmWasm  | `cosmwasm/`    | Rust     | bech32(sha256(pk)[:20]) | 🟡 stub | ❌ TODO | 3 w |
| 13| Aptos      | Move      | `aptos/`       | Move     | sha3_256(pk \|\| 0x02) | 🟡 stub | ❌ TODO | 6 w |
| 14| Sui        | Move      | `sui/`         | Move     | blake2b(0x02 \|\| pk) | 🟡 stub | ❌ TODO | 6 w |
| 15| NEAR       | WASM      | `near/`        | Rust/near-sdk | implicit account hex(sha256(pk)) | 🟡 stub | ❌ TODO | 4 w |
| 16| TON        | TVM(TON)  | `ton/`         | FunC     | hash(StateInit)      | 🟡 stub | ❌ TODO | 6 w |
| 17| Bitcoin    | Script    | `bitcoin/`     | miniscript/taproot | P2TR / BIP-360 P2MR | 🟡 design-doc only | ⏸ waiting on BIP-360 activation | — |

**Legend**:
- ✅ = functional (unit-tested against stub verifier)
- 🟡 = skeleton compiles / design finalized, SPHINCS+ logic TODO
- ❌ = not yet implemented
- ⏸ = blocked on external dependency

## 为什么骨架有价值（即使 verify 还是 stub）

1. 每条链的目录结构 + 配置文件 + 构建命令 **立刻可以** `git clone && cd <chain> && <build>`
2. 账户的接口 ABI、地址派生规则、状态机设计 **在骨架里就定好了**，不会在真实现时变
3. 任何第三方贡献者可以直接针对单一链实现 verify 并 PR，不需要先搭环境
4. 支付审计/实现 bounty 时，范围清晰：**"实现 X 链的 verify，接口已给，测试向量已给"**

## 共同接口

每条链的 AegisAccount 必须暴露以下语义（具体函数名因语言而异）：

```
constructor(pq_pk_hash, guardian, ecdsa_fallback_key, verifier, fee_collector)
execute(target, value, data, nonce, pq_pk, pq_sig)
initiate_emergency_exit(fallback_sig)
cancel_emergency_exit(pq_pk, pq_sig)
finalize_emergency_exit(assets[])  # after TIMELOCK (7 days)
```

参见 `SPEC.md` §4 的权威定义。
