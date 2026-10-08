# Aegis Wallet (Tauri + React)

统一钱包 UI。一屏显示用户在所有支持链的 PQ 账户和余额。

## 功能

- 导入 / 生成 24 词 BIP-39 助记词
- 通过 `aegis-core` (WASM) 派生 SPHINCS+ keypair + ECDSA fallback
- 显示每条链上该种子对应的 AegisAccount 地址和余额
- 发起 PQ-签名的转账（任意 token，任意地址）
- 发起紧急退出 ECDSA → 7 天 timelock → guardian
- 任何时候用 PQ 签名 cancel 待定的紧急退出
- 一键打开任意链 explorer 查看自己的 account

## 技术栈

- Tauri 2.x (桌面壳)
- React 19 + Vite + TypeScript
- `aegis-core` 的 WASM 构建 (`wasm-pack build core --target web`)
- viem / wagmi (EVM)
- starknet.js (Starknet)
- @solana/web3.js (Solana, phase 2)
- @cosmjs (CosmWasm, phase 2)

## 状态

Skeleton — 待实施。先确保 EVM 合约和核心库跑通后再做 UI。
