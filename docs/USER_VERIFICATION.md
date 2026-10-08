# 用户 10 秒自验：Aegis 为什么不会跑路

打开任意一条链的 explorer（BscScan / Etherscan / Arbiscan / ...），粘贴你的
AegisAccount 地址。你应当看到以下七条，每条都用 explorer 的"Read Contract"
标签页**自己点一下**验证，不依赖任何人的口头承诺。

---

## 1. 非托管

- 点 "Contract" → "Code"
- 搜索函数名 `balanceOf` / `transfer` / `withdraw`
- **应该**：这些函数不存在于 AegisAccount。你的资产余额用 explorer 左边
  的 "Balance" + "ERC-20 Token Txns" 自己看，私钥只在你手里。

## 2. 不可升级

- 点 "Contract" → "Code" → 搜 `upgradeTo` / `_setImplementation` / `delegatecall`
- **应该**：全部 0 结果。合约部署完就是全部，没有任何 upgrade/proxy pattern。

## 3. 没有 selfdestruct

- 搜 `selfdestruct`
- **应该**：0 结果。合约永远不会被销毁。

## 4. 费率有硬顶

- 点 "Contract" → "Read Contract"
- 找 `MAX_FEE_BPS` → **应该返回 `2000`**（= 20% 硬上限）
- 找 `PROTOCOL_FEE_BPS` → **应该返回 `1000`**（= 10% 当前费率）
- 两者都是 `constant`，永远不能被改。

## 5. Guardian 是你自己的地址

- 点 "Read Contract" → `GUARDIAN`
- **应该返回**：你部署账户时填的冷钱包地址。**自己确认一遍**。
- 如果这个地址不是你，说明你被钓鱼了，立刻停止使用并把资产转出。

## 6. 退出路径真的免费、真的 7 天

- 读 `TIMELOCK` → **应该返回 `604800`**（7 天的秒数）
- 读 `exitTimestamp` → `0` 表示没有待定退出；非 0 表示有，到期时间即该值
- 退出路径的函数 `finalizeEmergencyExit` 的实现**不调用** `FEE_COLLECTOR`，
  这是 code 级别的事实。

## 7. Verifier 和 Factory 在所有链同地址

打开 `aegis.eth` 的 contract-addresses 页面，验证：
- Verifier 地址在 Ethereum / BSC / Polygon / Arbitrum / Optimism / Base /
  Avalanche / ... 每条链都一样
- Factory 地址同上
- Deployer EOA (`0x...DEAD`) 在每条链的 nonce 都 ≥ 2，且**该地址的私钥已在**
  **发射当天公开直播销毁**。链接到销毁 tx hash。

---

## 如果以上任何一条不满足

**立刻停止使用，提款，并公开披露**。这个协议对自己的所有承诺都写在
code 里了。如果 code 不符合这份文档，是我们的 bug 或者你被钓到了假前端。

- 官方 ENS: `aegis.eth`
- 官方前端 IPFS CID: 见 ENS contenthash
- 官方 GitHub: 见本仓库
- 永久 Arweave 备份: 待发射后补充
