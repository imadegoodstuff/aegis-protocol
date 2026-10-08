# Aegis Protocol Specification v0.1

状态: Draft · 2026-10-08

本文档规范 Aegis 协议的核心数据结构、函数接口、派生规则和威胁模型。实现必须严格遵循。

---

## 1. 术语

| 术语 | 定义 |
|---|---|
| SPHINCS+ | NIST SLH-DSA (FIPS 205) 规定的无状态 hash-based 签名方案 |
| AegisAccount | 用户在一条链上的智能账户合约实例 |
| guardian | 用户在部署 AegisAccount 时指定的 fallback 收款地址，immutable |
| PQ sig | SPHINCS+-192s 签名，用于日常执行 |
| ECDSA fallback | 用户 EOA 私钥的签名，只能走 timelock 发送到 guardian |
| TIMELOCK | 紧急退出的 7 天延迟 (604,800 秒) |
| MAX_FEE_BPS | 协议费率硬上限，常量 2000 (20%) |
| PROTOCOL_FEE_BPS | 当前协议费率，常量 1000 (10%)，不可变 |

---

## 2. 密钥派生

```
BIP-39 mnemonic (24 词, 256 bit entropy)
   └─ PBKDF2-HMAC-SHA512(passphrase, iter=2048) → 64 byte seed
       └─ HKDF-SHA256(seed, info="aegis/sphincs+/192s/v1") → 96 byte SK seed
           └─ SPHINCS+-192s KeyGen (deterministic) → (sk, pk)
```

同一助记词 → 全链同一 SPHINCS+ keypair。各链地址由 pk 派生。

ECDSA fallback 私钥独立派生：
```
HKDF-SHA256(seed, info="aegis/ecdsa/fallback/v1") → 32 byte sk
```

---

## 3. 地址派生

### EVM 链

```
accountAddress = CREATE2(
    deployer = AegisAccountFactory,
    salt     = keccak256(pq_pk ++ guardian_addr),
    bytecode = keccak256(AegisAccount creationCode ++ constructor args)
)
```

Factory 和 Verifier 用相同的 deployer EOA + 相同 nonce 部署到每条链 → 所有 EVM 链上同地址。

故对任意两条 EVM 链 L1、L2：若 (pq_pk, guardian) 相同，则 account 地址相同。

### Starknet

```
accountAddress = pedersen(classHash, pedersen(pq_pk_hash, guardian_hash))
```

非 EVM，地址与 EVM 链不同，但同种子派生。

### Solana / Cosmos / Move

各链 PDA 规则，由对应 adapter 定义。

---

## 4. AegisAccount 合约接口

### 4.1 不可变状态

```solidity
contract AegisAccount {
    bytes32 public immutable PQ_PK_HASH;      // SPHINCS+ pk 的 hash
    address public immutable GUARDIAN;         // 紧急退出目标
    address public immutable VERIFIER;         // SphincsVerifier 合约
    address public immutable FEE_COLLECTOR;    // 费用收款地址
    uint256 public constant  MAX_FEE_BPS = 2000;
    uint256 public constant  PROTOCOL_FEE_BPS = 1000;
    uint256 public constant  TIMELOCK = 7 days;
}
```

**禁止**：proxy、selfdestruct、`upgradeTo`、`setOwner`、`setVerifier`、`setFee`、任何改状态的 setter。

### 4.2 执行 (日常路径)

```solidity
function execute(
    address target,
    uint256 value,
    bytes calldata data,
    uint256 nonce,
    bytes calldata pqSig
) external payable;
```

流程:
1. 构造 `digest = keccak256(abi.encode(block.chainid, address(this), nonce, target, value, data))`
2. 检查 `nonce == currentNonce + 1`
3. 调用 `VERIFIER.verify(PQ_PK, digest, pqSig)` ，失败则 revert
4. 计算 `fee = tx.gasPrice * gasUsed * PROTOCOL_FEE_BPS / 10000`，转给 FEE_COLLECTOR
5. 执行 `target.call{value: value}(data)`
6. `currentNonce += 1`

### 4.3 批量执行

```solidity
function executeBatch(
    address[] calldata targets,
    uint256[] calldata values,
    bytes[] calldata datas,
    uint256 nonce,
    bytes calldata pqSig
) external payable;
```

### 4.4 紧急退出 (ECDSA fallback)

两阶段 commit → delay → finalize：

```solidity
function initiateEmergencyExit(bytes calldata ecdsaSig) external;
function cancelEmergencyExit(bytes calldata pqSig) external;
function finalizeEmergencyExit(address[] calldata tokens) external;
```

流程：
1. `initiateEmergencyExit`：验证 ECDSA 签名（针对 `keccak256("AEGIS_EXIT" ++ chainid ++ address(this) ++ nonce)`），设置 `exitTimestamp = block.timestamp + TIMELOCK`
2. 任何时候 `cancelEmergencyExit`：PQ 签名可取消 (防止 ECDSA 被量子攻破的攻击者偷钱)
3. `block.timestamp >= exitTimestamp` 后：`finalizeEmergencyExit(tokens)` → 把 `address(this)` 的 ETH + 列表中 ERC-20 全部转到 `GUARDIAN`
4. 紧急退出路径 **不收任何协议费**

### 4.5 公钥轮换

v0.1 不支持。SPHINCS+ 是无状态签名，但轮换需要承诺旧 pk 失效 + 公告新 pk，设计留给 v0.2。

---

## 5. AegisAccountFactory

```solidity
contract AegisAccountFactory {
    address public immutable VERIFIER;
    address public immutable FEE_COLLECTOR;

    event AccountDeployed(address indexed account, bytes32 pqPkHash, address guardian);

    function deploy(
        bytes32 pqPkHash,
        address guardian
    ) external returns (address account);

    function predictAddress(
        bytes32 pqPkHash,
        address guardian
    ) external view returns (address);
}
```

Factory 本身 immutable。无 owner。任何人可以为任何 (pqPkHash, guardian) 调用 deploy。

---

## 6. SphincsVerifier

```solidity
interface ISphincsVerifier {
    function verify(
        bytes calldata pk,       // SPHINCS+-192s public key, 48 bytes
        bytes32 digest,
        bytes calldata signature // SPHINCS+-192s sig, ~16KB (或 SHRINCS 更小)
    ) external view returns (bool);
}
```

实现：fork [`nconsigny/SPHINCs-`](https://github.com/nconsigny/SPHINCS-) C13 verifier (FIPS 205 §11.2.2 uncompressed 32-byte ADRS)。本仓库 v0.1 带 stub，生产部署前必须替换为 C13 fork。

验证 gas 预算 (L2，参考 nconsigny C13)：**~190K gas standalone / ~290K gas 作为 UserOp 的一部分**。

---

## 7. 多链部署流程

1. 创建新的 deployer EOA (以下简称 `D`)
2. 在每条目标链上，分别向 `D` 发送最少 gas (用户捐赠或自己充值)
3. `D` 在每条链的 nonce = 0 时部署 `SphincsVerifier`
4. `D` 在每条链的 nonce = 1 时部署 `AegisAccountFactory(verifier, feeCollector)`
5. **公开直播销毁 `D` 的私钥**（例如发一笔 `selfdestruct` 到 `D` 自己，或公开 private key 让所有人验证）
6. 验证：所有链上 Verifier 地址相同、Factory 地址相同、`D` 已销毁

脚本见 `evm/script/DeployMultichain.s.sol`。

---

## 8. 费用

- 协议费 = `tx.gasPrice * (gasUsed_in_execute) * PROTOCOL_FEE_BPS / 10000`
- 收款地址 = `FEE_COLLECTOR` (部署时写死，immutable)
- 紧急退出路径不收费
- 费率 constant，不可改。要改必须部署新合约，用户自愿迁移。

---

## 9. 威胁模型

### 9.1 协议方应对的威胁

| 威胁 | 防御 |
|---|---|
| 协议方跑路 | 无 admin key、无升级、ECDSA fallback 可独立退出 |
| 费率被恶意提高 | `PROTOCOL_FEE_BPS` 是 constant |
| 费用金库被挪用 | 没有金库概念；fee 直接到 immutable FEE_COLLECTOR |
| 前端被劫持 | ENS + IPFS CID；用户可本地跑 UI |
| Deployer 被盗 | 部署完立刻公开销毁 |
| Factory 升级攻击 | Factory 本身 immutable |
| CREATE2 collision | SPHINCS+ pk 256 bit entropy，碰撞概率可忽略 |

### 9.2 协议方不应对的威胁 (必须坦白)

| 威胁 | 为什么管不了 |
|---|---|
| 链本身的共识被攻陷 | 链级问题，无法在合约层防御 |
| 用户设备被攻陷 | OPSEC 不是协议能解决的 |
| 用户泄露助记词 | 同上 |
| SPHINCS+ 本身被攻破 | 等于 hash 函数被破；此时所有系统都倒 |
| 用户把 guardian 写成攻击者地址 | 部署时就犯的错 |

### 9.3 PQ 威胁下的具体保证

| 场景 | 结果 |
|---|---|
| 量子/AI 破了 ECDSA，攻击者偷用户 EOA 私钥 | 攻击者 `initiateEmergencyExit` → 7 天 timelock → 用户用 PQ 签名 `cancelEmergencyExit` 阻止 |
| 量子破了 BSC 验证者签名 | Aegis 保护不了。但用户的 PQ 账户在任何保留状态根的 fork 链上继续有效 |
| 量子破了 SPHINCS+ | 不太可能 (hash 函数被破了)。但用户仍可 7 天 timelock 走 ECDSA fallback 到 guardian |

---

## 10. 版本和升级

- 协议版本 = 合约 `VERSION` constant = `"0.1.0"`
- 新版本 = 新 Factory + 新 Verifier 部署到新地址
- 老用户账户 **永不自动升级**。用户完全自愿把资金迁到新账户。
- 老合约永远可用，直到链本身消失。

---

## 11. 开放问题 (v0.2 考虑)

- 公钥轮换 (per-op key rotation)
- 批量 PQ 签名聚合 (借 leanVM / leanSig)
- Note relay 隐私层 (Classic McEliece KEM + Nostr-like gossip)
- SPHINCS+-192s → SHRINCS 迁移 (更小签名)
- 跨链 nonce 协调 (防重放)
- Social recovery 作为第三条验证路径

---

## 12. 参考

- [FIPS 205 (SLH-DSA / SPHINCS+)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf)
- [EIP-1014 CREATE2](https://eips.ethereum.org/EIPS/eip-1014)
- [nconsigny/SPHINCs-](https://github.com/nconsigny/SPHINCS-) - EVM verifier C13
- [pq.ethereum.org](https://pq.ethereum.org/) - Ethereum Lean roadmap
- Vitalik Buterin, 2026-10-07 X thread on AI-vulnerable cryptography
- Justin Drake, 2026-10-07 "bunker mode" post
