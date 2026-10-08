# Ten-second self-verification

Open any block explorer (Etherscan, BscScan, Arbiscan, …) and paste your Aegis account address. Every claim below can be checked from the explorer's **Code** and **Read Contract** tabs without trusting anyone's word.

---

## Hash-only account (`AegisCCHS`)

### 1. Non-custodial
- Code tab → search for `transfer`, `withdraw`, `owner`, `onlyOwner`.
- Expected: none exist. Funds move only through `execute`, which requires a valid CCHS signature. There is no privileged address.

### 2. Not upgradeable
- Search for `delegatecall`, `upgradeTo`, `_setImplementation`, `selfdestruct`.
- Expected: zero results. What was deployed is all there will ever be.

### 3. Verifier is built in
- Read Contract → there is no `VERIFIER` address. Signature verification is inside the account itself (SHA-256 precompile only). Nothing external can be swapped.

### 4. Root is yours
- Read Contract → `root`, `recRoot`.
- Expected: the two roots your client displayed at account creation. If they differ, stop and move funds out — you were served a different account.

### 5. Signature counter is monotonic
- Read Contract → `nextIdx`, `nonce`.
- Each successful `execute` increments both by one. Any gap or regression is impossible by construction.

### 6. Cache is append-only per epoch
- Read Contract → `cachedRoot((epoch << 64) | treeIdx)`.
- Once non-zero, it cannot be overwritten within the same `epoch`. `epoch` changes only through `recover`.

### 7. No protocol fee
- Search for `FEE_COLLECTOR`, `PROTOCOL_FEE_BPS`.
- Expected: absent. The hash-only account charges nothing.

---

## Hybrid account (`AegisAccountV2`)

### 1. Non-custodial
- Only `ecdsaOwner` can call `execute`. No other address has any authority.

### 2. Not upgradeable
- Search for `delegatecall`, `upgradeTo`, `selfdestruct`. Expected: zero results.

### 3. Fee has a hard ceiling
- Read Contract → `MAX_FEE_BPS` returns `2000`; `PROTOCOL_FEE_BPS` returns `1000`. Both are `constant`.

### 4. Post-quantum commitment is immutable
- Read Contract → `PQ_PK_HASH`. Matches the hash your client showed at creation. It cannot change.

### 5. Recovery is free
- `pqRecover` contains no fee logic. Rotating the owner after an ECDSA break costs only gas.

### 6. Verifier and factory are at the same address on every chain
- Compare `VERIFIER` and the factory address across chains. They match because the deployer used identical bytecode at identical nonces.

---

## If any check fails

Stop, withdraw, and disclose publicly. Every promise this protocol makes is in the bytecode; if the bytecode disagrees with this document, either the document is wrong or you are on a counterfeit front-end.

- Source: this repository
- Front-end: build it locally from `wallet/` and compare asset hashes
