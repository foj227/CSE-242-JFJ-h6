# H6 Market Log — CSE 242 Fall 2026

**Author:** foj227@lehigh.edu
**Assistant:** Claude (Opus), used per H6 §5 ("free to seek the aid of your favorite AI assistant… keep track of what you do").
**Started:** 2026-10-28
**Deadline:** Thu 2026-10-29 11:59pm EST

**Scope decision (10/28):** Pursue all avenues — arbitrage, defense, and targeted exploits of
confirmed-buggy pools, including sneaky-but-legal ideas. User confirms this and the use of an AI
assistant have been **cleared with the instructional team** per §5.

---

## 1. Objective

Use our H4 AMM plus every other team's AMM on the lu-eth network to make FAKEETH through
clever trading, and (per the rules) by exploiting bugs in other teams' exchanges where they exist.
Document strategy, discoveries, and final holdings for the report.

## 2. Environment / ground truth

- Network: **lu-eth** (behind Lehigh VPN). Claude cannot reach it directly; all on-chain reads/writes
  go through the user's Remix + MetaMask. Claude writes code and does the math; user executes.
- Block explorer (Blockscout): `http://vitalik.cse.lehigh.edu:8040`
- Tokens (ERC-20, 18 decimals):
  - ASA (AsaToken)  `0x31c6A9bdb16f4619C4AE66daB6909B3e8EA0f757`
  - HAW (HawKoin)   `0x79367eB28B970CaD4D667E20bA530d837014da97`
  - KOR (KorthCoin) `0x3788776dF00D6AD7FdE73D0Db289196849DC412f`
- Exchange interface (from H4 handout, `testExchange`):
  `provideLiquidity(uint)` payable, `withdrawLiquidity(uint)`, `swapForEth(uint)`,
  `swapForERC20Token()` payable, plus `estimate*` views and `getMyLiquidityPositions()`.
- AMM math (H4): constant product `K = ethBal * tokBal`. No swap fee (unlike Uniswap),
  so arbitrage and provide/withdraw are the only ways value moves.

## 3. Findings so far

### F1 — ASA deployed token has an allowlisted faucet (NOT a bug)  [confirmed from bytecode]
The deployed AsaToken differs from the handout source. Extra function `selector 0x08def058` (no args)
calls an internal `_mint(msg.sender, 1000e18)` but is gated: it only works for addresses the
constructor marked `true` in a mapping at storage slot 5 — the deployer, `0x1f82…b02f`, and
`0xFa5343…bAb3`. No function exists to add new addresses. This explains ASA total supply
99,999 → 103,999 (faucet called a few times by `0xFa53…bAb3`). **Conclusion: intended instructor
infrastructure, not exploitable by us.** (Worth stating in the report so the supply discrepancy is explained.)
_TODO: confirm HAW/KOR deployed bytecode for the same pattern — likely identical._

### F2 — Exchange population (from Blockscout token holders)  [addresses confirmed, reserves pending live scan]
Distinct **contract** holders of each token = the live exchanges. Grouped by the token they appeared under:

- **ASA pools:** `0x6978…3970`, `0xc207…23dB`, `0x28bA…a4c0` (all ~139.18 ASA — likely the three
  grader/reference pools), `0x311E…A0D4` (~88.0), `0x8138…AD0E` (~13.9), `0x592A…0a1B` (~4.4).
- **HAW pools:** `0x1aF0…8a2D`, `0x3517…5163`, `0xE476…C0a1` (all ~125.49), `0x800C…7594` (~39.7),
  `0x71bA…B9Cd` (~12.5), `0xd477…D212` (~11.9), `0xa153…88d5` (~0.40).
- **KOR pools:** `0xA0b1…1390`, `0xC6b8…EAa1`, `0xC211…5308` (all ~121.73), `0x35b5…0819` (~38.5),
  `0x1e53…4f57` (~12.7), `0xe96D…81eC` (~3.85), `0x6fA0…5a4c` (~3.36), `0xE8C9…9D45` (~0.39).

Note: the three near-identical reserves per token strongly suggest reference/grader deployments
(same code). The uneven ones are teams whose pools have already been traded against.
**Token reserves above are ballpark from the holder list; ETH reserves are unknown until the live scan,
and price = ETH/token needs both.**

### F3 — Market is efficient except one pool  [confirmed from live scan 10/29 00:00Z]
All pools of a token sit at the SAME price (no-fee AMMs → arbitraged/deployed to parity):
ASA 0.0051620, KOR 0.0063502, HAW 0.0067479 ETH/token, consistent to ~8 sig figs.
→ **No arbitrage in ASA or KOR. No "lying estimate" pools** (every honest pool's estimates match
fair constant-product within 2%).

### F4 — One mispriced/broken HAW pool  [arb target]
`0x6fA05B72bdC4f0DBbef1A83C4359BD151b1A5a4c`: 0.000616 ETH / 3.3555 HAW → 0.000184 ETH/HAW,
**97.3% below market**. All four estimate* functions REVERT (broken or hostile). Unique code
`0x6ffb85`, size 9511. Plan: buy its cheap HAW via ArbBot, sell on deep pool `0xA0b1…`; model
profit ~0.0154 ETH. Atomic require makes a misbehaving swap cost only gas.

### F5 — Deep-pool code families (primary exploit targets)
Shared deployed-bytecode hash ⇒ same implementation ⇒ same bugs, across 3 tokens each:
- `0x993b5a`: `0xc207…`(ASA 0.718Ξ), `0xA0b1…`(HAW 0.821Ξ), `0x1aF0…`(KOR 0.797Ξ)  ≈ 2.34 Ξ
- `0x7dae7b`: `0x28bA…`(ASA 0.718Ξ), `0xC6b8…`(HAW 0.821Ξ), `0xE476…`(KOR 0.797Ξ)  ≈ 2.34 Ξ
One drainable bug in either ⇒ drains all three pools in that family. Need bytecode to confirm.
Our own pools: ASA `0x6978`(code 0x2556b2), HAW `0xE8C9`(0x61e9eb), KOR `0xa153`(0x933edb).

### F6 — Code family `0x993b5a` audited: NOT exploitable  [pools 0xc207/0xA0b1/0x1aF0, ~2.34 Ξ]
Disassembled deployed bytecode (7932 B). Findings:
- OpenZeppelin-style `ReentrancyGuard` (slot-0 `_status`) wraps provide/withdraw/both swaps → no reentrancy.
- `swapForERC20Token` computes `tokenOut = tokBal − K/SELFBALANCE`; `SELFBALANCE` already includes
  `msg.value`, so it's the correct post-swap balance — **no msg.value double-count** (the handout's hinted trap, avoided).
- Checks-effects-interactions: storage writes precede external token/ETH transfers in withdraw/provide.
- Enforces: `"Wrong ratio"`, `"Cannot empty pool"`, `"Invalid output"`, `"Zero deposit"`, `"Wrong positions"`.
- Pricing matches fair constant-product (scanner F3) and no cached-K drift exploit.
Verdict: well-written, no exploit. (Note for report: confirms "everyone has AI" raises the bar.)

### F7 — Code family `0x7dae7b` audited: NOT exploitable  [pools 0x28bA/0xC6b8/0xE476, ~2.34 Ξ]
Disassembled (slots: posns=0, total=1, token=2, K=3). **No ReentrancyGuard** — but safe anyway:
- `withdrawLiquidity` writes posns/total/K to storage BEFORE the token transfer and ETH send
  (checks-effects-interactions) → reentry sees decremented balances, no double-withdraw. Enforces
  `"Cannot withdraw all liquidity from the pool"` (strict `_amount < total`) and `"Cannot burn more than you own"`.
- `swapForEth` sends ETH last; doesn't cache-update K (invariant) → no stale-reserve reentry edge.
- `swapForERC20Token` uses `tokenOut = tokBal − K/SELFBALANCE` (SELFBALANCE already includes msg.value) → no double-count.
Verdict: secure. Two biggest implementations (F6+F7 = 6 deep pools, ~4.7 Ξ) both clean.

### Interim assessment
No arbitrage (parity + no fees), the one off-price pool is non-functional, and both dominant
implementations are secure. Remaining exploit surface = pools running unique, un-audited code,
largest of which is `0x311E27ED` (asa-D, **0.454 Ξ**, code `0xe594d7`). Checking those next.

### F8 — Pool `0x311E27ED` (code `0xe594d7`, asa-D, 0.454 Ξ) audited: NOT exploitable
Immutable token addr; slots: K=0, total=1, posns=2, reentrancy-status=3. Boolean `nonReentrant`
(`"Re-entrant call"`) on all 4 funcs. `withdrawLiquidity` CEI-correct + `"Cannot withdraw all liquidity"`.
`swapForERC20Token` uses SELFBALANCE post-balance (no double-count). `provideLiquidity` enforces
EXACT ratio (`"Deposit ratio does not match pool"`). Verdict: clean.

**Running tally: 3 distinct implementations audited (~5.1 Ξ of pools), all secure.** Remaining = small
pools only: `0x35b5`(0.260Ξ,0x732734), `0x800C`(0.252Ξ,0xbe2064), family `0x76168d`(~0.24Ξ/3 pools),
`0xd477`(0.076Ξ), broken `0x6fA0`(0.0006Ξ).

### F9 — `0x35b5` & `0x800C` are the SAME contract as `0x311E` (F8): NOT exploitable
Their deployed bytecode is byte-identical to `0x311E` except the immutable token address (HAW/KOR vs
ASA) — that's why codehashes differ (0x732734 / 0xbe2064 vs 0xe594d7) but the source is one
implementation. So pools `0x311E`(0.454Ξ ASA) + `0x35b5`(0.260Ξ HAW) + `0x800C`(0.252Ξ KOR) = one
clean implementation, ~0.97 Ξ, already audited in F8.

### F10 — `0x6fA05B72` is NOT a pool — it's a classmate's trading BOT  [mystery resolved]
Different ABI entirely: `owner`, `"owner only"` guards, and helper functions that call
`swapForEth`/`swapForERC20Token`/`provideLiquidity`/`withdrawLiquidity` on OTHER exchanges (one does a
provide→withdraw loop). It holds 3.355 HAW + 0.0006 Ξ as leftover inventory, not as an AMM reserve.
This is why its exchange-interface calls reverted when probed (it doesn't implement them) and why the
"97% off" price in F4 was an artifact (no real pool there). Funds are `onlyOwner`-locked → not
exploitable. **Confirms ArbBot's atomic revert was the correct, safe outcome for T1.**

### F11 — Code family `0x76168d` (pools 0x8138/0x1e53/0x71bA, ~0.24 Ξ) audited: NOT exploitable
`ReentrancyGuard`; slots status=0, token=1, posns=2, total=3, K=4. Most defensive of the four:
recomputes `K = ethBefore*tokBal` locally each call (no stale cache), correct SELFBALANCE post-swap
math, CEI with ETH-send last, exact ratio check (`"Incorrect ratio"`), and bounds every swap/withdraw
(`"Invalid swap"` = 0<out<reserve, `"Cannot withdraw all"`, `"Invalid withdrawal"`). Verdict: clean.

### FINAL AUDIT RESULT
Four distinct exchange implementations cover every pool holding meaningful FAKEETH (~6 Ξ):
`0x993b5a`, `0x7dae7b`, `0xe594d7`(=0x732734=0xbe2064 source), `0x76168d` — **all secure**. The lone
price anomaly (`0x6fA0`) was a classmate's bot, not a pool. Only dust pools remain unaudited
(`0xd477` 0.076Ξ, `0x592A` 0.023Ξ, `0xfb44` ~0) — negligible and out of scope.
**Conclusion: efficient, well-secured market. No profitable arbitrage or exploit exists. The correct
play is capital preservation; the ArbBot is retained as the safe tool to capture any future imbalance.**

## 4. Strategy catalog (to attempt, in rough priority order)

| # | Strategy | Type | Status |
|---|----------|------|--------|
| S1 | Cross-exchange arbitrage: buy a token where ETH/tok is low, sell where high. Size each leg optimally from reserves. | honest | planned |
| S2 | **Atomic arbitrage contract**: do both legs in one tx; `require` end-FAKEETH > start-FAKEETH or revert. Removes the "someone trades between my two legs" risk the handout warns about. | honest | **contract written (`ArbBot.sol`), awaiting reserves to size/target** |
| S3 | Multi-hop routing across 3+ pools (FAKEETH→tok on A, tok→FAKEETH on B, …). | honest | planned |
| S4 | Exploit buggy `provideLiquidity`/`withdrawLiquidity` (e.g. ratio not enforced, or `msg.value` double-counted in balance). Only vs. a pool whose code/behavior we've confirmed buggy. | exploit (rules-permitted) | needs target confirmation |
| S5 | Re-entrancy: if a pool sends ETH before updating K/balances (the DAO bug H4 warns against). Only vs. a confirmed-vulnerable pool. | exploit (rules-permitted) | needs target confirmation |
| S6 | Defense: withdraw/relocate our own liquidity so arbitrageurs don't bleed our pool; optionally redeploy a fixed exchange (allowed by §5). | defense | planned |
| D1 | Never give unlimited ERC-20 `approve` to a classmate contract; our arb contract approves exact amounts only. | hygiene | adopted |

Anything "sneaky but legal" (e.g. deploying a pool whose real swap underpays its `estimate`) gets a
heads-up to the instructional team, per §5, so it reads as clever rather than shady.

## 5. Action log (chronological)

| # | Time (ET) | Action | Tx / result | FAKEETH Δ | Notes |
|---|-----------|--------|-------------|-----------|-------|
| 0 | 10/28 | Read-only scanner written; 22 exchange addresses discovered via explorer | — | 0 | no tx sent |
| 1 | 10/28 | F1 confirmed from bytecode: ASA "extra mint" is an allowlisted instructor faucet, not a bug | — | 0 | ruled out as exploit |
| 2 | 10/28 | `ArbBot.sol` written: atomic 2-leg arbitrage, reverts unless net FAKEETH gain ≥ minProfit; exact-approve only | — | 0 | not yet deployed |
| 3 | 10/28 | Live scan analyzed (`analyze.py`): market efficient except HAW pool `0x6fA0`; identified deep-pool exploit targets F5 | — | 0 | baseline holdings: 9.988 FAKEETH, 0 tokens |

| 4 | 10/28 20:23 | Deployed `ArbBot` @ `0xAde3f9f0C4B4aDF9aDb7057b4f5ACeebA7724710`; funded 0.01; ran T1 arb | tx `0x4eecc5…0e0628` **reverted** | -~0.0000036 (gas) | leg1 `swapForERC20Token` on `0x6fA0` REVERTS → pool's swap is non-functional, not just estimates |

**Conclusion after T1:** No arbitrage exists in this market — honest pools are all at price parity
(no-fee AMM), and the single off-price pool `0x6fA0` is broken (swap + estimates revert, untradeable).
ArbBot's atomic guard worked perfectly: bad leg → full revert → only gas lost. Profit from here must
come from **exploiting buggy pools** (F5 targets). Pivoting to bytecode analysis.

### Planned trade T1 — capture the mispriced HAW pool (S2, via ArbBot)
- Deploy `ArbBot`, `fund()` with 0.01 FAKEETH.
- Call `arb(`
  - exBuy  = `0x6fA05B72bdC4f0DBbef1A83C4359BD151b1A5a4c`
  - exSell = `0xA0b176a900EF0D8aCa48ae68b67F44708ff31390`
  - token  = `0x79367eB28B970CaD4D667E20bA530d837014da97` (HAW)
  - ethIn  = `3000000000000000` (0.003)
  - minProfitWei = `1000000000000000` (0.001 floor; model expects ~0.015)
  - `)`
- Then `withdrawAllEth()`. Expected net: ~+0.015 FAKEETH (or revert → only gas lost).

## 6. Holdings tracking

| When | FAKEETH | ASA | HAW | KOR | Source |
|------|---------|-----|-----|-----|--------|
| BEFORE (baseline) | 9.988 | 0 | 0 | 0 | MetaMask, 10/28 ~20:00 ET |
| AFTER | _TBD_ | _TBD_ | _TBD_ | _TBD_ | at submission |

## 7. Open TODO

- [ ] User runs `scan_exchanges.js` → get live ETH + token reserves + estimate quotes for every pool.
- [ ] Record BEFORE holdings from MetaMask.
- [ ] Compute real ETH/token prices and the arbitrage spread per token.
- [ ] Decide first trade (S1 manual, or go straight to S2 atomic contract).
- [ ] Confirm whether any pool's `estimate*` quotes diverge from fair constant-product value (scanner flags this) → candidate for S4.