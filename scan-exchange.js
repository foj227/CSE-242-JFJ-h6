// scan_exchanges.js  —  CSE 242 H6 market scanner
// READ-ONLY: sends no transactions, costs no gas, needs no approvals.
//
// How to run:
//   1. In Remix, put this file in the "scripts" folder.
//   2. Deploy & Run tab -> Environment = Browser Extension / MetaMask, connected to LuEth (on VPN).
//   3. Paste every team's exchange address into EXCHANGES below.
//   4. Right-click this file -> "Run" (or select it and use "Compile and Run script").
//   5. Copy everything from the Remix terminal (or the scan_output.json it writes) back to Claude.

// Discovered from Blockscout token-holder lists (is_contract:true).
// Grouping by token is tentative; the scanner re-reads real balances live and
// flags any mismatch, so wrong guesses self-correct. Add OUR team's exchanges too.
const EXCHANGES = [
  // --- Our exchanges ---
  { team: "jfj-asa", addr: "0x6978aF9863fE4c36f49b3c5623Fc2263a82F3970"}
  { team: "jfj-haw", addr: "0xE8C9FDf67d0929385EcA42105361B50C80B49D45"}
  { team: "jfj-kor", addr: "0xa153865001e2793e6E9092418ED68A30594A88d5"}

  // --- pools seen holding ASA ---
  { team: "asa-A", addr: "0x6978aF9863fE4c36f49b3c5623Fc2263a82F3970" },
  { team: "asa-B", addr: "0xc207b4d9200F70C8C4dE9483276feD456Ee123dB" },
  { team: "asa-C", addr: "0x28bAa9eaB6fD97860Cfb1c96993b7BF481FBa4c0" },
  { team: "asa-D", addr: "0x311E27ED45d1cbfCbda29cAee281BD26395DA0D4" },
  { team: "asa-E", addr: "0x8138F200eD6d7074B778Abe37EB58F415dEAAD0E" },
  { team: "asa-F", addr: "0x592AD2C91263c8b602A1916e68dBB7B4DDd40a1B" },

  // --- pools seen holding HAW ---
  { team: "haw-A", addr: "0x1aF015a9d6D94DD0B45Da149941A271d38978a2D" },
  { team: "haw-B", addr: "0x351763C482658Fe276fE576D74C4d676C9055163" },
  { team: "haw-C", addr: "0xE476a9Cc176c4F556Cf31aAaeaf3984f8E1FC0a1" },
  { team: "haw-D", addr: "0x800C05d0C4D661d3e6403b2A2283cc11F2Bf7594" },
  { team: "haw-E", addr: "0x71bA714C442BB03Ad949FEd31bC2cB6E7001B9Cd" },
  { team: "haw-F", addr: "0xd477581bD1ad0b98232A898cb92b608EE0A2D212" },
  { team: "haw-G", addr: "0xa153865001e2793e6E9092418ED68A30594A88d5" },

  // --- pools seen holding KOR ---
  { team: "kor-A", addr: "0xA0b176a900EF0D8aCa48ae68b67F44708ff31390" },
  { team: "kor-B", addr: "0xC6b80a957D30e2d379ECa592bDF9738E0C52EAa1" },
  { team: "kor-C", addr: "0xC211e5B66b863ffF378c5B81FdB92e608e9a5308" },
  { team: "kor-D", addr: "0x35b5D9c15CC684522C18E4f2FF9E297F76870819" },
  { team: "kor-E", addr: "0x1e534a94fE96687fbB7e72C130A9716Fd3074f57" },
  { team: "kor-F", addr: "0xe96D9760A4c0e2F4113F281a5AB0C92ad76181eC" },
  { team: "kor-G", addr: "0x6fA05B72bdC4f0DBbef1A83C4359BD151b1A5a4c" },
  { team: "kor-H", addr: "0xE8C9FDf67d0929385EcA42105361B50C80B49D45" },
  { team: "kor-dust", addr: "0xfb44f24C9133b2a314A87072657613595023C617" },
];

const TOKENS = {
  ASA: "0x31c6A9bdb16f4619C4AE66daB6909B3e8EA0f757",
  HAW: "0x79367eB28B970CaD4D667E20bA530d837014da97",
  KOR: "0x3788776dF00D6AD7FdE73D0Db289196849DC412f",
};

const INCLUDE_BYTECODE = false;     // set true once we want to reverse-engineer specific contracts
const PROBE = "10000000000000000";  // 0.01 token / 0.01 FakeETH, used for quotes

const EX_ABI = [
  "function estimateEthToProvide(uint256) view returns (uint256)",
  "function estimateERC20TokenToProvide(uint256) view returns (uint256)",
  "function estimateSwapForEth(uint256) view returns (uint256)",
  "function estimateSwapForERC20Token(uint256) view returns (uint256)",
];
const ERC20_ABI = ["function balanceOf(address) view returns (uint256)"];

(async () => {
  const E = ethers;
  const v5 = !!E.providers;
  const provider = v5 ? new E.providers.Web3Provider(web3Provider) : new E.BrowserProvider(web3Provider);
  const keccak = v5 ? E.utils.keccak256 : E.keccak256;
  const B = (x) => BigInt(x.toString());
  const f = (x) => (Number(B(x)) / 1e18).toPrecision(8);
  const probe = BigInt(PROBE);

  const net = await provider.getNetwork();
  console.log("chainId:", net.chainId.toString(), "(LuEth should be 297242)");

  const tokenC = {};
  for (const [sym, a] of Object.entries(TOKENS)) tokenC[sym] = new E.Contract(a, ERC20_ABI, provider);

  const tryCall = async (fn) => { try { return B(await fn()); } catch (e) { return "REVERT"; } };

  const results = [];
  for (const { team, addr } of EXCHANGES) {
    const r = { team, addr, flags: [] };
    try {
      const code = await provider.getCode(addr);
      r.codeSize = (code.length - 2) / 2;
      r.codeHash = code === "0x" ? null : keccak(code);
      if (INCLUDE_BYTECODE) r.bytecode = code;
      if (code === "0x") { r.flags.push("NO CODE at address"); results.push(r); continue; }

      r.eth = B(await provider.getBalance(addr));
      r.tokenBals = {};
      for (const sym of Object.keys(TOKENS)) r.tokenBals[sym] = B(await tokenC[sym].balanceOf(addr));
      const held = Object.entries(r.tokenBals).filter(([, v]) => v > 0n);
      r.pair = held.length === 1 ? held[0][0] : held.map(([s]) => s).join("+") || "NONE";
      if (held.length !== 1) r.flags.push("holds " + (held.length || "no") + " token types");
      const tok = held.length ? held.sort((a, b) => (b[1] > a[1] ? 1 : -1))[0][1] : 0n;
      r.tok = tok;

      const ex = new E.Contract(addr, EX_ABI, provider);
      r.estSwapForEth = await tryCall(() => ex.estimateSwapForEth(PROBE));
      r.estSwapForTok = await tryCall(() => ex.estimateSwapForERC20Token(PROBE));
      r.estEthToProvide = await tryCall(() => ex.estimateEthToProvide(PROBE));
      r.estTokToProvide = await tryCall(() => ex.estimateERC20TokenToProvide(PROBE));

      if (tok > 0n && r.eth > 0n) {
        r.priceEthPerTok = Number(r.eth) / Number(tok);
        // What an honest constant-product pool with these real balances would quote
        const k = r.eth * tok;
        const fairEthOut = r.eth - k / (tok + probe);
        const fairTokOut = tok - k / (r.eth + probe);
        const fairEthProv = (r.eth * probe) / tok;
        const cmp = (name, got, fair) => {
          if (got === "REVERT") { r.flags.push(name + " REVERTS"); return; }
          if (fair === 0n) return;
          const ratio = Number(got) / Number(fair);
          if (ratio > 1.01) r.flags.push(`${name} quotes ${ratio.toFixed(3)}x fair (GENEROUS?)`);
          if (ratio < 0.99) r.flags.push(`${name} quotes ${ratio.toFixed(3)}x fair (stingy / stale K?)`);
        };
        cmp("estimateSwapForEth", r.estSwapForEth, fairEthOut);
        cmp("estimateSwapForERC20Token", r.estSwapForTok, fairTokOut);
        cmp("estimateEthToProvide", r.estEthToProvide, fairEthProv);
      } else {
        r.flags.push("empty or one-sided pool");
      }
    } catch (e) {
      r.flags.push("ERROR: " + (e.message || e).toString().slice(0, 120));
    }
    results.push(r);
  }

  // Readable summary
  console.log("\n=== EXCHANGES ===");
  for (const r of results) {
    console.log(`${r.team} ${r.addr} pair=${r.pair} eth=${r.eth !== undefined ? f(r.eth) : "?"} tok=${r.tok !== undefined ? f(r.tok) : "?"} ` +
      `price(ETH/tok)=${r.priceEthPerTok ? r.priceEthPerTok.toPrecision(6) : "-"} code=${r.codeHash ? r.codeHash.slice(0, 10) : "-"} ${r.flags.join(" | ")}`);
  }

  console.log("\n=== SPREADS BY TOKEN (buy low, sell high) ===");
  for (const sym of Object.keys(TOKENS)) {
    const pools = results.filter((r) => r.pair === sym && r.priceEthPerTok).sort((a, b) => a.priceEthPerTok - b.priceEthPerTok);
    if (pools.length < 2) { console.log(sym, ": fewer than 2 live pools"); continue; }
    const lo = pools[0], hi = pools[pools.length - 1];
    console.log(`${sym}: cheapest ${lo.team} @ ${lo.priceEthPerTok.toPrecision(6)}  dearest ${hi.team} @ ${hi.priceEthPerTok.toPrecision(6)}  spread ${((hi.priceEthPerTok / lo.priceEthPerTok - 1) * 100).toFixed(1)}%`);
  }

  console.log("\n=== SHARED BYTECODE (same source) ===");
  const byHash = {};
  for (const r of results) if (r.codeHash) (byHash[r.codeHash] ||= []).push(r.team);
  for (const [h, teams] of Object.entries(byHash)) console.log(h.slice(0, 10), [...new Set(teams)].join(", "));

  const json = JSON.stringify({ when: new Date().toISOString(), results }, (k, v) => (typeof v === "bigint" ? v.toString() : v), 1);
  try { await remix.call("fileManager", "writeFile", "scan_output.json", json); console.log("\nWrote scan_output.json"); }
  catch (e) { console.log("\n(could not write file; raw JSON below)\n" + json); }
})();