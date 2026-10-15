# Zynull Protocol

Current Solana privacy program, NORMAL and EXIT proof circuits, and JavaScript
SDK. Includes SOL and legacy SPL operations, encrypted notes, recovery, Merkle
indexing and relay transaction handling.

Experimental and unaudited. Public deposits and withdrawals remain visible.
The included verification keys belong to a single-operator beta setup with no
independent phase-2 participant. Timing and network metadata can limit privacy.

## Requirements

Node.js 24, pnpm 11.25.0, and Rust/Agave with SBF support. The reference compiler
was Agave 4.3.0. Install toolchains separately.

```sh
pnpm install --frozen-lockfile
pnpm run build:normal
pnpm run build:exit
pnpm run build:program
```

Circuit outputs are written to `build/`. The program is written to
`build/zynull.so`. Program compilation pins both included verification keys by
SHA256 and preserves the production-candidate checks against development keys.
Build commands do not deploy, sign or submit transactions.

## SDK

```js
import { buildShieldedCore, Wallet, Relayer } from './src/index.mjs';
```

`src/wallet.mjs` implements private balances, proof preparation, operations,
recovery and relay submission. `src/instructions.mjs`, `state.mjs` and
`notes.mjs` define the current encoding. `account-addresses.mjs` contains shared
PDA and lane helpers required by that encoding.

Supply compatible NORMAL/EXIT proving keys and witness WASM when constructing
the SDK. Proving keys, witnesses, setup entropy, user wallets and private
operator state are not included. Independent ceremony and audit requirements
remain separate from compilation. Mainnet writes require explicit approval of
the exact transaction and debit cap through `src/mainnet-spending.mjs`.

Protocol domain strings, on-chain discriminators and data format constants
retain their established values for compatibility. There is one current
implementation in this directory.

## License

Project-authored source is GPL-3.0-only. See `LICENSE` for the complete license
and dependency attribution. Preserve upstream copyright and license notices.
