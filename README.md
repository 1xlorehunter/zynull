# Zynull

Private SOL and legacy SPL operations on Solana. This repository contains the
Solana program, proof circuits, client SDK, browser interface and tests.

[Website](https://zynull.xyz) · [X](https://x.com/zynullxyz)

Experimental, unaudited beta. Public deposits and withdrawals remain visible.
Timing, amounts, network metadata and a small anonymity population can limit
privacy. The beta proof setup has one operator and no independent phase-2
participant. Development proof keys must never secure real funds.

## Install and test

Use Node.js 24 and pnpm 11.25.0.

```sh
pnpm install --frozen-lockfile
pnpm --dir web-private-sol install --frozen-lockfile
node PREPARE_PUBLIC_PARAMETERS.mjs
pnpm test
pnpm --dir web-private-sol test
pnpm --dir web-private-sol build
```

The website build is written to `web-private-sol/dist/`. Serve that directory
over HTTPS and configure your own verified protocol gateway. Building the
website does not deploy a Solana program or start a relay.

Tests use synthetic identities and mocked chain access. Three optional
integration cases require separately supplied proving artifacts or archived
signed proofs and are skipped when those inputs are absent.

## Build the program and circuits

Install the Rust/Agave toolchain separately. The reference SBF build used Agave
4.3.0.

```sh
pnpm run circuit:build:v9
pnpm run circuit:build:exit
pnpm run circuit:test:v9
pnpm run circuit:test:exit
bash TEST_PROGRAM.sh
bash BUILD_PROGRAM.sh
```

`PREPARE_PUBLIC_PARAMETERS.mjs` copies only public development verification keys
and a synthetic size fixture. `scripts/setup-dev-proof.mjs` creates disposable
proving parameters for local/devnet tests; it is not a production ceremony.

The separate beta verifier uses `public-parameters/beta/normal-vk.json` and
`public-parameters/beta/exit-vk.json`. To rebuild it with those exact keys:

```sh
bash scripts/build-production-candidate.sh public-parameters/beta/normal-vk.json 1ab39ab86cf3522fbc9e9fb885b247430d0e6b8aa2682c06b368857516db1fdd public-parameters/beta/exit-vk.json 8be9e693ff1f8ec2e9e76c0c5a751646e30998ec597d777ced40b14b7e365f15 build/beta-rebuild
```

The reference beta ELF is 70,992 bytes with SHA256
`cef60d93bcc4b13ca57d3128e46baf3ad56cf0470a98616fdefbcce6e85e88fd`.
A different compiler or toolchain may produce different bytes. Rebuilding a
verifier does not establish that an on-chain deployment matches it.

## Source layout

- `program-size-experiment/`: Solana program. The directory name is historical.
- `circuits/`: NORMAL and EXIT proof relations.
- `src/`: SDK, note encryption, verification and relay code.
- `web-private-sol/`: Browser interface and wallet integration.
- `scripts/`: Build, test and release validation commands.
- `test/`: Protocol and service tests.

Mainnet launchers require exact release evidence and explicit runtime settings.
Their default behavior does not spend SOL. Every paid stage requires human
approval of its actions and limit. Private keys, user histories, operator
panels and deployment journals are not part of this repository.

## License

Project-authored source is GPL-3.0-only. See `LICENSE` for the license text and
dependency attribution. Font licenses are included beside the font files.
Existing upstream copyright and license notices must be preserved.
