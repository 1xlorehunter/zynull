import { createHash } from 'node:crypto';
import { PublicKey } from '@solana/web3.js';
import { statePda } from './program-addresses.mjs';
import { parseV9State } from './state.mjs';

const LOADER = new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111');
export const SOLANA_GENESIS_PINS = Object.freeze({
  mainnet: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
  devnet: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
});
const FIELDS = ['version', 'profileVersion', 'protocolVersion', 'stateSchema', 'network', 'rpcUrl', 'genesisHash', 'programId',
  'programSha256', 'programBytes', 'verifyingKeySha256', 'exitVerifyingKeySha256', 'ceremonyId', 'testSetup', 'auditStatus',
  'expectedUpgradeAuthority', 'releaseChannel'];
const REQUIRED = FIELDS.filter((field) => !['version', 'profileVersion', 'protocolVersion', 'stateSchema', 'expectedUpgradeAuthority', 'releaseChannel'].includes(field));
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function key(value) {
  if (typeof value !== 'string' || value.length > 44) throw new Error('Invalid production configuration public key');
  try { const parsed = new PublicKey(value); if (parsed.toBase58() !== value) throw new Error(); return parsed; }
  catch { throw new Error('Invalid production configuration public key'); }
}
function checksum(value) { if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new Error('Expected canonical artifact SHA-256'); return value; }

export function createProductionConfig(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).some((field) => !FIELDS.includes(field))
    || REQUIRED.some((field) => !Object.hasOwn(input, field))) throw new Error('Incomplete or unknown production configuration fields');
  if ((input.version ?? 1) !== 1 || (input.profileVersion ?? 1) !== 1 || (input.protocolVersion ?? 9) !== 9
    || (input.stateSchema ?? 'PSW9') !== 'PSW9') throw new Error('Unsupported SDK/profile/protocol schema');
  if (!['local', 'devnet', 'mainnet'].includes(input.network) || typeof input.testSetup !== 'boolean'
    || !['not-audited', 'in-progress', 'audited'].includes(input.auditStatus)) throw new Error('Invalid SDK network/setup/audit policy');
  if (input.network === 'mainnet' && input.testSetup) throw new Error('Mainnet refuses development/test proving setup');
  if (Object.hasOwn(input, 'releaseChannel') && !['beta', 'audited'].includes(input.releaseChannel)) throw new Error('Unknown release channel');
  if (input.releaseChannel === 'beta' && input.auditStatus !== 'not-audited') throw new Error('Beta must retain an honest not-audited status');
  if (input.network !== 'local' && input.genesisHash !== SOLANA_GENESIS_PINS[input.network]) throw new Error('Network name differs from its full pinned genesis hash');
  if (input.network === 'local' && Object.values(SOLANA_GENESIS_PINS).includes(input.genesisHash)) throw new Error('Public ledger cannot be relabeled as local');
  if (typeof input.rpcUrl !== 'string' || input.rpcUrl.length > 4096) throw new Error('Invalid configured RPC URL');
  let url; try { url = new URL(input.rpcUrl); } catch { throw new Error('Invalid configured RPC URL'); }
  if (url.username || url.password || url.hash) throw new Error('RPC userinfo/fragments are unsupported');
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  // A browser may use a same-origin loopback gateway to verified devnet.
  // Network identity still comes from its pinned genesis and loaded ELF; an
  // arbitrary plaintext remote endpoint or mainnet HTTP is never accepted.
  const devnetLoopback = input.network === 'devnet' && loopback && url.protocol === 'http:';
  if (input.network === 'local' ? (!loopback || !['http:', 'https:'].includes(url.protocol)) : url.protocol !== 'https:' && !devnetLoopback) throw new Error('RPC transport does not match configured network');
  if (!Number.isSafeInteger(input.programBytes) || input.programBytes < 64 || input.programBytes > 2 * 1024 * 1024) throw new Error('Invalid deployed ELF byte length');
  if (typeof input.ceremonyId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(input.ceremonyId)) throw new Error('Invalid proving ceremony identity');
  const authorityPin = Object.hasOwn(input, 'expectedUpgradeAuthority')
    ? { expectedUpgradeAuthority: input.expectedUpgradeAuthority === null ? null : key(input.expectedUpgradeAuthority).toBase58() } : {};
  return Object.freeze({ version: 1, profileVersion: 1, protocolVersion: 9, stateSchema: 'PSW9', network: input.network,
    rpcUrl: url.href, genesisHash: key(input.genesisHash).toBase58(), programId: key(input.programId).toBase58(),
    programSha256: checksum(input.programSha256), programBytes: input.programBytes,
    verifyingKeySha256: checksum(input.verifyingKeySha256), exitVerifyingKeySha256: checksum(input.exitVerifyingKeySha256),
    ceremonyId: input.ceremonyId, testSetup: input.testSetup, auditStatus: input.auditStatus, ...authorityPin,
    ...(Object.hasOwn(input, 'releaseChannel') ? { releaseChannel: input.releaseChannel } : {}) });
}
// Scope deliberately excludes the RPC URL, which can contain a provider API
// credential and may change without changing this ledger or wallet identity.
export function productionWalletScope(config) {
  const valid = createProductionConfig(config), { rpcUrl, ...scope } = valid; return Object.freeze(scope);
}
export function productionScopeDigest(config) { return sha(JSON.stringify(productionWalletScope(config))); }
export function assertSameProductionScope(config, scope) {
  if (!scope || typeof scope !== 'object' || Array.isArray(scope)) throw new Error('Invalid wallet scope');
  const expected = productionWalletScope(config);
  if (Object.keys(scope).length !== Object.keys(expected).length || Object.keys(scope).some((field) => !Object.hasOwn(expected, field))
    || Object.keys(expected).some((field) => scope[field] !== expected[field])) throw new Error('Wallet ledger/program/artifact/ceremony scope mismatch');
  return expected;
}
export function assertProductionReleaseReady(config) {
  const valid = createProductionConfig(config);
  if (valid.network !== 'mainnet' || valid.testSetup || valid.auditStatus !== 'audited' || valid.releaseChannel === 'beta') throw new Error('Production release requires mainnet, production ceremony and completed independent audit');
  // This validates configured policy claims, not the truth of a ceremony or
  // audit. Authentic release evidence must be independently reviewed/pinned.
  return valid;
}
// This is a separate, explicitly unaudited channel. Artifact/ceremony truth is
// established by beta-release-evidence, never these configuration fields alone.
export function assertMainnetReleasePolicy(config) {
  const valid = createProductionConfig(config);
  if (valid.releaseChannel !== 'beta') return assertProductionReleaseReady(valid);
  if (valid.network !== 'mainnet' || valid.testSetup || valid.auditStatus !== 'not-audited') throw new Error('Mainnet beta requires fresh non-test parameters and an honest unaudited status');
  return valid;
}
export function assertProductionArtifactsMatch(config, { normalVkBytes, exitVkBytes }) {
  const valid = createProductionConfig(config);
  if (!(normalVkBytes instanceof Uint8Array) || !(exitVkBytes instanceof Uint8Array)
    || sha(normalVkBytes) !== valid.verifyingKeySha256 || sha(exitVkBytes) !== valid.exitVerifyingKeySha256) throw new Error('Verifying key files differ from pinned release configuration');
  return true;
}
// Reads only general program/state accounts. A trusted RPC remains required;
// these checks are not Solana consensus/light-client inclusion verification.
export async function assertRpcMatchesProductionConfig(connection, config, { requireState = true } = {}) {
  const valid = createProductionConfig(config);
  if (typeof connection?.rpcEndpoint !== 'string' || new URL(connection.rpcEndpoint).href !== valid.rpcUrl) throw new Error('RPC endpoint differs from configured connection');
  if (await connection.getGenesisHash() !== valid.genesisHash) throw new Error('RPC ledger genesis differs from pinned network');
  const program = new PublicKey(valid.programId), account = await connection.getAccountInfo(program, 'confirmed');
  if (!account?.executable || !account.owner.equals(LOADER) || account.data.length !== 36 || account.data.readUInt32LE(0) !== 2) throw new Error('Expected pinned executable upgradeable program');
  const address = new PublicKey(account.data.subarray(4)), dataAccount = await connection.getAccountInfo(address, 'confirmed');
  if (!dataAccount || dataAccount.executable || !dataAccount.owner.equals(LOADER) || dataAccount.data.length < 45 + valid.programBytes
    || dataAccount.data.readUInt32LE(0) !== 3 || ![0, 1].includes(dataAccount.data[12])) throw new Error('Invalid deployed ProgramData metadata');
  const code = dataAccount.data.subarray(45, 45 + valid.programBytes);
  if (!code.subarray(0, 4).equals(Buffer.from([127, 69, 76, 70])) || sha(code) !== valid.programSha256
    || !dataAccount.data.subarray(45 + valid.programBytes).every((byte) => byte === 0)) throw new Error('Deployed program bytes differ from pinned release');
  const observedAuthority = dataAccount.data[12] === 1 ? new PublicKey(dataAccount.data.subarray(13, 45)).toBase58() : null;
  if (Object.hasOwn(valid, 'expectedUpgradeAuthority') && observedAuthority !== valid.expectedUpgradeAuthority) throw new Error('Deployed upgrade authority differs from the reviewed release authority');
  let initialized = false, count = null;
  if (requireState) {
    const state = await connection.getAccountInfo(statePda(program), 'confirmed');
    if (!state || state.executable || !state.owner.equals(program)) throw new Error('Protocol state is absent or belongs to another program');
    const parsed = parseV9State(state.data);
    if (parsed.bump !== PublicKey.findProgramAddressSync([Buffer.from('state')], program)[1]) throw new Error('Protocol state bump differs from canonical PDA');
    initialized = true; count = parsed.count;
  }
  return Object.freeze({ genesisMatched: true, programMatched: true, deployedCodeHashMatched: true, initialized, count,
    upgradeAuthority: observedAuthority,
    rpcTrusted: true, lightClientInclusionVerified: false });
}
