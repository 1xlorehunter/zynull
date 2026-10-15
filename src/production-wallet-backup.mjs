import { randomBytes, createHash, hkdfSync, createCipheriv, createDecipheriv } from 'node:crypto';
import { Keypair } from '@solana/web3.js';
import { exportV9WalletBackup, restoreV9WalletBackup } from './wallet.mjs';
import { createProductionConfig, productionWalletScope, assertSameProductionScope } from './production-config.mjs';
import { createPrivacyProfileAddress, parsePrivacyProfileAddress } from './privacy-profile-address.mjs';
import { validatePrivacyProfileCatalog, emptyPrivacyProfileCatalog } from './diversified-privacy-profiles.mjs';

export const PRODUCTION_WALLET_BACKUP_VERSION = 1;
export const PRODUCTION_WALLET_BACKUP_MAX_BYTES = 16384;
const FORMAT = 'privacy-user-owned-wallet-backup';
const DOCUMENT_FIELDS = ['format', 'version', 'scope', 'privacyAddress', 'encryptedSeed'];
const CATALOG_FIELDS = ['version', 'iv', 'tag', 'ciphertext'];
const knownCatalogs = new WeakMap();
function rememberCatalog(keypair, address, value) {
  const next = validatePrivacyProfileCatalog(value);
  let map = knownCatalogs.get(keypair);
  if (!map) { map = new Map(); knownCatalogs.set(keypair, map); }
  const old = map.get(address);
  const catalog = old ? validatePrivacyProfileCatalog({ version: 1, contactCount: Math.max(old.contactCount, next.contactCount),
    invoiceCount: Math.max(old.invoiceCount, next.invoiceCount) }) : next;
  map.set(address, catalog);
  if (!Object.hasOwn(keypair, 'privacyProfileCatalog')) Object.defineProperty(keypair, 'privacyProfileCatalog', {
    get: () => knownCatalogs.get(keypair)?.get(address), enumerable: false });
  return catalog;
}
const ENCRYPTED_FIELDS = ['version', 'programId', 'kdf', 'salt', 'iv', 'tag', 'ciphertext'];
const IDENTITY_SCOPE_FIELDS = ['version', 'profileVersion', 'protocolVersion', 'stateSchema', 'network', 'genesisHash', 'programId',
  'verifyingKeySha256', 'exitVerifyingKeySha256', 'ceremonyId', 'testSetup'];
function exact(document, fields) {
  if (!document || typeof document !== 'object' || Array.isArray(document) || Object.keys(document).length !== fields.length
    || fields.some((field) => !Object.hasOwn(document, field)) || Object.keys(document).some((field) => !fields.includes(field))) throw new Error('Invalid encrypted wallet backup schema');
}
function base64(value, size, max = size) {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4) throw new Error('Invalid encrypted wallet backup encoding');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value || (size !== null && bytes.length !== size) || bytes.length > max) throw new Error('Invalid encrypted wallet backup encoding');
}
function documentObject(value) {
  if (typeof value === 'string') { if (Buffer.byteLength(value) > PRODUCTION_WALLET_BACKUP_MAX_BYTES) throw new Error('Encrypted backup exceeds limit');
    try { value = JSON.parse(value); } catch { throw new Error('Invalid encrypted wallet backup JSON'); } }
  let bytes; try { bytes = Buffer.byteLength(JSON.stringify(value)); } catch { throw new Error('Invalid encrypted wallet backup JSON'); }
  if (bytes > PRODUCTION_WALLET_BACKUP_MAX_BYTES) throw new Error('Encrypted backup exceeds limit');
  exact(value, value?.version === 2 ? [...DOCUMENT_FIELDS, 'encryptedProfileCatalog'] : DOCUMENT_FIELDS);
  if (value.format !== FORMAT || ![1, 2].includes(value.version) || typeof value.privacyAddress !== 'string') throw new Error('Unsupported encrypted wallet backup version');
  exact(value.encryptedSeed, ENCRYPTED_FIELDS);
  const enc = value.encryptedSeed;
  if (enc.version !== 1 || enc.kdf !== 'scrypt-32768-8-1' || typeof enc.programId !== 'string') throw new Error('Unsupported encrypted wallet backup KDF/version');
  base64(enc.salt, 16); base64(enc.iv, 12); base64(enc.tag, 16); base64(enc.ciphertext, null, 4096);
  if (value.version === 2) {
    exact(value.encryptedProfileCatalog, CATALOG_FIELDS);
    if (value.encryptedProfileCatalog.version !== 1) throw new Error('Unsupported private profile catalog');
    base64(value.encryptedProfileCatalog.iv, 12); base64(value.encryptedProfileCatalog.tag, 16); base64(value.encryptedProfileCatalog.ciphertext, 64);
  }
  return value;
}
function context(config, privacyAddress, version = 1) {
  // Existing V9 backup helpers authenticate this context string. Its digest
  // includes every public scope field and the signed privacy address, so outer
  // metadata cannot be relabeled without failing AES-GCM authentication.
  return `privacy-sdk-wallet-backup-v${version}:` + createHash('sha256').update(JSON.stringify({ scope: productionWalletScope(config), privacyAddress })).digest('hex');
}
function catalogKey(keypair, binding) {
  const seed = Buffer.from(keypair.secretKey.subarray(0, 32));
  try { return Buffer.from(hkdfSync('sha256', seed, createHash('sha256').update(binding).digest(), Buffer.from('privacy-wallet-profile-catalog-v1'), 32)); }
  finally { seed.fill(0); }
}
function encryptCatalog(keypair, binding, value) {
  const catalog = validatePrivacyProfileCatalog(value), serialized = Buffer.from(JSON.stringify(catalog));
  if (serialized.length >= 64) throw new Error('Private profile catalog exceeds fixed envelope');
  const plain = Buffer.alloc(64), key = catalogKey(keypair, binding), iv = randomBytes(12);
  serialized.copy(plain);
  try {
    const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(binding));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return { version: 1, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
  } finally { serialized.fill(0); plain.fill(0); key.fill(0); }
}
function decryptCatalog(keypair, binding, document) {
  const key = catalogKey(keypair, binding); let plain;
  try {
    const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(document.iv, 'base64'));
    cipher.setAAD(Buffer.from(binding)); cipher.setAuthTag(Buffer.from(document.tag, 'base64'));
    plain = Buffer.concat([cipher.update(Buffer.from(document.ciphertext, 'base64')), cipher.final()]);
    const end = plain.indexOf(0);
    if (plain.length !== 64 || end < 0 || plain.subarray(end).some((byte) => byte !== 0)) throw new Error('Invalid private profile catalog padding');
    return validatePrivacyProfileCatalog(JSON.parse(plain.subarray(0, end).toString('utf8')));
  } finally { key.fill(0); plain?.fill(0); }
}
export function createProductionWalletIdentity() {
  const entropy = randomBytes(32);
  try { return Keypair.fromSeed(entropy); } finally { entropy.fill(0); }
}
export function exportProductionWalletBackup(keypair, config, passphrase, { core, privacyAddress, profileCatalog } = {}) {
  const valid = createProductionConfig(config); if (!core) throw new Error('Shielded core is required to verify the backup identity');
  const actualAddress = createPrivacyProfileAddress(core, keypair, valid.programId, { genesisHash: valid.genesisHash });
  if (privacyAddress !== undefined && privacyAddress !== actualAddress) throw new Error('Privacy address does not belong to this local identity');
  // An unlocked V2 backup carries its authenticated issuance metadata. Avoid
  // silently dropping funded child profiles when a caller re-exports it.
  const known = knownCatalogs.get(keypair)?.get(actualAddress);
  if (profileCatalog === undefined) profileCatalog = known;
  if (known && profileCatalog) {
    const old = known, next = validatePrivacyProfileCatalog(profileCatalog);
    if (next.contactCount < old.contactCount || next.invoiceCount < old.invoiceCount) throw new Error('Private profile catalog cannot forget issued addresses');
  }
  const version = profileCatalog === undefined ? 1 : 2, binding = context(valid, actualAddress, version);
  const result = { format: FORMAT, version, scope: productionWalletScope(valid), privacyAddress: actualAddress,
    encryptedSeed: exportV9WalletBackup(keypair, binding, passphrase),
    ...(version === 2 ? { encryptedProfileCatalog: encryptCatalog(keypair, binding, profileCatalog) } : {}) };
  if (version === 2) rememberCatalog(keypair, actualAddress, profileCatalog);
  return result;
}
export function restoreProductionWalletBackup(value, config, passphrase, { core, expectedAddress } = {}) {
  const valid = createProductionConfig(config), document = documentObject(value);
  if (!core) throw new Error('Shielded core is required to verify the restored identity');
  assertSameProductionScope(valid, document.scope);
  parsePrivacyProfileAddress(document.privacyAddress, { programId: valid.programId, genesisHash: valid.genesisHash });
  if (expectedAddress !== undefined && document.privacyAddress !== expectedAddress) throw new Error('Encrypted backup belongs to another privacy identity');
  const binding = context(valid, document.privacyAddress, document.version);
  if (document.encryptedSeed.programId !== binding) throw new Error('Encrypted backup scope authentication context mismatch');
  let keypair;
  try { keypair = restoreV9WalletBackup(document.encryptedSeed, binding, passphrase); }
  catch { throw new Error('Unable to unlock encrypted backup: wrong password or changed encrypted data'); }
  if (createPrivacyProfileAddress(core, keypair, valid.programId, { genesisHash: valid.genesisHash }) !== document.privacyAddress) throw new Error('Decrypted key does not match the signed privacy identity');
  if (document.version === 2) rememberCatalog(keypair, document.privacyAddress, decryptCatalog(keypair, binding, document.encryptedProfileCatalog));
  return keypair;
}
export function readProductionWalletProfileCatalog(value, config, keypair, { core } = {}) {
  const valid = createProductionConfig(config), document = documentObject(value);
  assertSameProductionScope(valid, document.scope);
  if (!core || createPrivacyProfileAddress(core, keypair, valid.programId, { genesisHash: valid.genesisHash }) !== document.privacyAddress) throw new Error('Private profile catalog belongs to another identity');
  const binding = context(valid, document.privacyAddress, document.version);
  if (document.encryptedSeed.programId !== binding) throw new Error('Encrypted backup scope authentication context mismatch');
  if (document.version === 1) return emptyPrivacyProfileCatalog();
  const catalog = decryptCatalog(keypair, binding, document.encryptedProfileCatalog);
  rememberCatalog(keypair, document.privacyAddress, catalog); return catalog;
}
export function updateProductionWalletProfileCatalog(value, config, keypair, catalog, { core } = {}) {
  const valid = createProductionConfig(config), document = documentObject(value);
  const old = readProductionWalletProfileCatalog(document, valid, keypair, { core });
  if (document.version !== 2) throw new Error('Upgrade the encrypted backup before adding private profiles');
  const next = validatePrivacyProfileCatalog(catalog);
  if (next.contactCount < old.contactCount || next.invoiceCount < old.invoiceCount) throw new Error('Private profile catalog cannot forget issued addresses');
  const known = knownCatalogs.get(keypair)?.get(document.privacyAddress);
  if (known && (next.contactCount < known.contactCount || next.invoiceCount < known.invoiceCount)) throw new Error('Private profile catalog cannot forget issued addresses');
  const result = { ...document, encryptedProfileCatalog: encryptCatalog(keypair, context(valid, document.privacyAddress, 2), next) };
  rememberCatalog(keypair, document.privacyAddress, next); return result;
}
export function migrateProductionWalletBackup(value, newConfig, passphrase, { core, expectedAddress, newPassphrase = passphrase } = {}) {
  const current = createProductionConfig(newConfig), document = documentObject(value);
  const replacementScope = productionWalletScope(current);
  for (const field of IDENTITY_SCOPE_FIELDS) if (document.scope?.[field] !== replacementScope[field]) throw new Error('Backup migration refuses changed ledger/program/profile/ceremony/verifying keys');
  // The original authenticated metadata is preserved and validated explicitly.
  // The replacement RPC is a transport detail, not a new ledger identity.
  const original = createProductionConfig({ ...document.scope, rpcUrl: current.rpcUrl });
  const keypair = restoreProductionWalletBackup(document, original, passphrase, { core, expectedAddress });
  const backup = exportProductionWalletBackup(keypair, current, newPassphrase, { core, privacyAddress: document.privacyAddress,
    ...(document.version === 2 ? { profileCatalog: keypair.privacyProfileCatalog } : {}) });
  const changedFields = ['programSha256', 'programBytes', 'auditStatus'].filter((field) => original[field] !== current[field]);
  const result = { backup, privacyAddress: document.privacyAddress, changedFields, requiresReviewedCompatibleCode: true };
  // Explicit local callers can retain the unlocked handle; ordinary JSON/API
  // serialization cannot accidentally include its raw seed bytes.
  Object.defineProperty(result, 'keypair', { value: keypair, enumerable: false });
  return Object.freeze(result);
}
