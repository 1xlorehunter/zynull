import { hkdfSync } from 'node:crypto';
import { Keypair, PublicKey } from '@solana/web3.js';
import { deriveShieldedProfile } from './shielded-profile.mjs';
import { createPrivacyProfileAddress, parsePrivacyProfileAddress } from './privacy-profile-address.mjs';

export const DIVERSIFIED_PRIVACY_PROFILE_VERSION = 1;
export const DIVERSIFIED_PRIVACY_PROFILE_MAX_INDEX = 0xffffffff;
export const DIVERSIFIED_PRIVACY_PROFILE_KINDS = Object.freeze(['contact', 'invoice']);
export const PRIVACY_PROFILE_CATALOG_VERSION = 1;
export const PRIVACY_PROFILE_CATALOG_MAX_PROFILES = 64;
const DOMAIN = Buffer.from('privacy-solana-diversified-identity-v1\0', 'utf8');
const SCOPE_FIELDS = ['programId', 'genesisHash', 'index', 'kind'];
const KIND_CODES = Object.freeze({ contact: 1, invoice: 2 });

export function validatePrivacyProfileCatalog(catalog) {
  const fields = ['version', 'contactCount', 'invoiceCount'];
  if (!catalog || typeof catalog !== 'object' || Array.isArray(catalog)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(catalog))) throw new Error('Invalid private profile catalog schema');
  const names = Object.getOwnPropertyNames(catalog), descriptors = Object.getOwnPropertyDescriptors(catalog);
  if (Object.getOwnPropertySymbols(catalog).length || names.length !== fields.length
    || names.some((name) => !fields.includes(name))
    || fields.some((name) => !Object.hasOwn(catalog, name) || !Object.hasOwn(descriptors[name], 'value') || !descriptors[name].enumerable)) {
    throw new Error('Private profile catalog requires exactly version, contactCount and invoiceCount');
  }
  if (catalog.version !== PRIVACY_PROFILE_CATALOG_VERSION) throw new Error('Unsupported private profile catalog version');
  for (const name of ['contactCount', 'invoiceCount']) {
    if (!Number.isInteger(catalog[name]) || Object.is(catalog[name], -0) || catalog[name] < 0
      || catalog[name] > PRIVACY_PROFILE_CATALOG_MAX_PROFILES) throw new Error('Private profile catalog count must be an integer from 0 to 64');
  }
  if (catalog.contactCount + catalog.invoiceCount > PRIVACY_PROFILE_CATALOG_MAX_PROFILES) throw new Error('Private profile catalog exceeds 64 active profiles');
  return Object.freeze({ version: PRIVACY_PROFILE_CATALOG_VERSION, contactCount: catalog.contactCount, invoiceCount: catalog.invoiceCount });
}

export function emptyPrivacyProfileCatalog() {
  return validatePrivacyProfileCatalog({ version: PRIVACY_PROFILE_CATALOG_VERSION, contactCount: 0, invoiceCount: 0 });
}

function pinnedKey(value) {
  if (!(typeof value === 'string' || value instanceof PublicKey)) throw new Error('Expected a canonical program/genesis public key');
  try {
    const key = new PublicKey(value);
    if (typeof value === 'string' && key.toBase58() !== value) throw new Error();
    return key;
  } catch { throw new Error('Expected a canonical program/genesis public key'); }
}

function validatedRootEntropy(rootIdentity) {
  if (!(rootIdentity instanceof Keypair)) throw new Error('Expected a local private root Keypair');
  let entropy;
  try {
    entropy = rootIdentity.secretKey;
    if (!(entropy instanceof Uint8Array) || entropy.length !== 64
      || !Keypair.fromSecretKey(entropy).publicKey.equals(rootIdentity.publicKey)) throw new Error();
    return entropy;
  } catch {
    entropy?.fill(0);
    throw new Error('Invalid local private root Keypair');
  }
}

function derivationScope(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(options))) throw new Error('Invalid diversified profile scope');
  const names = Object.getOwnPropertyNames(options), descriptors = Object.getOwnPropertyDescriptors(options);
  if (Object.getOwnPropertySymbols(options).length || names.length !== SCOPE_FIELDS.length
    || names.some((name) => !SCOPE_FIELDS.includes(name))
    || SCOPE_FIELDS.some((name) => !Object.hasOwn(options, name) || !Object.hasOwn(descriptors[name], 'value'))) {
    throw new Error('Diversified profile requires exactly programId, genesisHash, index and kind');
  }
  if (!Number.isInteger(options.index) || Object.is(options.index, -0)
    || options.index < 0 || options.index > DIVERSIFIED_PRIVACY_PROFILE_MAX_INDEX) throw new Error('Diversified profile index must be an unsigned 32-bit integer');
  if (typeof options.kind !== 'string' || !DIVERSIFIED_PRIVACY_PROFILE_KINDS.includes(options.kind)) throw new Error('Diversified profile kind must be contact or invoice');
  return { program: pinnedKey(options.programId), genesis: pinnedKey(options.genesisHash), index: options.index, kind: options.kind };
}

// A private root, never a wallet signMessage result, deterministically derives
// the entire child identity. In particular, owner, view and profile signer all
// change together; reusing the root profile signer would link issued addresses.
// Derivation v1: HKDF-SHA256(root seed, program || genesis,
// domain || uint8(kind) || uint32be(index), 32).
export function deriveDiversifiedPrivacyProfile(core, rootIdentity, options) {
  const scope = derivationScope(options);
  if (!core || typeof core.ownerPublic !== 'function') throw new Error('Shielded core is required for diversified profiles');
  let rootEntropy, childSeed, childEntropy;
  try {
    // The SDK Keypair constructor also accepts unchecked malformed objects.
    // Verify the supplied root contains a self-consistent Ed25519 keypair.
    rootEntropy = validatedRootEntropy(rootIdentity);
    const index = Buffer.alloc(4); index.writeUInt32BE(scope.index);
    childSeed = Buffer.from(hkdfSync('sha256', rootEntropy.subarray(0, 32),
      Buffer.concat([scope.program.toBuffer(), scope.genesis.toBuffer()]),
      Buffer.concat([DOMAIN, Buffer.from([KIND_CODES[scope.kind]]), index]), 32));
    const keypair = Keypair.fromSeed(childSeed);
    const privacyAddress = createPrivacyProfileAddress(core, keypair, scope.program, { genesisHash: scope.genesis });
    const recipient = parsePrivacyProfileAddress(privacyAddress, { programId: scope.program, genesisHash: scope.genesis });
    childEntropy = keypair.secretKey;
    const profile = Object.freeze(deriveShieldedProfile(core, { secretKey: childEntropy }, scope.program));
    const result = {
      derivationVersion: DIVERSIFIED_PRIVACY_PROFILE_VERSION,
      privacyAddress,
      programId: scope.program.toBase58(),
      genesisHash: scope.genesis.toBase58(),
    };
    // Explicit local callers use these handles for note scanning/spending.
    // Ordinary JSON, object spreading and API responses contain only public
    // data. There is no root key, index, kind or master public key in PSA1.
    Object.defineProperties(result, {
      keypair: { value: keypair, enumerable: false },
      profile: { value: profile, enumerable: false },
      recipient: { value: recipient, enumerable: false },
    });
    return Object.freeze(result);
  } finally {
    rootEntropy?.fill(0); childSeed?.fill(0); childEntropy?.fill(0);
  }
}

// Counts are private backup metadata. Each namespace has a contiguous issuance
// range 0..count-1; order here is contacts first, then invoices. The limit keeps
// the current full-history trial scan bounded and is not a protocol limit.
export function buildDiversifiedPrivacyProfiles(core, rootIdentity, ledgerScope, catalog) {
  const valid = validatePrivacyProfileCatalog(catalog);
  if (!ledgerScope || typeof ledgerScope !== 'object' || Array.isArray(ledgerScope)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(ledgerScope))) throw new Error('Invalid diversified profile ledger scope');
  const names = Object.getOwnPropertyNames(ledgerScope), descriptors = Object.getOwnPropertyDescriptors(ledgerScope);
  if (Object.getOwnPropertySymbols(ledgerScope).length || names.length !== 2
    || names.some((name) => !['programId', 'genesisHash'].includes(name))
    || ['programId', 'genesisHash'].some((name) => !Object.hasOwn(ledgerScope, name) || !Object.hasOwn(descriptors[name], 'value'))) {
    throw new Error('Diversified profile ledger scope requires exactly programId and genesisHash');
  }
  const programId = pinnedKey(ledgerScope.programId), genesisHash = pinnedKey(ledgerScope.genesisHash);
  // Validate even an empty catalogue, rather than accepting a malformed root
  // or scope only because no derivations happen to be requested yet.
  if (!core || typeof core.ownerPublic !== 'function') throw new Error('Shielded core is required for diversified profiles');
  const checkedEntropy = validatedRootEntropy(rootIdentity); checkedEntropy.fill(0);
  const children = [];
  for (const kind of DIVERSIFIED_PRIVACY_PROFILE_KINDS) {
    const count = kind === 'contact' ? valid.contactCount : valid.invoiceCount;
    for (let index = 0; index < count; index++) children.push(deriveDiversifiedPrivacyProfile(core, rootIdentity, { programId, genesisHash, kind, index }));
  }
  return Object.freeze(children);
}

// This prevents direct stable-key comparison of independently issued profiles;
// it is not a proof of protocol unlinkability. Reusing a profile still links
// disclosures. Active tagging, public funding/withdrawals, timing/amounts,
// network metadata and a compromised root remain separate risks. Current V9
// delivery has no discovery tags: trial scanning P profiles against H history
// records costs O(P * H), and the private issuance catalogue must be backed up.
// Clearing temporary arrays does not erase KeyObject/SDK/JavaScript copies.
