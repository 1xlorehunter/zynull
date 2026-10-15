import { createHash, hkdfSync, createPrivateKey, createPublicKey, diffieHellman, sign, verify } from 'node:crypto';
import { PublicKey } from '@solana/web3.js';
import { deriveShieldedProfile } from './shielded-profile.mjs';

export const PRIVACY_PROFILE_ADDRESS_PREFIX = 'psol1_';
export const PRIVACY_PROFILE_ADDRESS_VERSION = 1;
export const PRIVACY_PROFILE_ADDRESS_BYTES = 237;
const BODY_BYTES = 165, SIGNATURE_BYTES = 64, CHECKSUM_BYTES = 8;
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ED_PRIVATE = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED_PUBLIC = Buffer.from('302a300506032b6570032100', 'hex');
const X_PRIVATE = Buffer.from('302e020100300506032b656e04220420', 'hex');
const X_PUBLIC = Buffer.from('302a300506032b656e032100', 'hex');
const SIGN_DOMAIN = Buffer.from('privacy-solana-profile-address-v1');
const checksum = (bytes) => createHash('sha256').update(bytes).digest().subarray(0, CHECKSUM_BYTES);
function field(value) { const n = BigInt(value); if (n <= 0n || n >= FR) throw new Error('Invalid privacy owner field'); return n; }
const be32 = (n) => Buffer.from(field(n).toString(16).padStart(64, '0'), 'hex');
function scopeKey(value) { try { const key = new PublicKey(value); if (typeof value === 'string' && key.toBase58() !== value) throw new Error(); return key; }
  catch { throw new Error('Invalid privacy address program/genesis identity'); } }
function viewBytes(value) {
  if (typeof value !== 'string') throw new Error('Invalid privacy view key'); const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 44 || bytes.toString('base64') !== value || !bytes.subarray(0, 12).equals(X_PUBLIC)) throw new Error('Invalid privacy X25519 view key encoding');
  return bytes.subarray(12);
}
function validateViewPoint(raw) {
  const coordinate = BigInt('0x' + Buffer.from(raw).reverse().toString('hex'));
  if (coordinate >= (1n << 255n) - 19n) throw new Error('Noncanonical privacy X25519 coordinate');
  const testPrivate = createPrivateKey({ key: Buffer.concat([X_PRIVATE, Buffer.alloc(32, 66)]), type: 'pkcs8', format: 'der' });
  const pub = createPublicKey({ key: Buffer.concat([X_PUBLIC, raw]), type: 'spki', format: 'der' });
  let shared;
  try { shared = diffieHellman({ privateKey: testPrivate, publicKey: pub }); if (shared.every((byte) => byte === 0)) throw new Error('Invalid low-order privacy X25519 point'); }
  catch { throw new Error('Invalid low-order privacy X25519 point'); }
  finally { shared?.fill(0); }
}

// The signing identity is private-entropy derived and distinct from the
// funding/public wallet key. This signature proves control of its signing key;
// it does not provide a zero-knowledge ownership proof for arbitrary fields.
export function createPrivacyProfileAddress(core, identityKeypair, programId, { genesisHash } = {}) {
  if (!genesisHash || !identityKeypair?.secretKey) throw new Error('Private identity entropy and pinned genesis are required');
  const program = scopeKey(programId), genesis = scopeKey(genesisHash), entropy = identityKeypair.secretKey;
  if (!(entropy instanceof Uint8Array) || entropy.length !== 64) throw new Error('Expected local identity keypair');
  let signingSeed, privateDer;
  try {
    const identity = deriveShieldedProfile(core, { secretKey: entropy }, program), rawView = viewBytes(identity.viewPublicKey);
    validateViewPoint(rawView);
    signingSeed = Buffer.from(hkdfSync('sha256', entropy.subarray(0, 32), Buffer.concat([program.toBuffer(), genesis.toBuffer()]),
      Buffer.from('privacy-solana-profile-signing-v1'), 32));
    privateDer = Buffer.concat([ED_PRIVATE, signingSeed]); const privateKey = createPrivateKey({ key: privateDer, type: 'pkcs8', format: 'der' });
    const signer = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).subarray(12);
    const body = Buffer.concat([Buffer.from('PSA1'), Buffer.from([1]), genesis.toBuffer(), program.toBuffer(), be32(identity.ownerPub), rawView, signer]);
    const signature = sign(null, Buffer.concat([SIGN_DOMAIN, body]), privateKey), signed = Buffer.concat([body, signature]);
    return PRIVACY_PROFILE_ADDRESS_PREFIX + Buffer.concat([signed, checksum(signed)]).toString('base64url');
  } finally { entropy.fill(0); signingSeed?.fill(0); privateDer?.fill(0); }
}
export function parsePrivacyProfileAddress(address, { programId, genesisHash } = {}) {
  if (!programId || !genesisHash) throw new Error('Pin program and genesis before importing a privacy address');
  if (typeof address !== 'string' || address.length > 512 || !address.startsWith(PRIVACY_PROFILE_ADDRESS_PREFIX)) throw new Error('Invalid privacy address prefix/length');
  const encoded = address.slice(PRIVACY_PROFILE_ADDRESS_PREFIX.length), bytes = Buffer.from(encoded, 'base64url');
  if (bytes.length !== PRIVACY_PROFILE_ADDRESS_BYTES || bytes.toString('base64url') !== encoded
    || !bytes.subarray(0, 4).equals(Buffer.from('PSA1')) || bytes[4] !== 1) throw new Error('Unsupported/noncanonical privacy address');
  const signed = bytes.subarray(0, BODY_BYTES + SIGNATURE_BYTES);
  if (!checksum(signed).equals(bytes.subarray(BODY_BYTES + SIGNATURE_BYTES))) throw new Error('Privacy address checksum mismatch');
  const actualGenesis = new PublicKey(bytes.subarray(5, 37)), actualProgram = new PublicKey(bytes.subarray(37, 69));
  if (!actualProgram.equals(scopeKey(programId)) || !actualGenesis.equals(scopeKey(genesisHash))) throw new Error('Privacy address belongs to another ledger/program');
  const ownerPub = field(BigInt('0x' + bytes.subarray(69, 101).toString('hex'))), rawView = bytes.subarray(101, 133); validateViewPoint(rawView);
  const signer = bytes.subarray(133, BODY_BYTES), signature = bytes.subarray(BODY_BYTES, BODY_BYTES + SIGNATURE_BYTES);
  const signingKey = createPublicKey({ key: Buffer.concat([ED_PUBLIC, signer]), type: 'spki', format: 'der' });
  if (!verify(null, Buffer.concat([SIGN_DOMAIN, bytes.subarray(0, BODY_BYTES)]), signingKey, signature)) throw new Error('Privacy profile signature mismatch');
  return Object.freeze({ version: 1, programId: actualProgram.toBase58(), genesisHash: actualGenesis.toBase58(), ownerPub,
    viewPublicKey: Buffer.concat([X_PUBLIC, rawView]).toString('base64'), profileSigningPublicKey: new PublicKey(signer).toBase58(),
    signature: signature.toString('base64'), address, profileSignatureVerified: true, spendingKeyKnowledgeProven: false });
}
