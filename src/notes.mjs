import { createCipheriv, createDecipheriv, createPublicKey, diffieHellman,
  generateKeyPairSync, hkdfSync, randomBytes, createHash, createHmac } from 'node:crypto';
import { PublicKey } from '@solana/web3.js';

const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const DOMAIN = Buffer.from('solana-privacy-note-v4');
const AAD_DOMAIN = Buffer.from('privacy-v9-note-aad');
const IV_DOMAIN = Buffer.from('privacy-v9-gcm-iv');
export const V9_DELIVERY_BYTES = 303;
const scalar = (bytes) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
const field = (value) => { const n = BigInt(value); if (n < 0n || n >= FR) throw new Error('invalid V9 field'); return n; };
const amount = (value) => { const n = BigInt(value); if (n < 0n || n >= 1n << 64n) throw new Error('invalid V9 amount'); return n; };
const be32 = (value) => Buffer.from(field(value).toString(16).padStart(64, '0'), 'hex');
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(amount(value)); return out; }
function nonce() { let n; do { n = scalar(randomBytes(32)); } while (!n || n >= FR); return n; }
function canonicalBase64(value, length) {
  if (typeof value !== 'string') throw new Error('invalid V9 envelope encoding');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== length || bytes.toString('base64') !== value) throw new Error('invalid V9 envelope encoding');
  return bytes;
}
function envelopeParts(envelope) {
  if (envelope?.version !== 4 || Object.keys(envelope).some((key) => !['version', 'ephemeralPublicKey', 'tag', 'ciphertext'].includes(key))) throw new Error('V9 requires note envelope v4');
  const pub = canonicalBase64(envelope.ephemeralPublicKey, 44);
  if (!pub.subarray(0, 12).equals(PREFIX)) throw new Error('invalid V9 X25519 envelope');
  return { pub: pub.subarray(12), tag: canonicalBase64(envelope.tag, 16), ciphertext: canonicalBase64(envelope.ciphertext, 73) };
}
export function noteIvV9(ephemeralPublicRaw, commitment) {
  const pub = Buffer.from(ephemeralPublicRaw);
  if (pub.length !== 32) throw new Error('invalid V9 ephemeral key');
  return createHash('sha256').update(IV_DOMAIN).update(pub).update(be32(commitment)).digest().subarray(0, 12);
}
const aad = (commitment) => Buffer.concat([AAD_DOMAIN, be32(commitment)]);
function noteV9(core, input) {
  const note = { asset: field(input.asset), amount: amount(input.amount), ownerPub: field(input.ownerPub), nonce: field(input.nonce) };
  return { note, commitment: core.commitment(note) };
}

// Only the first three outputs need encrypted delivery. Output 3 is rebuilt
// from the relayer's seed and the public operation fields.
export function createEncryptedNotesV9(core, inputs, feeBinding) {
  if (!Array.isArray(inputs) || inputs.length !== 4 || (!feeBinding && inputs[3].nonce === undefined)) throw new Error('V9 requires four outputs and a deterministic fee nonce');
  return encryptExistingNotesV9(core, inputs.map((input, i) => i < 3 ? { ...input, nonce: nonce() } : input), feeBinding);
}
export function encryptExistingNotesV9(core, inputs, feeBinding) {
  if (!Array.isArray(inputs) || inputs.length !== 4) throw new Error('V9 requires four outputs');
  const ephemeral = generateKeyPairSync('x25519');
  const ephemeralPublicKey = ephemeral.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const rawPub = Buffer.from(ephemeralPublicKey, 'base64').subarray(12);
  if (feeBinding) {
    if (BigInt(inputs[3].asset) !== 0n || BigInt(inputs[3].amount) !== BigInt(feeBinding.feeAmount)) throw new Error('V9 fee output does not match binding');
    const recipient = createPublicKey({ key: canonicalBase64(inputs[3].viewPublicKey, 44), type: 'spki', format: 'der' });
    if (recipient.asymmetricKeyType !== 'x25519') throw new Error('V9 fee view key must be X25519');
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
    try { inputs = [...inputs.slice(0, 3), { ...inputs[3], nonce: operationFeeNonce(shared, feeBinding.programId, feeBinding.payer,
      feeBinding.nullifiers, feeBinding.feeAmount, rawPub) }]; }
    finally { shared.fill(0); }
  }
  const outputs = inputs.map((input) => noteV9(core, input));
  if (new Set(outputs.map((out) => out.commitment.toString())).size !== 4) throw new Error('duplicate V9 output commitment');
  if (outputs[3].note.asset !== 0n) throw new Error('V9 fee output must be SOL');
  return outputs.map((output, i) => {
    if (i === 3) return output;
    const recipient = createPublicKey({ key: Buffer.from(inputs[i].viewPublicKey, 'base64'), type: 'spki', format: 'der' });
    if (recipient.asymmetricKeyType !== 'x25519') throw new Error('view key must be X25519');
    const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
    const key = Buffer.from(hkdfSync('sha256', shared, DOMAIN, be32(output.commitment), 32));
    const plaintext = Buffer.alloc(73); plaintext[0] = 4; plaintext.set(be32(output.note.asset), 1);
    plaintext.writeBigUInt64BE(output.note.amount, 33); plaintext.set(be32(output.note.nonce), 41);
    try {
      const cipher = createCipheriv('aes-256-gcm', key, noteIvV9(rawPub, output.commitment)); cipher.setAAD(aad(output.commitment));
      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return { ...output, envelope: { version: 4, ephemeralPublicKey, tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') } };
    } finally { shared.fill(0); key.fill(0); plaintext.fill(0); }
  });
}
export function encodeTripleNoteBinaryV9(envelopes) {
  if (!Array.isArray(envelopes) || envelopes.length !== 3) throw new Error('V9 requires three encrypted envelopes');
  const parts = envelopes.map(envelopeParts);
  if (!parts.every((part) => part.pub.equals(parts[0].pub))) throw new Error('V9 outputs must share the operation ephemeral key');
  return Buffer.concat([Buffer.from('PSB9'), parts[0].pub, ...parts.flatMap(({ tag, ciphertext }) => [tag, ciphertext])]);
}
export function decodeTripleNoteBinaryV9(input) {
  const bytes = Buffer.from(input);
  if (bytes.length !== V9_DELIVERY_BYTES || bytes.subarray(0, 4).toString() !== 'PSB9') throw new Error('invalid V9 delivery');
  const ephemeralPublicKey = Buffer.concat([PREFIX, bytes.subarray(4, 36)]).toString('base64');
  return { envelopes: [0, 1, 2].map((i) => ({ version: 4, ephemeralPublicKey,
    tag: bytes.subarray(36 + i * 89, 52 + i * 89).toString('base64'), ciphertext: bytes.subarray(52 + i * 89, 125 + i * 89).toString('base64') })) };
}
export function decryptNoteV9(core, identity, commitment, envelope) {
  const parts = envelopeParts(envelope), ephemeral = createPublicKey({ key: Buffer.concat([PREFIX, parts.pub]), type: 'spki', format: 'der' });
  const shared = diffieHellman({ privateKey: identity.viewPrivate, publicKey: ephemeral });
  const key = Buffer.from(hkdfSync('sha256', shared, DOMAIN, be32(commitment), 32)); let plain;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, noteIvV9(parts.pub, commitment)); decipher.setAAD(aad(commitment)); decipher.setAuthTag(parts.tag);
    plain = Buffer.concat([decipher.update(parts.ciphertext), decipher.final()]);
    if (plain.length !== 73 || plain[0] !== 4) throw new Error('invalid V9 note plaintext');
    const note = { asset: field(scalar(plain.subarray(1, 33))), amount: amount(plain.readBigUInt64BE(33)), ownerPub: field(identity.ownerPub), nonce: field(scalar(plain.subarray(41))) };
    if (core.commitment(note) !== field(commitment)) throw new Error('V9 note commitment mismatch');
    return { ...note, spendSecret: identity.spendSecret };
  } finally { shared.fill(0); key.fill(0); plain?.fill(0); }
}
export function deliveryHashV9(delivery) {
  decodeTripleNoteBinaryV9(delivery); return scalar(createHash('sha256').update(delivery).digest().subarray(0, 31));
}
export function bindDeliveryV9(core, commitments, delivery) {
  if (!Array.isArray(commitments) || commitments.length !== 4) throw new Error('V9 requires four commitments');
  return core.hash(...commitments.map(field), deliveryHashV9(delivery));
}
export function deriveFeeNonceV9(keypair, programId, payer, nullifiers, feeAmount) {
  if (!Array.isArray(nullifiers) || nullifiers.length !== 3) throw new Error('invalid V9 fee nullifiers');
  const nfs = nullifiers.map((nf) => Buffer.isBuffer(nf) ? Buffer.from(nf) : be32(nf));
  nfs.forEach((nf) => { if (nf.length !== 32) throw new Error('invalid V9 fee nullifier'); field(scalar(nf)); });
  if (new Set(nfs.map((nf) => nf.toString('hex'))).size !== 3) throw new Error('duplicate V9 fee nullifier');
  const key = Buffer.from(hkdfSync('sha256', keypair.secretKey.subarray(0, 32), new PublicKey(programId).toBuffer(), Buffer.from('privacy-v9-fee-nonce-key'), 32));
  try { return scalar(createHmac('sha256', key).update(Buffer.from('PSF9')).update(new PublicKey(payer).toBuffer()).update(Buffer.concat(nfs)).update(u64(feeAmount)).digest()) % FR; }
  finally { key.fill(0); }
}
export function recoverFeeNoteV9(core, identity, keypair, programId, payer, nullifiers, feeAmount, commitment) {
  const note = { asset: 0n, amount: amount(feeAmount), ownerPub: field(identity.ownerPub), nonce: deriveFeeNonceV9(keypair, programId, payer, nullifiers, feeAmount) };
  if (core.commitment(note) !== field(commitment)) throw new Error('V9 deterministic fee commitment mismatch');
  return { ...note, spendSecret: identity.spendSecret };
}
function operationFeeNonce(shared, programId, payer, nullifiers, feeAmount, ephemeralRaw) {
  if (!Array.isArray(nullifiers) || nullifiers.length !== 3 || ephemeralRaw.length !== 32) throw new Error('invalid V9 operation fee binding');
  const nfs = nullifiers.map((nf) => Buffer.isBuffer(nf) ? Buffer.from(nf) : be32(nf));
  nfs.forEach((nf) => { if (nf.length !== 32) throw new Error('invalid V9 operation nullifier'); field(scalar(nf)); });
  if (new Set(nfs.map((nf) => nf.toString('hex'))).size !== 3) throw new Error('duplicate V9 operation nullifier');
  const key = Buffer.from(hkdfSync('sha256', shared, new PublicKey(programId).toBuffer(), Buffer.from('privacy-v9-fee-nonce-key'), 32));
  try { return scalar(createHmac('sha256', key).update(Buffer.from('PSF9')).update(new PublicKey(payer).toBuffer()).update(Buffer.concat(nfs))
    .update(u64(feeAmount)).update(ephemeralRaw).digest()) % FR; }
  finally { key.fill(0); }
}
function operationEphemeral(input) {
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const bytes = Buffer.from(input); decodeTripleNoteBinaryV9(bytes); return bytes.subarray(4, 36);
  }
  const encoded = typeof input === 'string' ? input : input?.ephemeralPublicKey;
  const publicKey = canonicalBase64(encoded, 44);
  if (!publicKey.subarray(0, 12).equals(PREFIX)) throw new Error('invalid V9 operation ephemeral key'); return publicKey.subarray(12);
}
export function deriveOperationFeeNonceV9(identity, programId, payer, nullifiers, feeAmount, deliveryOrEphemeral) {
  const ephemeralRaw = operationEphemeral(deliveryOrEphemeral), ephemeral = createPublicKey({ key: Buffer.concat([PREFIX, ephemeralRaw]), type: 'spki', format: 'der' });
  const shared = diffieHellman({ privateKey: identity.viewPrivate, publicKey: ephemeral });
  try { return operationFeeNonce(shared, programId, payer, nullifiers, feeAmount, ephemeralRaw); }
  finally { shared.fill(0); }
}
export function recoverOperationFeeNoteV9(core, identity, programId, payer, nullifiers, feeAmount, commitment, deliveryOrEphemeral) {
  const note = { asset: 0n, amount: amount(feeAmount), ownerPub: field(identity.ownerPub),
    nonce: deriveOperationFeeNonceV9(identity, programId, payer, nullifiers, feeAmount, deliveryOrEphemeral) };
  if (core.commitment(note) !== field(commitment)) throw new Error('V9 DH fee commitment mismatch');
  return { ...note, spendSecret: identity.spendSecret };
}
