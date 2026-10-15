import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';
import { TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { randomBytes } from 'node:crypto';
import { encodeGroth16Proof } from './proof-encoding.mjs';
import { statePda } from './program-addresses.mjs';
import { addressLimbsV7, normalizeV7Lanes, publicContextV7,
  bucketIdV7, bucketPaddingPdaV7, spentBucketPdaV7 } from './account-addresses.mjs';
import { parseV9SpentBucket } from './state.mjs';
import { bindDeliveryV9, deliveryHashV9, decodeTripleNoteBinaryV9, encodeTripleNoteBinaryV9 } from './notes.mjs';

export const V9_TREE_DEPTH = 32, V9_ROOT_HISTORY = 512;
export const V9_PACKET_BYTES = 830, V9_ACCOUNT_COUNT = 22;
export const V9_EXIT_PACKET_BYTES = 373, V9_EXIT_ACCOUNT_COUNT = 16;
export const V9_PACKET_OFFSETS = Object.freeze({ rootIndex: 1, proof: 3, nullifiers: 259,
  commitments: 355, kinds: 483, amounts: 487, feeAmount: 519, delivery: 527 });
export const V9_EXIT_OFFSETS = Object.freeze({ rootIndex: 1, proof: 3, nullifiers: 259, kinds: 355, amounts: 357 });
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const meta = (pubkey, isWritable = false, isSigner = false) => ({ pubkey, isWritable, isSigner });
const scalar = (bytes) => BigInt(`0x${bytes.toString('hex')}`);
function field(value) { const n = BigInt(value); if (n < 0n || n >= FR) throw new Error('noncanonical V9 field'); return n; }
const be32 = (value) => Buffer.from(field(value).toString(16).padStart(64, '0'), 'hex');
function randomField() { let n; do { n = scalar(randomBytes(32)); } while (!n || n >= FR); return n; }
function rootHeader(selector, rootIndex) {
  if (!Number.isInteger(rootIndex) || rootIndex < 0 || rootIndex >= V9_ROOT_HISTORY) throw new Error('invalid V9 root index');
  const header = Buffer.alloc(3); header[0] = selector; header.writeUInt16LE(rootIndex, 1); return header;
}
function laneData(lanes) {
  for (const lane of lanes) {
    const value = BigInt(lane.amount);
    if (![0, 1, 2].includes(lane.kind) || value < 0n || value >= 1n << 64n
      || (lane.kind === 0 ? value !== 0n : value === 0n)) throw new Error('invalid V9 lane');
  }
  return [Buffer.from(lanes.map((lane) => lane.kind)), ...lanes.map((lane) => {
    const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(lane.amount)); return out;
  })];
}
function decodedLanes(packet, kindOffset, amountOffset, count) {
  const laneKinds = Array.from({ length: count }, (_, i) => packet[kindOffset + i]);
  const laneAmounts = Array.from({ length: count }, (_, i) => packet.readBigUInt64BE(amountOffset + i * 8));
  laneData(laneKinds.map((kind, i) => ({ kind, amount: laneAmounts[i] })));
  return { laneKinds, laneAmounts };
}
function decodedFields(packet, offset, count = 3) {
  return Array.from({ length: count }, (_, i) => {
    const out = Buffer.from(packet.subarray(offset + i * 32, offset + (i + 1) * 32)); field(scalar(out)); return out;
  });
}
function buckets(programId, nullifiers, writable) {
  const seen = new Set();
  return nullifiers.map((nf, i) => {
    const id = bucketIdV7(nf);
    if (seen.has(id)) return meta(bucketPaddingPdaV7(programId, i));
    seen.add(id); return meta(spentBucketPdaV7(programId, nf), writable);
  });
}
export const normalizeV9Lanes = normalizeV7Lanes;
export function exitMarkerPdaV9(programId, nullifier) {
  const bytes = Buffer.isBuffer(nullifier) ? nullifier : be32(nullifier);
  if (bytes.length !== 32) throw new Error('invalid exit nullifier'); field(scalar(bytes));
  return PublicKey.findProgramAddressSync([Buffer.from('exit-nullifier'), bytes], new PublicKey(programId))[0];
}
export function parseExitMarkerV9(data, nullifier) {
  const bytes = Buffer.from(data), nf = Buffer.isBuffer(nullifier) ? nullifier : be32(nullifier);
  if (bytes.length !== 36 || bytes.subarray(0, 4).toString() !== 'PSE8'
    || !bytes.subarray(4).equals(nf)) throw new Error('invalid V9 exit marker');
  return { nullifier: Buffer.from(nf), spent: true };
}
export async function isSpentV9(connection, programId, nullifier) {
  const nf = Buffer.isBuffer(nullifier) ? nullifier : be32(nullifier);
  const [bucket, marker] = await connection.getMultipleAccountsInfo([
    spentBucketPdaV7(programId, nf), exitMarkerPdaV9(programId, nf)], 'confirmed');
  if (marker) {
    if (marker.owner.equals(programId)) { parseExitMarkerV9(marker.data, nf); return true; }
    if (!marker.owner.equals(SystemProgram.programId) || marker.data.length !== 0) throw new Error('foreign exit marker');
  }
  if (!bucket || (bucket.owner.equals(SystemProgram.programId) && bucket.data.length === 0)) return false;
  if (!bucket.owner.equals(programId)) throw new Error('foreign spent bucket');
  return parseV9SpentBucket(bucket.data, bucketIdV7(nf)).has(nf);
}
export function publicContextV9(core, programId, payer, lanes, feeAmount) {
  const fee = BigInt(feeAmount);
  if (fee < 0n || fee >= 1n << 64n) throw new Error('invalid V9 fee amount');
  return core.hash(91n, publicContextV7(core, programId, payer, lanes), fee);
}
export function buildV9Witness(core, { tree, payer, programId, selected = [], outputs,
  laneInput = [], feeAmount, dummySecret = [randomField(), randomField(), randomField()] }) {
  const fee = BigInt(feeAmount);
  if (tree?.depth !== 32 || selected.length > 3 || outputs?.length !== 4 || dummySecret.length !== 3
    || fee < 0n || fee >= 1n << 64n || outputs[3].note.asset !== 0n || outputs[3].note.amount !== fee) throw new Error('invalid V9 slots or fee output');
  const lanes = normalizeV9Lanes(core, programId, payer, laneInput);
  const paths = [0, 1, 2].map((i) => selected[i] ? tree.path(selected[i].index)
    : { siblings: Array(32).fill(0n), pathBits: Array(32).fill(0n) });
  if (paths.some((path) => path.siblings?.length !== 32 || path.pathBits?.length !== 32)) throw new Error('invalid V9 path');
  const nullifiers = [0, 1, 2].map((i) => selected[i] ? core.nullifier(selected[i].identity.spendSecret, selected[i].commitment)
    : core.hash(71n, dummySecret[i], BigInt(i + 1)));
  if (new Set(nullifiers.map(String)).size !== 3 || new Set(outputs.map((o) => o.commitment.toString())).size !== 4) throw new Error('duplicate V9 nullifier or commitment');
  const delivery = encodeTripleNoteBinaryV9(outputs.slice(0, 3).map((out) => out.envelope));
  const witness = { root: tree.root(), nullifiers, outCommitments: outputs.map((out) => out.commitment),
    deliveryHash: deliveryHashV9(delivery), deliveryBinding: bindDeliveryV9(core, outputs.map((out) => out.commitment), delivery),
    publicContext: publicContextV9(core, programId, payer, lanes, fee), feeAmount: fee,
    programDomain: addressLimbsV7(programId), submitter: addressLimbsV7(payer),
    laneKind: lanes.map((l) => BigInt(l.kind)), laneAsset: lanes.map((l) => l.asset), laneAmount: lanes.map((l) => l.amount),
    laneAddress: lanes.map((l) => addressLimbsV7(l.address)), active: [0, 1, 2].map((i) => BigInt(Boolean(selected[i]))),
    inAsset: [0, 1, 2].map((i) => selected[i]?.note.asset ?? 0n), inAmount: [0, 1, 2].map((i) => selected[i]?.note.amount ?? 0n),
    ownerSecret: [0, 1, 2].map((i) => selected[i]?.identity.spendSecret ?? 1n), inNonce: [0, 1, 2].map((i) => selected[i]?.note.nonce ?? 1n),
    dummySecret, siblings: paths.map((p) => p.siblings), pathBits: paths.map((p) => p.pathBits),
    outAsset: outputs.map((o) => o.note.asset), outAmount: outputs.map((o) => o.note.amount),
    outOwnerPub: outputs.map((o) => o.note.ownerPub), outNonce: outputs.map((o) => o.note.nonce) };
  return { witness, lanes, delivery };
}
export function encodeV9Packet(core, proof, publicSignals, delivery, rootIndex, lanes, feeAmount) {
  const fee = BigInt(feeAmount);
  if (lanes?.length !== 4 || publicSignals?.length !== 10 || fee < 0n || fee >= 1n << 64n) throw new Error('invalid V9 slots or fee');
  publicSignals.forEach(field); decodeTripleNoteBinaryV9(delivery);
  const proofBytes = encodeGroth16Proof(proof);
  if (bindDeliveryV9(core, publicSignals.slice(4, 8).map(BigInt), delivery) !== BigInt(publicSignals[8])) throw new Error('V9 delivery does not match proof binding');
  const feeBytes = Buffer.alloc(8); feeBytes.writeBigUInt64BE(fee);
  return Buffer.concat([rootHeader(13, rootIndex), proofBytes, ...publicSignals.slice(1, 8).map(be32), ...laneData(lanes), feeBytes, delivery]);
}
export function parseV9Packet(packet) {
  if (!Buffer.isBuffer(packet) || packet.length !== V9_PACKET_BYTES || packet[0] !== 13
    || packet.readUInt16LE(1) >= V9_ROOT_HISTORY) throw new Error('invalid V9 packet');
  const delivery = Buffer.from(packet.subarray(527)); decodeTripleNoteBinaryV9(delivery);
  const nullifiers = decodedFields(packet, 259), commitments = decodedFields(packet, 355, 4);
  if (new Set(nullifiers.map((n) => n.toString('hex'))).size !== 3 || new Set(commitments.map((n) => n.toString('hex'))).size !== 4) throw new Error('duplicate V9 packet fields');
  return { rootIndex: packet.readUInt16LE(1), proof: Buffer.from(packet.subarray(3, 259)), nullifiers, commitments,
    ...decodedLanes(packet, 483, 487, 4), feeAmount: packet.readBigUInt64BE(519), delivery };
}
export function processInstructionV9(core, programId, payer, packet, laneInput = []) {
  const decoded = parseV9Packet(packet), lanes = normalizeV9Lanes(core, programId, payer, laneInput);
  lanes.forEach((lane, i) => {
    if (lane.kind !== decoded.laneKinds[i] || lane.amount !== decoded.laneAmounts[i]) throw new Error('V9 lanes do not match packet');
  });
  return new TransactionInstruction({ programId, keys: [meta(payer, true, true), meta(statePda(programId), true),
    ...buckets(programId, decoded.nullifiers, true), meta(SystemProgram.programId), meta(TOKEN_PROGRAM_ID),
    ...lanes.flatMap((lane) => [meta(lane.address, true), meta(lane.vault, true), meta(lane.mint)]),
    ...decoded.nullifiers.map((nf) => meta(exitMarkerPdaV9(programId, nf)))], data: packet });
}
export function normalizeV9ExitLanes(core, programId, payer, lanes = []) {
  if (!Array.isArray(lanes) || lanes.length > 2) throw new Error('V9 exit has two withdrawal lanes');
  return normalizeV9Lanes(core, programId, payer, [{ kind: 0 }, { kind: 0 }, ...lanes]).slice(2);
}
export function publicExitContextV9(core, programId, payer, lanes) {
  if (lanes?.length !== 2) throw new Error('V9 exit has two lanes');
  const hashes = lanes.map((lane) => core.hash(81n, BigInt(lane.kind), lane.asset, lane.amount, ...addressLimbsV7(lane.address)));
  return core.hash(84n, ...addressLimbsV7(programId), ...addressLimbsV7(payer), ...hashes);
}
export function buildV9ExitWitness(core, { tree, programId, payer, selected, laneInput,
  dummySecret = [randomField(), randomField(), randomField()] }) {
  if (tree?.depth !== 32 || !Array.isArray(selected) || selected.length < 1 || selected.length > 3
    || dummySecret.length !== 3) throw new Error('V9 exit requires one to three input notes');
  const lanes = normalizeV9ExitLanes(core, programId, payer, laneInput);
  const sums = new Map(); selected.forEach(({ note }) => sums.set(note.asset.toString(), (sums.get(note.asset.toString()) ?? 0n) + note.amount));
  for (const lane of lanes) if (lane.kind) sums.set(lane.asset.toString(), (sums.get(lane.asset.toString()) ?? 0n) - lane.amount);
  if ([...sums.values()].some((value) => value !== 0n)) throw new Error('V9 exit must withdraw all selected value; no change');
  const paths = [0, 1, 2].map((i) => selected[i] ? tree.path(selected[i].index)
    : { siblings: Array(32).fill(0n), pathBits: Array(32).fill(0n) });
  const nullifiers = [0, 1, 2].map((i) => selected[i] ? core.nullifier(selected[i].identity.spendSecret, selected[i].commitment)
    : core.hash(71n, dummySecret[i], BigInt(i + 1)));
  const witness = { root: tree.root(), nullifiers, publicContext: publicExitContextV9(core, programId, payer, lanes),
    programDomain: addressLimbsV7(programId), submitter: addressLimbsV7(payer),
    laneKind: lanes.map((lane) => BigInt(lane.kind)), laneAsset: lanes.map((lane) => lane.asset),
    laneAmount: lanes.map((lane) => lane.amount), laneAddress: lanes.map((lane) => addressLimbsV7(lane.address)),
    active: [0, 1, 2].map((i) => BigInt(Boolean(selected[i]))),
    inAsset: [0, 1, 2].map((i) => selected[i]?.note.asset ?? 0n), inAmount: [0, 1, 2].map((i) => selected[i]?.note.amount ?? 0n),
    ownerSecret: [0, 1, 2].map((i) => selected[i]?.identity.spendSecret ?? 1n),
    inNonce: [0, 1, 2].map((i) => selected[i]?.note.nonce ?? 1n), dummySecret,
    siblings: paths.map((path) => path.siblings), pathBits: paths.map((path) => path.pathBits) };
  return { witness, lanes };
}
export function encodeV9ExitPacket(core, proof, publicSignals, rootIndex, lanes) {
  if (publicSignals?.length !== 5 || lanes?.length !== 2) throw new Error('invalid V9 exit signals');
  publicSignals.forEach(field);
  const proofBytes = encodeGroth16Proof(proof);
  return Buffer.concat([rootHeader(11, rootIndex), proofBytes, ...publicSignals.slice(1, 4).map(be32), ...laneData(lanes)]);
}
export function parseV9ExitPacket(packet) {
  if (!Buffer.isBuffer(packet) || packet.length !== 373 || packet[0] !== 11
    || packet.readUInt16LE(1) >= 512) throw new Error('invalid V9 exit packet');
  return { rootIndex: packet.readUInt16LE(1), proof: Buffer.from(packet.subarray(3, 259)),
    nullifiers: decodedFields(packet, 259), ...decodedLanes(packet, 355, 357, 2) };
}
export function exitInstructionV9(core, programId, payer, packet, laneInput) {
  const decoded = parseV9ExitPacket(packet), lanes = normalizeV9ExitLanes(core, programId, payer, laneInput);
  lanes.forEach((lane, i) => {
    if (lane.kind !== decoded.laneKinds[i] || lane.amount !== decoded.laneAmounts[i]) throw new Error('V9 exit lanes do not match packet');
  });
  return new TransactionInstruction({ programId, keys: [meta(payer, true, true), meta(statePda(programId), true),
    ...buckets(programId, decoded.nullifiers, false), meta(SystemProgram.programId), meta(TOKEN_PROGRAM_ID),
    ...lanes.flatMap((lane) => [meta(lane.address, true), meta(lane.vault, true), meta(lane.mint)]),
    ...decoded.nullifiers.map((nf) => meta(exitMarkerPdaV9(programId, nf), true))], data: packet });
}
