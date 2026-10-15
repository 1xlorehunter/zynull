import { randomBytes, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { PublicKey, SystemProgram } from '@solana/web3.js';
import { bucketIdV7, spentBucketPdaV7 } from './account-addresses.mjs';
import { parseV9SpentBucket, V9_BUCKET_CAPACITY } from './state.mjs';
import { parseV9Packet, isSpentV9, exitMarkerPdaV9 } from './instructions.mjs';

export async function minimumV9RelayFee(connection, programId, packetOrNullifiers, { networkFee = 5000n } = {}) {
  const nfs = Buffer.isBuffer(packetOrNullifiers) ? parseV9Packet(packetOrNullifiers).nullifiers : packetOrNullifiers;
  if (!Array.isArray(nfs) || nfs.length !== 3 || nfs.some((nf) => !Buffer.isBuffer(nf) || nf.length !== 32)
    || new Set(nfs.map((nf) => nf.toString('hex'))).size !== 3) throw new Error('invalid V9 fee nullifiers');
  const grouped = new Map();
  for (const nf of nfs) {
    if (await isSpentV9(connection, programId, nf)) throw new Error('V9 nullifier already spent');
    const address = spentBucketPdaV7(programId, nf), id = address.toBase58();
    const entry = grouped.get(id) ?? { address, id: bucketIdV7(nf), added: 0 };
    entry.added++; grouped.set(id, entry);
  }
  let rentDelta = 0n;
  const buckets = [];
  for (const entry of grouped.values()) {
    const account = await connection.getAccountInfo(entry.address, 'confirmed');
    const absent = !account || (account.owner.equals(SystemProgram.programId) && account.data.length === 0);
    if (!absent && !account.owner.equals(programId)) throw new Error('foreign V9 spent bucket');
    const oldCount = absent ? 0 : parseV9SpentBucket(account.data, entry.id).count;
    if (oldCount + entry.added > V9_BUCKET_CAPACITY) throw new Error('V9 spent bucket is full; use emergency full withdrawal');
    const bytes = 8 + (oldCount + entry.added) * 32;
    const required = BigInt(await connection.getMinimumBalanceForRentExemption(bytes, 'confirmed'));
    const delta = required > BigInt(account?.lamports ?? 0) ? required - BigInt(account?.lamports ?? 0) : 0n;
    rentDelta += delta; buckets.push({ address: entry.address.toBase58(), oldCount, added: entry.added, bytes, rentDelta: delta });
  }
  return { rentDelta, networkFee: BigInt(networkFee), minimumFeeLamports: rentDelta + BigInt(networkFee), buckets };
}

export async function fixedV9RelayFee(connection, { marginLamports = 10000n } = {}) {
  if (BigInt(marginLamports) < 0n) throw new Error('invalid V9 fixed fee margin');
  const newBucketRent = BigInt(await connection.getMinimumBalanceForRentExemption(40, 'confirmed'));
  return { newBucketRent, networkFee: 5000n, marginLamports: BigInt(marginLamports),
    feeAsset: 0n, feeAmount: 3n * newBucketRent + 5000n + BigInt(marginLamports) };
}
export async function quoteV9RelayFee(connection, programId, nullifiers, { asset = 0n,
  marginLamports = 10000n, expiresInMs = 120000, now = Date.now() } = {}) {
  if (BigInt(asset) !== 0n) throw new Error('Релейер принимает только приватную SOL комиссию');
  const base = await minimumV9RelayFee(connection, programId, nullifiers);
  const fixed = await fixedV9RelayFee(connection, { marginLamports });
  if (!Number.isInteger(expiresInMs) || expiresInMs < 1000 || expiresInMs > 300000
    || BigInt(marginLamports) < 0n) throw new Error('invalid V9 quote policy');
  return { id: randomBytes(18).toString('base64url'), programId: new PublicKey(programId).toBase58(),
    createdAt: now, expiresAt: now + expiresInMs, nullifiers: nullifiers.map((nf) => nf.toString('hex')),
    feeAsset: 0n, feeAmount: fixed.feeAmount,
    marginLamports: BigInt(marginLamports), fixedFee: true, ...base };
}

export async function minimumV9ExitCost(connection, programId, nullifiers) {
  let markerRent = 0n;
  const required = BigInt(await connection.getMinimumBalanceForRentExemption(36, 'confirmed'));
  for (const nf of nullifiers) {
    if (await isSpentV9(connection, programId, nf)) throw new Error('V9 exit nullifier already spent');
    const account = await connection.getAccountInfo(exitMarkerPdaV9(programId, nf), 'confirmed');
    const current = BigInt(account?.lamports ?? 0); markerRent += required > current ? required - current : 0n;
  }
  return { markerRent, networkFee: 5000n, minimumFeeLamports: markerRent + 5000n };
}
export async function fixedV9ExitBudget(connection) {
  const markerRent = 3n * BigInt(await connection.getMinimumBalanceForRentExemption(36, 'confirmed'));
  return { markerRent, networkFee: 5000n, budgetLamports: markerRent + 5000n, costIsUpperBound: true };
}
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ED_PRIVATE_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED_PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const X_PUBLIC_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const descriptorFields = ['version', 'programId', 'payer', 'ownerPub', 'viewPublicKey', 'feeAsset', 'feeAmount', 'createdAt', 'expiresAt', 'signature'];
function descriptorMessage(doc) { return Buffer.from(JSON.stringify(['privacy-v9-relay-descriptor', doc.version, doc.programId, doc.payer,
  doc.ownerPub, doc.viewPublicKey, doc.feeAsset, doc.feeAmount, doc.createdAt, doc.expiresAt])); }
export async function createV9RelayDescriptor(connection, programId, keypair, identity, { now = Date.now(), expiresInMs = 120000 } = {}) {
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isInteger(expiresInMs) || expiresInMs < 1000 || expiresInMs > 120000) throw new Error('invalid V9 relay descriptor expiry');
  const fixed = await fixedV9RelayFee(connection), descriptor = { version: 1, programId: new PublicKey(programId).toBase58(),
    payer: keypair.publicKey.toBase58(), ownerPub: identity.ownerPub.toString(), viewPublicKey: identity.viewPublicKey,
    feeAsset: '0', feeAmount: fixed.feeAmount.toString(), createdAt: now, expiresAt: now + expiresInMs };
  const seed = Buffer.from(keypair.secretKey.subarray(0, 32));
  try { const key = createPrivateKey({ key: Buffer.concat([ED_PRIVATE_PREFIX, seed]), type: 'pkcs8', format: 'der' });
    descriptor.signature = sign(null, descriptorMessage(descriptor), key).toString('base64'); }
  finally { seed.fill(0); }
  return descriptor;
}
export function verifyV9RelayDescriptor(descriptor, { programId, payer, now = Date.now() } = {}) {
  if (!descriptor || typeof descriptor !== 'object' || Array.isArray(descriptor) || Object.keys(descriptor).length !== descriptorFields.length
    || descriptorFields.some((field) => !Object.hasOwn(descriptor, field)) || Object.keys(descriptor).some((field) => !descriptorFields.includes(field))
    || descriptor.version !== 1 || descriptor.feeAsset !== '0' || typeof descriptor.ownerPub !== 'string'
    || typeof descriptor.feeAmount !== 'string' || typeof descriptor.viewPublicKey !== 'string' || typeof descriptor.signature !== 'string'
    || !/^(0|[1-9]\d*)$/.test(descriptor.ownerPub)
    || !/^[1-9]\d*$/.test(descriptor.feeAmount) || BigInt(descriptor.ownerPub) >= FR || BigInt(descriptor.feeAmount) >= 1n << 64n
    || !Number.isSafeInteger(descriptor.createdAt) || !Number.isSafeInteger(descriptor.expiresAt)
    || descriptor.createdAt < 0 || descriptor.createdAt > now + 10000 || descriptor.expiresAt <= now
    || descriptor.expiresAt - descriptor.createdAt < 1000 || descriptor.expiresAt - descriptor.createdAt > 120000) throw new Error('invalid/expired V9 relay descriptor');
  const actualProgram = new PublicKey(descriptor.programId), actualPayer = new PublicKey(descriptor.payer);
  if (actualProgram.toBase58() !== descriptor.programId || actualPayer.toBase58() !== descriptor.payer
    || !programId || !actualProgram.equals(new PublicKey(programId)) || !payer || !actualPayer.equals(new PublicKey(payer))) throw new Error('V9 relay descriptor program/payer mismatch');
  const view = Buffer.from(descriptor.viewPublicKey, 'base64'), signature = Buffer.from(descriptor.signature, 'base64');
  if (view.length !== 44 || view.toString('base64') !== descriptor.viewPublicKey || !view.subarray(0, 12).equals(X_PUBLIC_PREFIX)
    || signature.length !== 64 || signature.toString('base64') !== descriptor.signature) throw new Error('invalid V9 relay descriptor encoding');
  const key = createPublicKey({ key: Buffer.concat([ED_PUBLIC_PREFIX, actualPayer.toBuffer()]), type: 'spki', format: 'der' });
  if (!verify(null, descriptorMessage(descriptor), key, signature)) throw new Error('V9 relay descriptor signature mismatch');
  return { ...descriptor, feeAsset: 0n, feeAmount: BigInt(descriptor.feeAmount), ownerPub: BigInt(descriptor.ownerPub) };
}
