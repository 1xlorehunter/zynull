import { createCipheriv, createDecipheriv, randomBytes, scryptSync, hkdfSync, createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { Keypair, PublicKey, SystemProgram, ComputeBudgetProgram, TransactionMessage, VersionedTransaction } from '@solana/web3.js';
import { getAccount, TOKEN_PROGRAM_ID } from '@solana/spl-token';
import { deriveShieldedProfile } from './shielded-profile.mjs';
import { mintToAssetId } from './assets.mjs';
import { loadChainTree } from './chain-index.mjs';
import { findV9RootIndex, parseV9SpentBucket } from './state.mjs';
import { spentBucketPdaV7, bucketIdV7 } from './account-addresses.mjs';
import { statePda, vaultPda } from './program-addresses.mjs';
import { createEncryptedNotesV9, decryptNoteV9, decodeTripleNoteBinaryV9, deriveFeeNonceV9, recoverFeeNoteV9, recoverOperationFeeNoteV9 } from './notes.mjs';
import { buildV9Witness, encodeV9Packet, parseV9Packet, processInstructionV9, buildV9ExitWitness,
  encodeV9ExitPacket, parseV9ExitPacket, exitInstructionV9, exitMarkerPdaV9, parseExitMarkerV9 } from './instructions.mjs';
import { quoteV9RelayFee, fixedV9ExitBudget, fixedV9RelayFee, createV9RelayDescriptor, verifyV9RelayDescriptor } from './fee-quote.mjs';

export const V9_LOCAL_RPC = 'http://127.0.0.1:8947';
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const json = (value) => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2);
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8').replace(/^\uFEFF/, ''));
const be32 = (value) => Buffer.from(BigInt(value).toString(16).padStart(64, '0'), 'hex');
const normalSignals = (w) => [w.root, ...w.nullifiers, ...w.outCommitments, w.deliveryBinding, w.publicContext].map(String);
const exitSignals = (w) => [w.root, ...w.nullifiers, w.publicContext].map(String);
function randomField() { let n; do { n = BigInt(`0x${randomBytes(32).toString('hex')}`); } while (!n || n >= FR); return n; }
function atomicJson(path, value) { mkdirSync(dirname(path), { recursive: true }); writeFileSync(`${path}.tmp`, json(value), { mode: 0o600 }); renameSync(`${path}.tmp`, path); }
export function assertV9Local(connection) {
  const url = new URL(connection.rpcEndpoint);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
    || url.port !== '8947' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('V9 prototype accepts only localhost validator on port 8947');
  }
}
export function parseHumanAmount(value, decimals = 9) {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18 || typeof value !== 'string'
    || !/^(0|[1-9]\d*)(\.\d+)?$/.test(value)) throw new Error('Введите положительную сумму без экспоненты');
  const [whole, fraction = ''] = value.split('.');
  if (fraction.length > decimals) throw new Error(`Допустимо не больше ${decimals} знаков после точки`);
  const amount = BigInt(whole) * 10n ** BigInt(decimals) + BigInt(fraction.padEnd(decimals, '0') || '0');
  if (amount <= 0n || amount >= 1n << 64n) throw new Error('Сумма вне диапазона'); return amount;
}
export function formatHumanAmount(amount, decimals = 9) {
  const value = BigInt(amount), scale = 10n ** BigInt(decimals);
  const fraction = (value % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${value / scale}${fraction ? `.${fraction}` : ''}`;
}
export function selectV9Notes(notes, asset, amount, { maxInputs = 3 } = {}) {
  const available = notes.filter((entry) => !entry.spent && entry.note.amount > 0n && entry.note.asset === BigInt(asset))
    .sort((a, b) => a.note.amount === b.note.amount ? a.index - b.index : a.note.amount > b.note.amount ? -1 : 1);
  const selected = []; let total = 0n;
  for (const entry of available) { if (total >= BigInt(amount)) break; selected.push(entry); total += entry.note.amount; if (selected.length === maxInputs) break; }
  if (total < BigInt(amount)) throw new Error(`Не хватает средств в ${maxInputs} notes: сначала объедините мелкие notes`);
  return { selected, total };
}
export function selectV9AtomicNotes(notes, asset, amount, feeAmount, { combine = false } = {}) {
  asset = BigInt(asset); amount = BigInt(amount); feeAmount = BigInt(feeAmount);
  if (asset < 0n || asset >= FR || amount < 0n || amount >= 1n << 64n || feeAmount <= 0n || feeAmount >= 1n << 64n
    || (!combine && amount === 0n)) throw new Error('invalid V9 atomic payment');
  const available = (id) => notes.filter((entry) => !entry.spent && entry.note.amount > 0n && entry.note.asset === id)
    .sort((a, b) => a.note.amount === b.note.amount ? a.index - b.index : a.note.amount > b.note.amount ? -1 : 1);
  if (asset === 0n) {
    const selection = combine ? { selected: available(0n).slice(0, 3) } : selectV9Notes(notes, 0n, amount + feeAmount);
    const total = selection.selected.reduce((sum, entry) => sum + entry.note.amount, 0n), paymentAmount = combine ? total - feeAmount : amount;
    if (!selection.selected.length || paymentAmount <= 0n || total < paymentAmount + feeAmount) throw new Error('Недостаточно приватной SOL для суммы и комиссии');
    return { selected: selection.selected, assetTotal: total, solTotal: total, paymentAmount };
  }
  const assetNotes = available(asset), solNotes = available(0n);
  if (!solNotes.length) throw new Error('Для SPL платежа нужна приватная SOL комиссия: внесите SOL в протокол');
  for (const k of combine ? [2, 1] : [1, 2]) {
    const chosen = assetNotes.slice(0, k); if (chosen.length !== k) continue;
    const assetTotal = chosen.reduce((sum, entry) => sum + entry.note.amount, 0n), paymentAmount = combine ? assetTotal : amount;
    if (paymentAmount <= 0n || assetTotal < paymentAmount) continue;
    const sol = []; let solTotal = 0n;
    for (const entry of solNotes.slice(0, 3 - k)) { if (solTotal >= feeAmount) break; sol.push(entry); solTotal += entry.note.amount; }
    if (solTotal >= feeAmount) return { selected: [...chosen, ...sol], assetTotal, solTotal, paymentAmount };
  }
  throw new Error('Сумма и SOL комиссия не помещаются в три входные notes: объедините записи');
}
export function readOrCreateV9Keypair(path) {
  const readWinner = () => {
    for (let attempt = 0; attempt < 40; attempt++) {
      try { const doc = readJson(path); if (doc.version !== 1 || typeof doc.seed !== 'string') throw new Error('invalid local V9 seed file');
        const seed = Buffer.from(doc.seed, 'base64');
        try { if (seed.length !== 32 || seed.toString('base64') !== doc.seed) throw new Error('invalid local V9 seed file'); return Keypair.fromSeed(seed); }
        finally { seed.fill(0); }
      } catch (error) {
        // An exclusive creator can have opened the file just before writing
        // its short document. Wait briefly for completion; never replace it.
        if (attempt === 39) throw new Error('invalid or incomplete local V9 seed file; existing seed was not overwritten');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
      }
    }
  };
  if (existsSync(path)) return readWinner();
  const seed = randomBytes(32); mkdirSync(dirname(path), { recursive: true });
  try {
    try { writeFileSync(path, json({ version: 1, seed: seed.toString('base64') }), { flag: 'wx', mode: 0o600 }); return Keypair.fromSeed(seed); }
    catch (error) { if (error.code !== 'EEXIST') throw error; return readWinner(); }
  } finally { seed.fill(0); }
}
function seal(plaintext, key, aad) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') };
}
function unseal(document, key, aad) {
  const iv = Buffer.from(document.iv, 'base64');
  if (iv.length !== 12 || typeof document.tag !== 'string' || typeof document.ciphertext !== 'string') throw new Error('invalid V9 encrypted backup');
  const tag = Buffer.from(document.tag, 'base64'); if (tag.length !== 16) throw new Error('invalid V9 encrypted backup');
  const decipher = createDecipheriv('aes-256-gcm', key, iv); decipher.setAAD(aad); decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(Buffer.from(document.ciphertext, 'base64')), decipher.final()]);
}
export function exportV9WalletBackup(keypair, programId, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < 12 || passphrase.length > 1024) throw new Error('Пароль резервной копии: минимум 12 символов');
  const salt = randomBytes(16), key = scryptSync(passphrase, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 });
  const aad = Buffer.from(`privacy-v9-wallet-backup:${programId}`), plaintext = Buffer.from(json({ version: 1, programId: String(programId), seed: Buffer.from(keypair.secretKey.subarray(0, 32)).toString('base64') }));
  try { return { version: 1, programId: String(programId), kdf: 'scrypt-32768-8-1', salt: salt.toString('base64'), ...seal(plaintext, key, aad) }; }
  finally { plaintext.fill(0); key.fill(0); }
}
export function restoreV9WalletBackup(document, programId, passphrase) {
  if (document?.version !== 1 || document.programId !== String(programId) || document.kdf !== 'scrypt-32768-8-1'
    || typeof passphrase !== 'string' || passphrase.length < 12 || passphrase.length > 1024) throw new Error('Резервная копия другого протокола или неверный пароль');
  const salt = Buffer.from(document.salt, 'base64'); if (salt.length !== 16) throw new Error('invalid V9 backup salt');
  const key = scryptSync(passphrase, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 }); let plain;
  try { plain = unseal(document, key, Buffer.from(`privacy-v9-wallet-backup:${programId}`)); const decoded = JSON.parse(plain.toString());
    if (decoded.version !== 1 || decoded.programId !== String(programId)) throw new Error('invalid V9 backup contents');
    const seed = Buffer.from(decoded.seed, 'base64'); if (seed.length !== 32) throw new Error('invalid V9 backup seed');
    try { return Keypair.fromSeed(seed); } finally { seed.fill(0); } }
  finally { key.fill(0); plain?.fill(0); }
}
function base58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt(`0x${Buffer.from(bytes).toString('hex')}`), out = '';
  while (n > 0n) { out = alphabet[Number(n % 58n)] + out; n /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; out = `1${out}`; } return out;
}
export function publicV9Receipt(receipt) {
  return { signature: receipt.signature, kind: receipt.kind, transactionBytes: receipt.transactionBytes,
    computeUnits: receipt.computeUnits ?? null, confirmed: receipt.confirmed, publicEdges: receipt.publicEdges,
    feeAsset: receipt.feeAsset?.toString(), feeAmount: receipt.feeAmount?.toString(),
    ...(receipt.subsidizedLocalBudgetLamports !== undefined ? { subsidizedLocalBudgetLamports: receipt.subsidizedLocalBudgetLamports.toString(), costIsUpperBound: true } : {}),
    ...(receipt.totalFeeAmount !== undefined ? { totalFeeAmount: receipt.totalFeeAmount.toString() } : {}) };
}
// Retry exactly the signed bytes. A fresh blockhash/signature is never created
// here, so a transient TPU drop cannot turn one request into another spend.
export async function sendAndConfirmV9Bytes(connection, { raw, signature, latest,
  onAttempt = () => {}, intervalMs = 2000, maxDurationMs = 180000 }) {
  const bytes = Buffer.from(raw); let attempts = 0, busy = false, finished = false, lastError;
  const broadcast = async () => {
    attempts++; onAttempt({ attempts, at: Date.now() });
    try {
      const returned = await connection.sendRawTransaction(bytes, { skipPreflight: false, preflightCommitment: 'confirmed',
        maxRetries: connection.mainnetTransactionPolicy?.maxRetries === 0 ? 0 : 3 });
      if (returned !== signature) { const error = new Error('RPC returned a different transaction signature'); error.code = 'V9SignatureMismatch'; throw error; }
    } catch (error) { lastError = error; if (error.code === 'V9SignatureMismatch' || error.code === 'MAINNET_SPENDING_DISABLED') throw error; }
  };
  await broadcast();
  const timer = connection.mainnetTransactionPolicy?.rebroadcast === false ? null : setInterval(async () => { if (busy || finished) return; busy = true;
    try { await broadcast(); } catch (error) { lastError = error; } finally { busy = false; }
  }, intervalMs);
  let timeout;
  try {
    const confirmation = await Promise.race([connection.confirmTransaction({ signature, ...latest }, 'confirmed'),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error(`Confirmation timeout for exact signature ${signature}${lastError ? ': ' + lastError.message : ''}`)), maxDurationMs); })]);
    return { confirmation, attempts };
  } finally { finished = true; clearInterval(timer); clearTimeout(timeout); }
}
function validatePreparedRequest(request, fields, laneCount) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
    || Object.keys(request).some((key) => !fields.includes(key)) || request.version !== 1
    || typeof request.packet !== 'string' || !Array.isArray(request.lanes) || request.lanes.length !== laneCount) {
    throw new Error('invalid prepared V9 relay request');
  }
  const packet = Buffer.from(request.packet, 'base64');
  if (packet.toString('base64') !== request.packet) throw new Error('noncanonical prepared V9 packet encoding');
  for (const lane of request.lanes) {
    if (!lane || typeof lane !== 'object' || Array.isArray(lane)
      || Object.keys(lane).some((key) => !['kind', 'amount', 'address', 'mint'].includes(key))
      || !Number.isInteger(lane.kind) || ![0, 1, 2].includes(lane.kind)
      || typeof lane.amount !== 'string' || !/^(0|[1-9]\d*)$/.test(lane.amount)
      || typeof lane.address !== 'string' || (lane.mint !== undefined && typeof lane.mint !== 'string')) {
      throw new Error('invalid public V9 relay lane');
    }
  }
  return packet;
}

// Spend status is downloaded for the whole public protocol, not queried at
// addresses derived from this wallet's future nullifiers. Targeted queries
// would let an RPC operator link this wallet's later spends together.
export async function readV9SpentSnapshot(connection, programId) {
  const program = new PublicKey(programId), addresses = Array.from({ length: 32 }, (_, id) => {
    const value = Buffer.alloc(32); value[31] = id; return spentBucketPdaV7(program, value);
  });
  const accounts = await connection.getMultipleAccountsInfo(addresses, 'confirmed');
  if (!Array.isArray(accounts) || accounts.length !== 32) throw new Error('incomplete public V9 bucket snapshot');
  const buckets = accounts.map((account, id) => {
    if (!account || (account.owner.equals(SystemProgram.programId) && account.data.length === 0)) return null;
    if (!account.owner.equals(program) || account.executable) throw new Error('foreign V9 bucket snapshot owner');
    return parseV9SpentBucket(account.data, id);
  });
  const response = await connection.getProgramAccounts(program, { commitment: 'confirmed', withContext: true,
    filters: [{ dataSize: 36 }, { memcmp: { offset: 0, bytes: base58(Buffer.from('PSE8')) } }] });
  if (!response || !Array.isArray(response.value) || !Number.isSafeInteger(response.context?.slot)
    || response.context.slot < 0) throw new Error('incomplete public V9 marker snapshot');
  const markers = new Set();
  for (const { pubkey, account } of response.value) {
    if (!account?.owner?.equals(program) || account.executable || !Buffer.isBuffer(account.data)
      || account.data.length !== 36 || account.data.subarray(0, 4).toString() !== 'PSE8') throw new Error('invalid public V9 marker owner/layout');
    const nf = account.data.subarray(4);
    if (BigInt(`0x${nf.toString('hex')}`) >= FR) throw new Error('noncanonical public V9 marker nullifier');
    if (!new PublicKey(pubkey).equals(exitMarkerPdaV9(program, nf))) throw new Error('invalid public V9 marker PDA');
    parseExitMarkerV9(account.data, nf); const id = nf.toString('hex');
    if (markers.has(id)) throw new Error('duplicate public V9 marker'); markers.add(id);
  }
  return { markerCount: markers.size, markerSnapshotSlot: response.context.slot,
    bucketCounts: Object.freeze(buckets.map((bucket) => bucket?.count ?? 0)), has(nullifier) {
    const nf = Buffer.isBuffer(nullifier) ? nullifier : be32(nullifier);
    if (nf.length !== 32 || BigInt(`0x${nf.toString('hex')}`) >= FR) throw new Error('invalid local V9 nullifier');
    return markers.has(nf.toString('hex')) || (buckets[bucketIdV7(nf)]?.has(nf) ?? false);
  } };
}

export class V9Relayer {
  constructor({ connection, core, programId, keypair, assets = [], lookupTable, journalPath = 'build/v9-ui-relay-journal.json', connectionPolicy = assertV9Local }) {
    connectionPolicy(connection); Object.assign(this, { connection, core, programId: new PublicKey(programId), keypair, assets, lookupTable, journalPath });
    this.identity = deriveShieldedProfile(core, keypair, this.programId); this.quotes = new Map();
    this.journal = existsSync(journalPath) ? readJson(journalPath) : { version: 1, requests: [] };
  }
  async quote(nullifiers, asset, { expiresInMs = 120000 } = {}) {
    for (const [id, quote] of this.quotes) if (quote.expiresAt < Date.now() || quote.used) this.quotes.delete(id);
    if (!Number.isInteger(expiresInMs) || expiresInMs < 1000 || expiresInMs > 120000) throw new Error('invalid relay quote expiry');
    const quote = await quoteV9RelayFee(this.connection, this.programId, nullifiers, { asset, expiresInMs });
    quote.feeNonce = deriveFeeNonceV9(this.keypair, this.programId, this.keypair.publicKey, nullifiers, quote.feeAmount);
    this.quotes.set(quote.id, quote); return quote;
  }
  async describe() {
    if (!this.descriptor || this.descriptor.expiresAt < Date.now() + 30000) this.descriptor = await createV9RelayDescriptor(this.connection,
      this.programId, this.keypair, this.identity);
    return { ...this.descriptor };
  }
  async _send(instruction, signer, kind, fee = {}) {
    const requestDigest = this.requestDigest;
    if (requestDigest !== undefined && (typeof requestDigest !== 'string' || !/^[a-f0-9]{64}$/.test(requestDigest))) throw new Error('invalid relay request digest');
    const mainnetIdentity = this.connection.mainnetTransactionPolicy ? this.mainnetRequestIdentity : undefined;
    if (this.connection.mainnetTransactionPolicy && (!mainnetIdentity || mainnetIdentity.requestDigest !== requestDigest
      || mainnetIdentity.packetSha256 !== createHash('sha256').update(instruction.data).digest('hex'))) throw new Error('Mainnet operation requires its checked semantic replay identity before signing');
    const latest = await this.connection.getLatestBlockhash('confirmed');
    const message = new TransactionMessage({ payerKey: signer.publicKey, recentBlockhash: latest.blockhash,
      instructions: [ComputeBudgetProgram.setComputeUnitLimit({ units: 1400000 }), instruction] }).compileToV0Message(this.lookupTable ? [this.lookupTable] : []);
    const tx = new VersionedTransaction(message); tx.sign([signer]); const raw = tx.serialize();
    if (raw.length > 1232) throw new Error('V9 transaction exceeds 1232 bytes: refresh local address lookup table');
    const signature = base58(tx.signatures[0]);
    const record = { signature, kind, status: 'prepared', signedTransaction: Buffer.from(raw).toString('base64'),
      blockhash: latest.blockhash, lastValidBlockHeight: latest.lastValidBlockHeight, preparedAt: Date.now(),
      ...(requestDigest !== undefined ? { requestDigest } : {}), ...(mainnetIdentity ? {
        packetSha256: mainnetIdentity.packetSha256, nullifiers: [...mainnetIdentity.nullifiers],
      } : {}) };
    this.journal.requests.push(record); atomicJson(this.journalPath, this.journal);
    record.simulationStartedAt = Date.now();
    const simulated = await this.connection.simulateTransaction(tx, { commitment: 'confirmed', sigVerify: true });
    record.simulationCompletedAt = Date.now();
    record.computeUnits = simulated.value.unitsConsumed ?? null;
    if (simulated.value.err) { record.status = 'simulation-rejected'; atomicJson(this.journalPath, this.journal); throw new Error(`Операция отклонена валидатором: ${json(simulated.value.err)}`); }
    record.status = 'sending'; atomicJson(this.journalPath, this.journal);
    try {
      const { confirmation } = await sendAndConfirmV9Bytes(this.connection, { raw, signature, latest,
        onAttempt: ({ attempts, at }) => { record.broadcastAttempts = attempts; record.lastBroadcastAt = at;
          if (!record.firstBroadcastAt) record.firstBroadcastAt = at; atomicJson(this.journalPath, this.journal); } });
      record.confirmedAt = Date.now();
      record.status = confirmation.value.err ? 'rejected' : 'confirmed'; atomicJson(this.journalPath, this.journal);
      if (confirmation.value.err) throw new Error(`Операция не подтверждена: ${json(confirmation.value.err)}`);
      return { signature, kind, transactionBytes: raw.length, computeUnits: simulated.value.unitsConsumed,
        confirmed: true, publicEdges: kind !== 'private' && kind !== 'combine', ...fee };
    } catch (error) { if (record.status === 'sending') { record.status = 'unknown'; record.error = String(error.message).slice(0, 600); atomicJson(this.journalPath, this.journal); }
      throw new Error(`Проверьте статус транзакции ${signature} перед повтором: ${error.message}`); }
  }
  async submit(request) {
    const packet = validatePreparedRequest(request, ['version', 'kind', 'packet', 'lanes'], 4);
    if (request.kind !== 'operation') throw new Error('invalid prepared V9 relay request');
    const decoded = parseV9Packet(packet), fixed = await fixedV9RelayFee(this.connection);
    if (decoded.laneKinds[0] || decoded.laneKinds[1]) throw new Error('Relayer does not accept public deposit lanes');
    let feeNote; try { feeNote = recoverOperationFeeNoteV9(this.core, this.identity, this.programId, this.keypair.publicKey,
      decoded.nullifiers, decoded.feeAmount, BigInt(`0x${decoded.commitments[3].toString('hex')}`), decoded.delivery); }
    catch { throw new Error('Нет корректной детерминированной приватной SOL note комиссии релейеру'); }
    if (decoded.feeAmount !== fixed.feeAmount) throw new Error('Комиссия не совпадает с текущей фиксированной SOL комиссией');
    // Three new buckets and one network fee are already covered. Separate
    // prepared-nullifier queries would expose them to RPC before broadcast;
    // replay/capacity checks run in the complete onchain simulation instead.
    const publicBudget = fixed.feeAmount - fixed.marginLamports;
    if (await this.connection.getBalance(this.keypair.publicKey, 'confirmed') < Number(publicBudget)) throw new Error('Релейеру не хватает публичной SOL ликвидности');
    const instruction = processInstructionV9(this.core, this.programId, this.keypair.publicKey, packet, request.lanes);
    return this._send(instruction, this.keypair, 'operation', { feeAsset: feeNote.asset, feeAmount: feeNote.amount,
      publicEdges: decoded.laneKinds.some((kind) => kind !== 0) });
  }
  async submitExit(request) {
    const packet = validatePreparedRequest(request, ['version', 'kind', 'packet', 'lanes'], 2);
    if (request.kind !== 'emergency') throw new Error('invalid V9 emergency request');
    const decoded = parseV9ExitPacket(packet);
    const budget = await fixedV9ExitBudget(this.connection);
    if (await this.connection.getBalance(this.keypair.publicKey) < Number(budget.budgetLamports)) throw new Error('Локальному релейеру не хватает SOL на marker accounts');
    return this._send(exitInstructionV9(this.core, this.programId, this.keypair.publicKey, packet, request.lanes), this.keypair, 'emergency',
      { feeAsset: 0n, feeAmount: 0n, subsidizedLocalBudgetLamports: budget.budgetLamports, costIsUpperBound: true });
  }
}

export class V9Wallet {
  constructor({ connection, core, programId, keypair, storePath, prove, relayer, assets = [], loadTree = loadChainTree, connectionPolicy = assertV9Local, privacyProfiles = [] }) {
    connectionPolicy(connection); Object.assign(this, { connection, core, programId: new PublicKey(programId), keypair, storePath, prove, relayer, assets, loadTree });
    this.identity = deriveShieldedProfile(core, keypair, this.programId); this.notes = []; this.pending = []; this.receipts = [];
    if (!this.identity.spendSecret) throw new Error('derived zero spending key');
    this.activePrivacyProfile = this.identity;
    this.setPrivacyProfiles(privacyProfiles);
    if (storePath && existsSync(storePath)) this._loadStore();
  }
  address() { return { publicAddress: this.keypair.publicKey.toBase58(), ownerPub: this.identity.ownerPub.toString(), viewPublicKey: this.identity.viewPublicKey }; }
  setPrivacyProfiles(profiles) {
    if (!Array.isArray(profiles) || profiles.length > 64) throw new Error('Invalid private profile collection');
    const entries = [{ identity: this.identity, keypair: this.keypair }], owners = new Set([this.identity.ownerPub.toString()]);
    for (const entry of profiles) {
      if (!entry?.identity || !entry.keypair?.secretKey) throw new Error('Private profile requires a local key handle');
      const derived = deriveShieldedProfile(this.core, entry.keypair, this.programId), owner = derived.ownerPub.toString();
      if (!derived.spendSecret || derived.spendSecret !== entry.identity.spendSecret || derived.ownerPub !== entry.identity.ownerPub
        || derived.viewPublicKey !== entry.identity.viewPublicKey || owners.has(owner)) throw new Error('Invalid or duplicate private profile');
      owners.add(owner); entries.push({ identity: derived, keypair: entry.keypair });
    }
    const active = this.activePrivacyProfile?.ownerPub;
    this.privateProfiles = entries;
    this.activePrivacyProfile = entries.find((entry) => entry.identity.ownerPub === active)?.identity ?? this.identity;
  }
  setActivePrivacyProfile(ownerPub) {
    const profile = this.privateProfiles.find((entry) => entry.identity.ownerPub.toString() === String(ownerPub));
    if (!profile) throw new Error('Unknown local private profile');
    this.activePrivacyProfile = profile.identity;
  }
  _backupKey() { return Buffer.from(hkdfSync('sha256', this.keypair.secretKey.subarray(0, 32), this.programId.toBuffer(), Buffer.from('privacy-v9-local-wallet-state'), 32)); }
  _saveStore() {
    if (!this.storePath) return;
    const key = this._backupKey(), plain = Buffer.from(json({ version: 1, programId: this.programId.toBase58(), pending: this.pending, receipts: this.receipts }));
    try { atomicJson(this.storePath, { version: 1, ...seal(plain, key, this.programId.toBuffer()) }); }
    finally { plain.fill(0); key.fill(0); }
  }
  _loadStore() {
    const key = this._backupKey(); let plain;
    try { plain = unseal(readJson(this.storePath), key, this.programId.toBuffer()); const state = JSON.parse(plain.toString());
      if (state.version !== 1 || state.programId !== this.programId.toBase58() || !Array.isArray(state.pending) || !Array.isArray(state.receipts)) throw new Error('invalid V9 wallet store');
      this.pending = state.pending; this.receipts = state.receipts; }
    finally { key.fill(0); plain?.fill(0); }
  }
  async scan({ ignoreCache = false } = {}) {
    const snapshot = await this.loadTree(this.connection, this.programId, { ignoreCache });
    const spentSnapshot = await readV9SpentSnapshot(this.connection, this.programId), notes = [];
    const add = (note, commitment, event, identity) => {
      const index = snapshot.tree.leaves.indexOf(commitment); if (index < 0) throw new Error('recovered V9 note missing from tree');
      const spent = spentSnapshot.has(this.core.nullifier(identity.spendSecret, commitment));
      if (!notes.some((entry) => entry.commitment === commitment)) notes.push({ identity, note, commitment, index, spent, signature: event.signature });
    };
    for (const event of snapshot.events) {
      for (const delivery of event.deliveries ?? []) {
        if (delivery.commitment === null) continue;
        for (const { identity } of this.privateProfiles) {
          let note; try { note = decryptNoteV9(this.core, identity, delivery.commitment, delivery.envelope); } catch { continue; }
          add(note, BigInt(delivery.commitment), event, identity); break;
        }
      }
      // All fields below come from the public packet, not a cached quote.
      // Seed alone rebuilds relay fees and a depositor's zero-valued slot 3.
      if (event.v9) {
        const { payer, nullifiers, feeAmount, commitment } = event.v9;
        const nfs = nullifiers.map((nf) => typeof nf === 'string' && /^[a-f0-9]{64}$/.test(nf) ? Buffer.from(nf, 'hex') : BigInt(nf));
        for (const { identity, keypair } of this.privateProfiles) {
          let note; try { note = recoverOperationFeeNoteV9(this.core, identity, this.programId, new PublicKey(payer),
            nfs, BigInt(feeAmount), BigInt(commitment), event.v9.ephemeralPublicKey ?? event.deliveries?.[0]?.envelope); }
          catch {
          // Compatibility with direct-signer, zero-fee circuit fixtures only.
          // The quote-free relayer never accepts this legacy fee derivation.
            if (BigInt(feeAmount) !== 0n) continue;
            try { note = recoverFeeNoteV9(this.core, identity, keypair, this.programId, new PublicKey(payer), nfs, 0n, BigInt(commitment)); } catch { continue; }
          }
          add(note, BigInt(commitment), event, identity); break;
        }
      }
    }
    this.notes = notes; this.snapshot = snapshot;
    const balances = {};
    for (const entry of notes) if (!entry.spent && entry.note.amount > 0n) balances[entry.note.asset.toString()] = (BigInt(balances[entry.note.asset.toString()] ?? 0) + entry.note.amount).toString();
    return { balances, unspentNotes: notes.filter((entry) => !entry.spent && entry.note.amount > 0n).length,
      recoveredNotes: notes.length, treeCount: snapshot.tree.count, receipts: this.receipts.map(publicV9Receipt), address: this.address() };
  }
  async _proof(built, kind) {
    const result = await this.prove(built.witness, kind), expected = kind === 'exit' ? exitSignals(built.witness) : normalSignals(built.witness);
    if (!result?.proof || result.publicSignals?.length !== expected.length || result.publicSignals.some((value, i) => String(value) !== expected[i])) throw new Error('Proof signals do not match prepared V9 operation');
    return result;
  }
  _persistOutputs(outputs, kind) {
    const entry = { id: randomBytes(16).toString('hex'), kind, createdAt: Date.now(), status: 'prepared',
      outputs: outputs.map(({ note, commitment, envelope }) => ({ note, commitment, envelope })) };
    this.pending.push(entry); this._saveStore(); return entry;
  }
  async _finish(pending, operation) {
    try { const receipt = await operation(); if (pending) pending.status = 'confirmed'; this.receipts.push(publicV9Receipt(receipt)); this._saveStore(); await this.scan(); return publicV9Receipt(receipt); }
    catch (error) { if (pending) { pending.status = error?.transactionSubmitted === false ? 'rejected' : 'check-transaction-before-retry'; this._saveStore(); } throw error; }
  }
  async deposit({ asset = 0n, amount, source, mint, fundingSigner = this.keypair }) {
    await this.scan(); asset = BigInt(asset); amount = BigInt(amount); if (amount <= 0n) throw new Error('deposit must be positive');
    const payer = new PublicKey(fundingSigner?.publicKey);
    if (asset === 0n && source && !new PublicKey(source).equals(payer)) throw new Error('SOL deposit source must match its funding signer');
    const own = this.activePrivacyProfile, dummySecret = [randomField(), randomField(), randomField()];
    const nullifiers = dummySecret.map((secret, i) => this.core.hash(71n, secret, BigInt(i + 1))).map(be32);
    const outputs = createEncryptedNotesV9(this.core, [{ ...own, asset, amount }, { ...own, asset, amount: 0n },
      { ...own, asset: 0n, amount: 0n }, { ...this.identity, asset: 0n, amount: 0n }],
      { programId: this.programId, payer, nullifiers, feeAmount: 0n });
    const laneInput = [{ kind: asset === 0n ? 1 : 2, amount, address: source ?? payer, ...(mint ? { mint } : {}) }];
    const built = buildV9Witness(this.core, { tree: this.snapshot.tree, payer, programId: this.programId,
      outputs, laneInput, dummySecret, feeAmount: 0n });
    const pending = this._persistOutputs(outputs, 'deposit');
    return this._finish(pending, async () => {
      let instruction;
      try {
        const proof = await this._proof(built, 'normal');
        const state = await this.connection.getAccountInfo(statePda(this.programId)); const rootIndex = findV9RootIndex(state.data, built.witness.root);
        const packet = encodeV9Packet(this.core, proof.proof, proof.publicSignals, built.delivery, rootIndex, built.lanes, 0n);
        instruction = processInstructionV9(this.core, this.programId, payer, packet, laneInput);
      } catch (error) { error.transactionSubmitted = false; throw error; }
      return this.relayer._send(instruction, fundingSigner, 'deposit');
    });
  }
  async preparePrivate({ asset = 0n, amount, recipient, withdrawal, combine = false }) {
    await this.scan(); asset = BigInt(asset); amount = BigInt(amount ?? 0n);
    if (!combine && amount <= 0n) throw new Error('transfer must be positive');
    const descriptor = verifyV9RelayDescriptor(await this.relayer.describe(), { programId: this.programId, payer: this.relayer.keypair.publicKey });
    const feeProfile = { ownerPub: descriptor.ownerPub, viewPublicKey: descriptor.viewPublicKey }, recipientProfile = withdrawal ? this.activePrivacyProfile : recipient;
    if (!recipientProfile?.ownerPub || !recipientProfile.viewPublicKey) throw new Error('invalid recipient privacy identity');
    if (withdrawal) {
      processWithdrawalTarget(withdrawal);
      if (asset !== 0n) {
        if (!withdrawal.mint || mintToAssetId(this.core, new PublicKey(withdrawal.mint).toBytes()) !== asset) throw new Error('SPL mint вывода не совпадает с выбранным активом');
        const mint = new PublicKey(withdrawal.mint), destination = new PublicKey(withdrawal.address);
        if (destination.equals(vaultPda(this.programId, mint))) throw new Error('Нельзя выводить SPL обратно в vault протокола');
        let target; try { target = await getAccount(this.connection, destination, 'confirmed', TOKEN_PROGRAM_ID); }
        catch { throw new Error('Счёт получателя SPL не существует или не является legacy SPL token account'); }
        if (!target.isInitialized || target.isFrozen || !target.mint.equals(mint)) throw new Error('Счёт получателя SPL не инициализирован, заморожен или имеет другой mint');
      }
    }
    const selection = selectV9AtomicNotes(this.notes, asset, amount, descriptor.feeAmount, { combine }); amount = selection.paymentAmount;
    const dummySecret = [randomField(), randomField(), randomField()];
    const nfs = [0, 1, 2].map((i) => selection.selected[i] ? this.core.nullifier(selection.selected[i].identity.spendSecret, selection.selected[i].commitment)
      : this.core.hash(71n, dummySecret[i], BigInt(i + 1))).map(be32);
    this.onStatus?.('Готовим единый приватный платёж и SOL комиссию. Предварительная транзакция не нужна.');
    const assetChange = selection.assetTotal - amount - (asset === 0n ? descriptor.feeAmount : 0n);
    const solChange = asset === 0n ? 0n : selection.solTotal - descriptor.feeAmount;
    const outputs = createEncryptedNotesV9(this.core, [
      { ...recipientProfile, asset, amount: withdrawal ? 0n : amount }, { ...this.activePrivacyProfile, asset, amount: assetChange },
      { ...this.activePrivacyProfile, asset: 0n, amount: solChange }, { ...feeProfile, asset: 0n, amount: descriptor.feeAmount }],
      { programId: this.programId, payer: descriptor.payer, nullifiers: nfs, feeAmount: descriptor.feeAmount });
    const kind = withdrawal ? 'withdraw' : combine ? 'combine' : 'private';
    const laneInput = withdrawal ? [{ kind: 0 }, { kind: 0 }, { kind: asset === 0n ? 1 : 2, amount,
      address: new PublicKey(withdrawal.address), ...(withdrawal.mint ? { mint: new PublicKey(withdrawal.mint) } : {}) }] : [];
    const built = buildV9Witness(this.core, { tree: this.snapshot.tree, programId: this.programId, payer: new PublicKey(descriptor.payer),
      selected: selection.selected, outputs, laneInput, dummySecret, feeAmount: descriptor.feeAmount });
    const pending = this._persistOutputs(outputs, kind), proof = await this._proof(built, 'normal');
    const state = await this.connection.getAccountInfo(statePda(this.programId)); const rootIndex = findV9RootIndex(state.data, built.witness.root);
    const packet = encodeV9Packet(this.core, proof.proof, proof.publicSignals, built.delivery, rootIndex, built.lanes, descriptor.feeAmount);
    return { request: { version: 1, kind: 'operation', packet: packet.toString('base64'), lanes: built.lanes.map(publicLane) }, pending, descriptor };
  }
  async pay(options) { const prepared = await this.preparePrivate(options); return this._finish(prepared.pending, async () => ({
    ...await this.relayer.submit(prepared.request), kind: prepared.pending.kind, totalFeeAmount: prepared.descriptor.feeAmount })); }
  async emergencyWithdraw({ selections, destinations }) {
    await this.scan();
    const selected = selections ? selections.map((cm) => this.notes.find((entry) => !entry.spent && entry.commitment === BigInt(cm)))
      : this.notes.filter((entry) => !entry.spent && entry.note.amount > 0n).slice(0, 3);
    if (selected.some((entry) => !entry) || selected.length < 1 || selected.length > 3
      || new Set(selected.map((entry) => entry.commitment.toString())).size !== selected.length) throw new Error('Select one to three unspent notes');
    const totals = new Map(); selected.forEach(({ note }) => totals.set(note.asset.toString(), (totals.get(note.asset.toString()) ?? 0n) + note.amount));
    if (totals.size > 2) throw new Error('Emergency exit supports at most two assets');
    const laneInput = [...totals].map(([asset, amount]) => {
      const target = destinations[asset]; if (!target) throw new Error('Missing emergency withdrawal destination');
      return { kind: asset === '0' ? 1 : 2, amount, address: new PublicKey(target.address), ...(target.mint ? { mint: new PublicKey(target.mint) } : {}) };
    });
    const built = buildV9ExitWitness(this.core, { tree: this.snapshot.tree, programId: this.programId,
      payer: this.relayer.keypair.publicKey, selected, laneInput });
    const pending = this._persistOutputs([], 'emergency'), proof = await this._proof(built, 'exit');
    const state = await this.connection.getAccountInfo(statePda(this.programId)); const rootIndex = findV9RootIndex(state.data, built.witness.root);
    const packet = encodeV9ExitPacket(this.core, proof.proof, proof.publicSignals, rootIndex, built.lanes);
    return this._finish(pending, () => this.relayer.submitExit({ version: 1, kind: 'emergency', packet: packet.toString('base64'), lanes: built.lanes.map(publicLane) }));
  }
}
function publicLane(lane) { return { kind: lane.kind, amount: lane.amount.toString(), address: lane.address.toBase58(), mint: lane.mint.toBase58() }; }
function processWithdrawalTarget(target) { new PublicKey(target.address); if (target.mint) new PublicKey(target.mint); }
