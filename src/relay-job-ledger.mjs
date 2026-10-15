import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createPublicKey, verify } from 'node:crypto';
import { ComputeBudgetProgram, PublicKey, VersionedTransaction } from '@solana/web3.js';
import { relaySubmissionDigest, validateRelaySubmission } from './relay-http-client.mjs';
import { parseV9Packet, parseV9ExitPacket, processInstructionV9, exitInstructionV9 } from './instructions.mjs';
import { publicV9Receipt } from './wallet.mjs';
const json = (v) => JSON.stringify(v, (_, x) => typeof x === 'bigint' ? x.toString() : x);
const digestPattern = /^[a-f0-9]{64}$/;
const statuses = new Set(['queued', 'running', 'unknown', 'complete', 'failed']);
function publicResult(result) {
  if (!result || result.confirmed !== true || typeof result.signature !== 'string' || !result.signature) throw Error('Неверное подтверждение релейера');
  return publicV9Receipt(result);
}
function signatureBase58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let value = BigInt(`0x${Buffer.from(bytes).toString('hex')}`), result = '';
  while (value) { result = alphabet[Number(value % 58n)] + result; value /= 58n; }
  for (const byte of bytes) { if (byte) break; result = '1' + result; } return result;
}
// Only signed bytes from this relayer/program may resolve a job. A status or
// matching operation kind alone cannot establish which HTTP request was sent.
function linkedReceipt(relayer, job, record) {
  if (record.requestDigest !== job.digest || !digestPattern.test(record.requestDigest)
    || !['operation', 'emergency'].includes(record.kind) || (job.kind && job.kind !== record.kind)
    || typeof record.signedTransaction !== 'string') return null;
  const raw = Buffer.from(record.signedTransaction, 'base64');
  if (raw.toString('base64') !== record.signedTransaction || raw.length > 1232) return null;
  const tx = VersionedTransaction.deserialize(raw), payer = new PublicKey(relayer.keypair.publicKey);
  if (tx.signatures.length !== 1 || tx.message.header.numRequiredSignatures !== 1
    || !tx.message.staticAccountKeys[0].equals(payer) || record.blockhash !== tx.message.recentBlockhash
    || record.signature !== signatureBase58(tx.signatures[0])) return null;
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), payer.toBuffer()]), format: 'der', type: 'spki' });
  if (!verify(null, tx.message.serialize(), publicKey, tx.signatures[0])) return null;
  const keys = tx.message.getAccountKeys({ addressLookupTableAccounts: relayer.lookupTable ? [relayer.lookupTable] : [] });
  const instructions = tx.message.compiledInstructions;
  if (instructions.length !== 2 || !keys.get(instructions[0].programIdIndex).equals(ComputeBudgetProgram.programId)
    || !Buffer.from(instructions[0].data).equals(ComputeBudgetProgram.setComputeUnitLimit({ units: 1400000 }).data)) return null;
  const instruction = instructions[1], programId = new PublicKey(relayer.programId);
  if (!keys.get(instruction.programIdIndex).equals(programId)) return null;
  const packet = Buffer.from(instruction.data), exit = record.kind === 'emergency';
  const decoded = (exit ? parseV9ExitPacket : parseV9Packet)(packet);
  if (instruction.accountKeyIndexes.length !== (exit ? 16 : 22)) return null;
  const lanes = decoded.laneKinds.map((kind, i) => ({ kind, amount: decoded.laneAmounts[i].toString(),
    address: keys.get(instruction.accountKeyIndexes[7 + i * 3]).toBase58(),
    mint: keys.get(instruction.accountKeyIndexes[9 + i * 3]).toBase58() }));
  const request = { version: 1, kind: record.kind, packet: packet.toString('base64'), lanes };
  validateRelaySubmission(request, exit);
  if (relaySubmissionDigest(request) !== job.digest) return null;
  const expected = (exit ? exitInstructionV9 : processInstructionV9)(relayer.core, programId, payer, packet, lanes);
  if (expected.keys.some((meta, i) => !keys.get(instruction.accountKeyIndexes[i]).equals(meta.pubkey))) return null;
  return { signature: record.signature, kind: record.kind, transactionBytes: raw.length,
    computeUnits: Number.isSafeInteger(record.computeUnits) && record.computeUnits >= 0 ? record.computeUnits : null,
    confirmed: true, publicEdges: decoded.laneKinds.some((kind) => kind !== 0) };
}
export function createRelayJobResolver(relayer) {
  return async (job) => {
    if (relayer.journal?.version !== 1 || !Array.isArray(relayer.journal.requests)) return null;
    const matching = [];
    for (const record of relayer.journal.requests) {
      if (record?.requestDigest !== job.digest) continue;
      try { const receipt = linkedReceipt(relayer, job, record); if (receipt) matching.push({ record, receipt }); }
      catch { /* Missing ALT or malformed signed source remains unresolved. */ }
    }
    if (matching.length !== 1) return null;
    const { record, receipt } = matching[0];
    if (record.status === 'confirmed') return { status: 'complete', result: receipt };
    if (['rejected', 'simulation-rejected'].includes(record.status)) return { status: 'failed', error: `Транзакция ${receipt.signature} отклонена` };
    const response = await relayer.connection.getSignatureStatuses([receipt.signature], { searchTransactionHistory: true });
    const status = response?.value?.[0];
    if (!status || !['confirmed', 'finalized'].includes(status.confirmationStatus)) return null;
    return status.err ? { status: 'failed', error: `Транзакция ${receipt.signature} отклонена` }
      : { status: 'complete', result: receipt };
  };
}
export class RelayJobLedger {
  constructor({ path, submit, submitExit, resolveUnknown, maxJobs = 10000, journalScope }) {
    Object.assign(this, { path, submit, submitExit, resolveUnknown, maxJobs, journalScope }); this.queue = Promise.resolve(); this.jobs = new Map();
    if (path && existsSync(path)) {
      const doc = JSON.parse(readFileSync(path, 'utf8'));
      if (journalScope && JSON.stringify(doc.scope) !== JSON.stringify(journalScope)) throw Error('Relay jobs ledger/program/artifact scope mismatch; no replay attempted');
      if (doc.version !== 1 || !Array.isArray(doc.jobs) || doc.jobs.length > maxJobs) throw Error('Неверный журнал релейера');
      for (const job of doc.jobs) { if (!/^[a-f0-9-]{36}$/.test(job.id) || !digestPattern.test(job.digest) || !statuses.has(job.status)
          || (job.kind !== undefined && !['operation', 'emergency'].includes(job.kind)) || this.jobs.has(job.id)
          || Object.keys(job).some((key) => !['id', 'digest', 'kind', 'status', 'createdAt', 'completedAt', 'error', 'result'].includes(key))) throw Error('Повреждённый журнал релейера');
        if (job.result) job.result = publicResult(job.result);
        if (['queued', 'running'].includes(job.status)) { job.status = 'unknown'; job.error = 'Сервис перезапущен: проверьте статус до новой отправки'; }
        this.jobs.set(job.id, job); }
      this.save();
    }
  }
  save() { if (!this.path) return; mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path + '.tmp', json({ version: 1, ...(this.journalScope ? { scope: this.journalScope } : {}), jobs: [...this.jobs.values()] }), { mode: 0o600 }); renameSync(this.path + '.tmp', this.path); }
  accept(id, request, exit = false) {
    if (typeof id !== 'string' || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(id)) throw Error('Неверный номер запроса');
    validateRelaySubmission(request, exit); const digest = relaySubmissionDigest(request), old = this.jobs.get(id);
    if (old) { if (old.digest !== digest) throw Error('Номер запроса уже занят другим пакетом'); return old; }
    if (this.jobs.size >= this.maxJobs) throw Error('Журнал релейера заполнен: новые запросы временно недоступны');
    const job = { id, digest, kind: exit ? 'emergency' : 'operation', status: 'queued', createdAt: Date.now() }; this.jobs.set(id, job); this.save();
    this.queue = this.queue.then(async () => { job.status = 'running'; this.save();
      try { job.result = publicResult(await (exit ? this.submitExit : this.submit)(request, { id, digest })); job.status = 'complete'; }
      catch (e) { job.status = e.code === 'MAINNET_OPERATION_UNRESOLVED' || /статус|перед повтором|перед новым переводом/i.test(e.message) ? 'unknown' : 'failed'; job.error = String(e.message).slice(0, 650); }
      finally { job.completedAt = Date.now(); this.save(); }
    });
    return job;
  }
  async reconcileUnknown() {
    await this.idle();
    if (!this.resolveUnknown) return;
    for (const job of this.jobs.values()) {
      if (job.status !== 'unknown') continue;
      let outcome; try { outcome = await this.resolveUnknown({ id: job.id, digest: job.digest, kind: job.kind }); }
      catch { continue; }
      if (!outcome || !['complete', 'failed'].includes(outcome.status)) continue;
      if (outcome.status === 'complete') job.result = publicResult(outcome.result);
      else job.error = String(outcome.error ?? 'Транзакция отклонена').slice(0, 650);
      job.status = outcome.status; job.completedAt = Date.now(); if (job.status === 'complete') delete job.error; this.save();
    }
  }
  get(id) { return this.jobs.get(id); }
  async idle() { await this.queue; }
}
