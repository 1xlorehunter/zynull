import { createHash, randomUUID } from 'node:crypto';
import { PublicKey } from '@solana/web3.js';
import { parseV9Packet, parseV9ExitPacket } from './instructions.mjs';
import { publicV9Receipt } from './wallet.mjs';

export function validateRelaySubmission(request, exit = false) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
    || Object.keys(request).sort().join(',') !== 'kind,lanes,packet,version' || request.version !== 1
    || request.kind !== (exit ? 'emergency' : 'operation') || typeof request.packet !== 'string'
    || !Array.isArray(request.lanes) || request.lanes.length !== (exit ? 2 : 4)) throw Error('Неверный готовый пакет перевода');
  const bytes = Buffer.from(request.packet, 'base64');
  if (bytes.toString('base64') !== request.packet) throw Error('Неверное кодирование пакета');
  (exit ? parseV9ExitPacket : parseV9Packet)(bytes);
  for (const lane of request.lanes) {
    if (!lane || Object.keys(lane).sort().join(',') !== 'address,amount,kind,mint' || ![0, 1, 2].includes(lane.kind)
      || typeof lane.amount !== 'string' || !/^(0|[1-9]\d*)$/.test(lane.amount) || BigInt(lane.amount) >= 1n << 64n) throw Error('Неверный публичный маршрут');
    for (const name of ['address', 'mint']) if (new PublicKey(lane[name]).toBase58() !== lane[name]) throw Error('Неверный адрес маршрута');
  }
  return bytes;
}
export function relaySubmissionDigest(request) { return createHash('sha256').update(JSON.stringify([request.version, request.kind,
  request.packet, request.lanes.map((lane) => [lane.kind, lane.amount, lane.address, lane.mint])])).digest('hex'); }
export class RelayHttpClient {
  constructor({ baseUrl, token, payer, fetchImpl = fetch, onStatus, timeoutMs = 180000, pollMs = 750 }) {
    const url = new URL(baseUrl), local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if ((!local || url.protocol !== 'http:') && url.protocol !== 'https:') throw Error('Релейер должен использовать HTTPS или localhost');
    if (url.username || url.password || url.search || url.hash || url.pathname !== '/') throw Error('Неверный адрес релейера');
    if (typeof token !== 'string' || token.length < 24 || token.length > 256) throw Error('Нужен ключ доступа к релейеру');
    Object.assign(this, { baseUrl: url.origin, token, fetchImpl, onStatus, timeoutMs, pollMs });
    this.keypair = { publicKey: new PublicKey(payer) }; this.requests = new Map();
  }
  async _api(path, body, id) {
    const response = await this.fetchImpl(this.baseUrl + path, { method: body ? 'POST' : 'GET', redirect: 'error',
      signal: AbortSignal.timeout(15000), headers: { Authorization: `Bearer ${this.token}`, Origin: this.baseUrl,
        ...(body ? { 'Content-Type': 'application/json', 'Idempotency-Key': id } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    const raw = await response.text(); if (Buffer.byteLength(raw) > 262144) throw Error('Слишком большой ответ релейера');
    const data = JSON.parse(raw); if (!response.ok) throw Error(String(data.error ?? 'Релейер отклонил запрос').slice(0, 500)); return data;
  }
  async describe() { return this._api('/v1/descriptor'); }
  submit(request) { return this._submit(request, false); }
  submitExit(request) { return this._submit(request, true); }
  async _submit(request, exit) {
    validateRelaySubmission(request, exit); const digest = relaySubmissionDigest(request);
    const id = this.requests.get(digest) ?? randomUUID(); this.requests.set(digest, id);
    let job;
    // The same id/body is retried after a lost HTTP response. The service must
    // persist the id before broadcasting, and never create a second job.
    for (let attempt = 0; attempt < 2; attempt++) { try { job = await this._api(exit ? '/v1/exits' : '/v1/operations', request, id); break; }
      catch (error) { if (attempt) throw Error(`Статус запроса ${id} неизвестен. Проверьте его перед новым переводом: ${error.message}`); } }
    const deadline = Date.now() + this.timeoutMs;
    while (true) {
      if (job.id !== id) throw Error('Релейер вернул другой номер запроса');
      if (job.status === 'complete') { if (!job.result?.confirmed || !job.result.signature) throw Error('Релейер не подтвердил перевод'); return publicV9Receipt(job.result); }
      if (job.status === 'failed') throw Error(String(job.error ?? 'Перевод отклонён').slice(0, 500));
      if (job.status === 'unknown' || Date.now() >= deadline) throw Error(`Статус запроса ${id} неизвестен. Проверьте подтверждение перед новым переводом.`);
      if (!['queued', 'running'].includes(job.status)) throw Error('Неверный статус запроса');
      this.onStatus?.('Релейер проверяет и подтверждает перевод…');
      await new Promise((done) => setTimeout(done, this.pollMs)); job = await this._api('/v1/jobs/' + id);
    }
  }
}
