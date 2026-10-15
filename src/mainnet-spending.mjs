import { createHash, createPublicKey, verify } from 'node:crypto';
import { PublicKey, VersionedTransaction } from '@solana/web3.js';

export const MAINNET_SPENDING_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
export const MAINNET_READ_METHODS = Object.freeze([
  'getGenesisHash', 'getVersion', 'getHealth', 'getSlot', 'getBlockHeight', 'getLatestBlockhash',
  'isBlockhashValid', 'getAccountInfo', 'getMultipleAccounts', 'getProgramAccounts', 'getBalance',
  'getMinimumBalanceForRentExemption', 'getFeeForMessage', 'getSignatureStatuses',
  'getSignaturesForAddress', 'getTransaction', 'getBlock', 'getBlockTime', 'getBlocks',
  'getTokenAccountBalance', 'getTokenAccountsByOwner', 'getTokenSupply', 'getRecentPrioritizationFees',
  'simulateTransaction',
]);
const reads = new Set(MAINNET_READ_METHODS);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const publicKeyPrefix = Buffer.from('302a300506032b6570032100', 'hex');
const MAX_LAMPORTS = 18446744073709551615n;
function base58(bytes) {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let value = BigInt('0x' + Buffer.from(bytes).toString('hex')), result = '';
  while (value) { result = alphabet[Number(value % 58n)] + result; value /= 58n; }
  for (const byte of bytes) { if (byte) break; result = '1' + result; }
  return result;
}
export class MainnetSpendingDisabled extends Error {
  constructor(message = 'Mainnet spending is disabled. A funded wallet is not spending authorization.') {
    super(message); this.name = 'MainnetSpendingDisabled'; this.code = 'MAINNET_SPENDING_DISABLED';
  }
}
function requestValue(value) {
  if (!value || Array.isArray(value) || typeof value !== 'object' || value.jsonrpc !== '2.0'
    || typeof value.method !== 'string' || !Array.isArray(value.params ?? [])
    || Object.keys(value).some(key => !['jsonrpc', 'id', 'method', 'params'].includes(key))
    || !['number', 'string'].includes(typeof value.id)) throw new MainnetSpendingDisabled('Unrecognized mainnet RPC request.');
  return value;
}
export function inspectSignedMainnetTransaction(encoded) {
  if (typeof encoded !== 'string' || encoded.length > 1644) throw new MainnetSpendingDisabled('Invalid mainnet transaction encoding.');
  const rawTransaction = Buffer.from(encoded, 'base64');
  if (rawTransaction.length > 1232 || !rawTransaction.length || rawTransaction.toString('base64') !== encoded) throw new MainnetSpendingDisabled('Invalid mainnet transaction encoding.');
  let tx;
  try { tx = VersionedTransaction.deserialize(rawTransaction); } catch { throw new MainnetSpendingDisabled('Invalid mainnet transaction.'); }
  if (!Buffer.from(tx.serialize()).equals(rawTransaction)) throw new MainnetSpendingDisabled('Noncanonical mainnet transaction.');
  const keys = tx.message.staticAccountKeys ?? tx.message.accountKeys, message = tx.message.serialize();
  if (!tx.signatures.length || tx.signatures.length !== tx.message.header.numRequiredSignatures) throw new MainnetSpendingDisabled('Mainnet transaction is not fully signed.');
  for (let i = 0; i < tx.signatures.length; i++) {
    const key = createPublicKey({ key: Buffer.concat([publicKeyPrefix, keys[i].toBuffer()]), type: 'spki', format: 'der' });
    if (!verify(null, message, key, tx.signatures[i])) throw new MainnetSpendingDisabled('Mainnet transaction signature is invalid.');
  }
  return Object.freeze({ rawTransaction, encoding: 'base64', transactionSha256: sha(rawTransaction),
    signature: base58(tx.signatures[0]), feePayer: keys[0].toBase58(), messageBase64: Buffer.from(message).toString('base64') });
}

function rpcInteger(value) { return Number.isSafeInteger(value) && value >= 0; }
function nonbroadcastableSimulation(params) {
  if (!Array.isArray(params) || params.length !== 2 || params[1]?.encoding !== 'base64'
    || typeof params[0] !== 'string' || params[0].length > 1644) throw new MainnetSpendingDisabled('Mainnet simulations require bounded base64 transaction bytes.');
  const raw = Buffer.from(params[0], 'base64');
  if (!raw.length || raw.length > 1232 || raw.toString('base64') !== params[0]) throw new MainnetSpendingDisabled('Invalid mainnet simulation transaction.');
  let transaction;
  try { transaction = VersionedTransaction.deserialize(raw); if (!Buffer.from(transaction.serialize()).equals(raw)) throw Error(); }
  catch { throw new MainnetSpendingDisabled('Invalid mainnet simulation transaction.'); }
  if (params[1].sigVerify === true) inspectSignedMainnetTransaction(params[0]);
  for (const signature of transaction.signatures) signature.fill(0);
  return [Buffer.from(transaction.serialize()).toString('base64'), { ...params[1], sigVerify: false }];
}
// Read-only estimates are required for every proposed send, including public
// browser deposits and NORMAL/EXIT. They are RPC estimates, not an onchain cap.
// The exact bytes, reviewed estimate and explicit cap still require approval.
async function estimateDebit(fetchImpl, endpoint, options, inspected, encoded) {
  let id = 0;
  const read = async (method, params = []) => {
    const requestId = 'zynull-debit-' + ++id;
    let response, document;
    try {
      response = await fetchImpl(endpoint, { ...options, body: JSON.stringify({ jsonrpc: '2.0', id: requestId, method, params }) });
      if (!response?.ok) throw Error();
      document = await response.json();
    } catch { throw new MainnetSpendingDisabled('Mainnet debit estimate is unavailable; no transaction was sent.'); }
    if (document?.jsonrpc !== '2.0' || document.id !== requestId || document.error || !Object.hasOwn(document, 'result')) throw new MainnetSpendingDisabled('Invalid mainnet debit estimate RPC response.');
    return document.result;
  };
  if (await read('getGenesisHash') !== MAINNET_SPENDING_GENESIS) throw new MainnetSpendingDisabled('Debit estimate RPC differs from Solana mainnet.');
  const fee = await read('getFeeForMessage', [inspected.messageBase64, { commitment: 'confirmed' }]);
  if (!rpcInteger(fee?.value) || !rpcInteger(fee?.context?.slot)) throw new MainnetSpendingDisabled('Mainnet fee estimate is unavailable.');
  // An RPC provider must never receive broadcastable bytes before approval.
  // Verify the real signatures locally, then simulate the identical message
  // with every signature erased. No signer is sent to the RPC.
  const simulated = await read('simulateTransaction', nonbroadcastableSimulation([encoded, { encoding: 'base64', commitment: 'confirmed', sigVerify: true,
    minContextSlot: fee.context.slot, accounts: { encoding: 'base64', addresses: [inspected.feePayer] } }]));
  const value = simulated?.value, before = value?.preBalances?.[0], after = value?.postBalances?.[0];
  // Both balances must come from ONE simulation bank. An independently read
  // getBalance at an earlier slot can hide a debit behind an incoming credit.
  if (!value || value.err !== null || !rpcInteger(before) || !rpcInteger(after) || !rpcInteger(value.fee)
    || !Array.isArray(value.preBalances) || !Array.isArray(value.postBalances) || value.preBalances.length !== value.postBalances.length
    || value.accounts?.[0]?.lamports !== after || !rpcInteger(simulated.context?.slot)
    || simulated.context.slot < fee.context.slot) throw new MainnetSpendingDisabled('Mainnet signed-transaction simulation failed or its payer debit is unavailable.');
  // Adding the fee even when the simulator includes it makes this estimate
  // conservative. Never subtract a simulated credit from the network fee.
  const feeLamports = Math.max(fee.value, value.fee);
  const debit = BigInt(feeLamports) + (before > after ? BigInt(before) - BigInt(after) : 0n);
  return Object.freeze({ kind: 'simulated-fee-payer-debit', feeLamports: String(feeLamports), payerBalanceLamports: String(before),
    simulatedPayerBalanceLamports: String(after), slot: simulated.context.slot, maximumExpectedDebitLamports: debit.toString(),
    estimateOnly: true });
}

/** A second boundary beneath all web3.js submission helpers. No signer or permit is created here.
 * authorizeTransaction is trusted local integration code and MUST obtain explicit human
 * authorization for these exact bytes, fees and debit cap. It must return an exact digest
 * receipt. No runtime JSON flag, wallet balance or remote request supplies that callback.
 */
export function createMainnetRpcFetch({ fetchImpl = globalThis.fetch.bind(globalThis), authorizeTransaction, rpcUrl } = {}) {
  if (typeof fetchImpl !== 'function' || (authorizeTransaction !== undefined && typeof authorizeTransaction !== 'function')) throw TypeError('Invalid mainnet RPC policy.');
  const expectedUrl = rpcUrl === undefined ? undefined : new URL(rpcUrl).href;
  if (expectedUrl && !expectedUrl.startsWith('https://')) throw TypeError('Mainnet upstream RPC must use HTTPS.');
  return async function mainnetFetch(input, init = {}) {
    const suppliedUrl = typeof input === 'string' || input instanceof URL ? String(input) : input?.url;
    if (!suppliedUrl || new URL(suppliedUrl).protocol !== 'https:' || (expectedUrl && new URL(suppliedUrl).href !== expectedUrl)) throw new MainnetSpendingDisabled('Mainnet RPC endpoint differs from the configured HTTPS endpoint.');
    if ((init.method ?? 'GET').toUpperCase() !== 'POST' || typeof init.body !== 'string' || Buffer.byteLength(init.body) > 262144) throw new MainnetSpendingDisabled('Mainnet RPC requires a bounded explicit JSON request.');
    // Capture caller-owned mutable input before any authorization await. A
    // later change to init.body, headers or URL cannot replace reviewed bytes.
    const endpoint = new URL(suppliedUrl).href;
    const options = { method: 'POST', headers: new Headers(init.headers), body: init.body, redirect: 'error',
      ...(init.signal ? { signal: init.signal } : {}) };
    let parsed;
    try { parsed = JSON.parse(options.body); } catch { throw new MainnetSpendingDisabled('Invalid mainnet RPC JSON.'); }
    const batch = Array.isArray(parsed), requests = (batch ? parsed : [parsed]).map(requestValue);
    if (!requests.length || requests.length > 100) throw new MainnetSpendingDisabled('Invalid mainnet RPC batch.');
    for (const request of requests) if (request.method === 'simulateTransaction') request.params = nonbroadcastableSimulation(request.params);
    options.body = JSON.stringify(parsed);
    for (const request of requests) {
      if (reads.has(request.method)) continue;
      if (request.method !== 'sendTransaction' || batch || !authorizeTransaction) throw new MainnetSpendingDisabled();
      const params = request.params;
      if (!Array.isArray(params) || params.length !== 2 || params[1]?.encoding !== 'base64'
        || params[1]?.skipPreflight === true || params[1]?.maxRetries !== 0) throw new MainnetSpendingDisabled('Mainnet submission must use base64, preflight and explicit zero automatic RPC retries.');
      const inspected = inspectSignedMainnetTransaction(params[0]);
      const budget = await estimateDebit(fetchImpl, endpoint, options, inspected, params[0]);
      const info = Object.freeze({ ...inspected, rawTransaction: Buffer.from(inspected.rawTransaction),
        rpcMethod: 'sendTransaction', requestId: request.id, genesisHash: MAINNET_SPENDING_GENESIS, budget });
      const receipt = await authorizeTransaction(info);
      if (!receipt || receipt.approved !== true || receipt.transactionSha256 !== inspected.transactionSha256
        || receipt.genesisHash !== MAINNET_SPENDING_GENESIS || !/^[1-9]\d*$/.test(receipt.maximumDebitLamports ?? '')
        || BigInt(receipt.maximumDebitLamports) > MAX_LAMPORTS) throw new MainnetSpendingDisabled('Explicit authorization for this exact mainnet transaction and positive bounded debit is missing.');
      if (BigInt(receipt.maximumDebitLamports) < BigInt(budget.maximumExpectedDebitLamports)) throw new MainnetSpendingDisabled('Mainnet approval cap is below the transaction fee and simulated payer debit; no transaction was sent.');
    }
    // Redirects cannot move a reviewed request to an unreviewed upstream.
    return fetchImpl(endpoint, options);
  };
}

/** Verify an externally signed, exact-transaction review receipt. It is deliberately
 * not a standing relay budget. Fee/debit simulation and durable one-action journaling
 * remain the executor's responsibility before asking the human to approve.
 */
export function verifyExactMainnetApproval({ approval, expectedApprover, transactionSha256, programId,
  payer, now = Date.now() } = {}) {
  const message = approval?.message;
  if (!message || typeof message !== 'object' || Array.isArray(message)
    || Object.keys(message).sort().join(',') !== 'domain,expiresAt,genesisHash,maximumDebitLamports,payer,programId,transactionSha256,version'
    || message.version !== 1 || message.domain !== 'zynull-mainnet-exact-transaction-v1'
    || message.genesisHash !== MAINNET_SPENDING_GENESIS || message.transactionSha256 !== transactionSha256
    || !/^[a-f0-9]{64}$/.test(transactionSha256 ?? '') || message.programId !== programId || message.payer !== payer
    || !Number.isSafeInteger(now) || !Number.isSafeInteger(message.expiresAt) || message.expiresAt <= now
    || message.expiresAt - now > 15 * 60 * 1000 || !/^[1-9]\d*$/.test(message.maximumDebitLamports ?? '')
    || BigInt(message.maximumDebitLamports) > MAX_LAMPORTS) throw new MainnetSpendingDisabled('Mainnet approval does not match the exact reviewed action.');
  let key, signature;
  try {
    const address = new PublicKey(expectedApprover); new PublicKey(programId); new PublicKey(payer);
    key = createPublicKey({ key: Buffer.concat([publicKeyPrefix, address.toBuffer()]), type: 'spki', format: 'der' });
    signature = Buffer.from(approval.signatureBase64, 'base64');
    if (signature.length !== 64 || signature.toString('base64') !== approval.signatureBase64) throw Error();
  } catch { throw new MainnetSpendingDisabled('Invalid mainnet approval signer or signature.'); }
  const canonicalMessage = JSON.stringify({ domain: message.domain, expiresAt: message.expiresAt, genesisHash: message.genesisHash,
    maximumDebitLamports: message.maximumDebitLamports, payer: message.payer, programId: message.programId,
    transactionSha256: message.transactionSha256, version: message.version });
  if (!verify(null, Buffer.from(canonicalMessage), key, signature)) throw new MainnetSpendingDisabled('Mainnet approval signature does not match the reviewed user.');
  return Object.freeze({ approved: true, transactionSha256, genesisHash: MAINNET_SPENDING_GENESIS,
    authorizedBy: expectedApprover, maximumDebitLamports: message.maximumDebitLamports,
    approvalSha256: sha(Buffer.from(canonicalMessage)), expiresAt: message.expiresAt });
}
