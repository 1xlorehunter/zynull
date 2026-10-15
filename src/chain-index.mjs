import { createHash, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { PublicKey } from '@solana/web3.js';
import { buildShieldedCore } from './shielded-core.mjs';
import { statePda } from './program-addresses.mjs';
import { parseV9Packet } from './instructions.mjs';
import { decodeTripleNoteBinaryV9 } from './notes.mjs';
import { parseV9State, V9_STATE_MAGIC } from './state.mjs';


const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function decodeBase58(value) {
  let n = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error('invalid base58 transaction data');
    n = n * 58n + BigInt(digit);
  }
  const hex = n.toString(16);
  const raw = n === 0n ? Buffer.alloc(0) : Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
  return Buffer.concat([Buffer.alloc(value.match(/^1*/)[0].length), raw]);
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function canonicalJson(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  throw new Error('non-JSON public cache value');
}

// A checksum detects accidental file corruption. It is not authentication
// against an attacker who can replace the file and recompute its checksum.
export function chainCacheChecksum(document) {
  const { checksum, ...body } = document;
  return createHash('sha256').update('privacy-chain-index-cache-v2\0').update(canonicalJson(body)).digest('hex');
}
function cacheScalar(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) throw new Error('invalid cached scalar');
  const parsed = BigInt(value);
  if (parsed >= FR) throw new Error('noncanonical cached scalar');
  return parsed;
}
function validateCachedHistory(document, { depth, programId, snapshotCount, isV9, widenedState }) {
  if (document?.version !== 2 || document.depth !== depth || document.programId !== programId.toBase58()
    || typeof document.checksum !== 'string' || !/^[a-f0-9]{64}$/.test(document.checksum)
    || chainCacheChecksum(document) !== document.checksum || !Array.isArray(document.leaves)
    || document.leaves.length > snapshotCount || !Array.isArray(document.events)
    || (document.snapshotSlot !== null && (!Number.isSafeInteger(document.snapshotSlot) || document.snapshotSlot < 0))) {
    throw new Error('invalid public cache checksum or schema');
  }
  document.leaves.forEach(cacheScalar);
  let offset = 0;
  for (const event of document.events) {
    const counts = { 13: 4 };
    if (!event || typeof event.signature !== 'string' || !event.signature.length || event.signature.length > 256
      || !Number.isInteger(event.selector) || !counts[event.selector] || (isV9 && event.selector !== 13)
      || !Array.isArray(event.commitments) || event.commitments.length !== counts[event.selector]
      || !Array.isArray(event.deliveries)) throw new Error('invalid cached event shape');
    for (const value of event.commitments) {
      cacheScalar(value);
      if (value !== document.leaves[offset++]) throw new Error('cached events do not cover cached leaves');
    }
    if (event.selector === 13) {
      if (typeof event.packet !== 'string') throw new Error('modern cache event lacks raw packet');
      const raw = Buffer.from(event.packet, 'base64');
      if (raw.toString('base64') !== event.packet || raw[0] !== event.selector) throw new Error('invalid cached packet encoding');
      const packet = parseV9Packet(raw);
      const commitments = packet.commitments.map((bytes) => BigInt(`0x${bytes.toString('hex')}`));
      const inline = decodeTripleNoteBinaryV9(packet.delivery);
      const expectedDeliveries = inline.envelopes.map((envelope, i) => ({ commitment: commitments[i].toString(), envelope }));
      if (canonicalJson(commitments.map(String)) !== canonicalJson(event.commitments)
        || canonicalJson(expectedDeliveries) !== canonicalJson(event.deliveries)) throw new Error('cached delivery provenance differs from packet');
      if (event.selector === 13) {
        if (!Array.isArray(event.accountKeys) || event.accountKeys.length !== 22
          || event.accountKeys.some((key) => typeof key !== 'string' || new PublicKey(key).toBase58() !== key)) throw new Error('invalid V9 cached execution accounts');
        const expected = { payer: event.accountKeys[0], nullifiers: packet.nullifiers.map((nf) => nf.toString('hex')),
          feeAmount: packet.feeAmount.toString(), commitment: commitments[3].toString(),
          ephemeralPublicKey: inline.envelopes[0].ephemeralPublicKey };
        if (canonicalJson(expected) !== canonicalJson(event.v9)) throw new Error('cached V9 fee provenance differs from packet');
      }
    }
  }
  if (offset !== document.leaves.length || document.latestSignature !== (document.events.at(-1)?.signature ?? null)) {
    throw new Error('incomplete cached event history');
  }
  return document;
}

async function retry(operation, maxAttempts = 5) {
  for (let attempt = 0; ; attempt++) {
    try { return await operation(); }
    catch (error) {
      if (attempt >= maxAttempts || !/429|rate limit|Too Many Requests/i.test(String(error))) throw error;
      await sleep(Math.min(1000 * 2 ** attempt, 8000));
    }
  }
}

// RPC records inner instructions in execution order within each outer call.
// An instruction wrapper can invoke the current program through CPI.
export function orderedTransactionInstructions(transaction) {
  const message = transaction.transaction.message;
  const outer = message.instructions ?? message.compiledInstructions;
  if (!Array.isArray(outer)) throw new Error('missing transaction instructions');
  const inner = new Map();
  for (const group of transaction.meta?.innerInstructions ?? []) {
    if (!Number.isInteger(group.index) || group.index < 0 || group.index >= outer.length
      || inner.has(group.index) || !Array.isArray(group.instructions)) throw new Error('invalid inner instruction group');
    inner.set(group.index, group.instructions);
  }
  return outer.flatMap((instruction, index) => [instruction, ...(inner.get(index) ?? [])]);
}

export async function loadChainTree(connection, programId, { ignoreCache = false } = {}) {
  const stateAddress = statePda(programId);
  const snapshot = typeof connection.getAccountInfoAndContext === 'function'
    ? await retry(() => connection.getAccountInfoAndContext(stateAddress, 'confirmed'))
    : { value: await retry(() => connection.getAccountInfo(stateAddress, 'confirmed')), context: null };
  const state = snapshot.value;
  const snapshotSlot = snapshot.context?.slot ?? null;
  if (snapshotSlot !== null && (!Number.isSafeInteger(snapshotSlot) || snapshotSlot < 0)) {
    throw new Error('invalid state snapshot slot');
  }
  if (!state) throw new Error('state PDA not initialized');
  const magic = state.data.subarray(0, 4).toString('ascii');
  const isV9 = magic === V9_STATE_MAGIC;
  const widenedState = parseV9State(state.data);
  const depth = 32;
  const { MerkleTree } = await buildShieldedCore();
  const tree = new MerkleTree(depth);
  const snapshotCount = widenedState.count;
  const endpointId = createHash('sha256').update(connection.rpcEndpoint).digest('hex').slice(0, 12);
  const cachePath = `build/chain-index-${programId.toBase58()}-${endpointId}.json`;
  let cache = null;
  if (!ignoreCache && existsSync(cachePath)) {
    try {
      const loaded = JSON.parse(readFileSync(cachePath, 'utf8'));
      cache = validateCachedHistory(loaded, { depth, programId, snapshotCount, isV9, widenedState });
    } catch { /* A damaged public cache is rebuilt from the chain. */ }
  }
  const signatures = [];
  let before;
  let foundCachedHead = false;
  while (true) {
    const page = await retry(() => connection.getSignaturesForAddress(stateAddress,
      { limit: 1000, ...(before ? { before } : {}) }, 'confirmed'));
    const eligible = snapshotSlot === null ? page : page.filter(({ slot }) => slot <= snapshotSlot);
    const cachedHeadIndex = cache?.latestSignature
      ? eligible.findIndex(({ signature }) => signature === cache.latestSignature) : -1;
    if (cachedHeadIndex >= 0) {
      signatures.push(...eligible.slice(0, cachedHeadIndex));
      foundCachedHead = true;
      break;
    }
    signatures.push(...eligible);
    if (page.length < 1000) break;
    before = page.at(-1).signature;
  }
  if (cache && !foundCachedHead) cache = null;
  let events = [];
  if (cache) {
    try {
      for (const leaf of cache.leaves) tree.append(BigInt(leaf));
      events = cache.events.map((event) => ({ ...event,
        commitments: event.commitments.map(BigInt),
        deliveries: (event.deliveries ?? []).map((delivery) => ({
          ...delivery, commitment: delivery.commitment === null ? null : BigInt(delivery.commitment),
        })),
      }));
    } catch {
      // A parseable but damaged public cache must not prevent seed recovery.
      return loadChainTree(connection, programId, { ignoreCache: true });
    }
  }
  const chronological = signatures.reverse();
  for (let offset = 0; offset < chronological.length; offset += 8) {
    const batch = chronological.slice(offset, offset + 8);
    let transactions;
    try {
      transactions = await retry(() => connection.getTransactions(
        batch.map(({ signature }) => signature),
        { commitment: 'confirmed', maxSupportedTransactionVersion: 0 },
      ), 1);
    } catch (error) {
      if (!/429|rate limit|Too Many Requests/i.test(String(error))) throw error;
      // Public devnet RPC often rejects batched getTransactions even when
      // individual getTransaction calls still work. Keep the fallback slow.
      transactions = [];
      for (const { signature } of batch) {
        transactions.push(await retry(() => connection.getTransaction(signature,
          { commitment: 'confirmed', maxSupportedTransactionVersion: 0 })));
        await sleep(300);
      }
    }
    // JSON-RPC batch replies may arrive out of order even when the requests
    // were ordered. Reassociate by transaction signature before appending.
    const bySignature = new Map(transactions.filter(Boolean).map((transaction) => [
      transaction.transaction.signatures[0], transaction,
    ]));
    for (let i = 0; i < batch.length; i++) {
      const { signature } = batch[i];
      const tx = bySignature.get(signature);
      if (!tx || tx.meta?.err) continue;
      const message = tx.transaction.message;
      const keys = (message.accountKeys ?? [...message.staticAccountKeys,
        ...(tx.meta?.loadedAddresses?.writable ?? []),
        ...(tx.meta?.loadedAddresses?.readonly ?? [])]).map((key) => new PublicKey(key));
      const instructions = orderedTransactionInstructions(tx);
      const instructionBytes = (instruction) => typeof instruction.data === 'string'
        ? decodeBase58(instruction.data) : Buffer.from(instruction.data);
      for (const instruction of instructions) {
        // A provider can expose later history while the saved account snapshot
        // is older. Stop at its exact append count, including same-slot races;
        // the final root check still authenticates this complete prefix.
        if (tree.count === snapshotCount) break;
        if (!keys[instruction.programIdIndex].equals(programId)) continue;
        const data = instructionBytes(instruction);
        const selector = data[0];
        let commitments, v9, v9AccountKeys, modernDeliveries;
        if (selector === 13) {
          if (!isV9) throw new Error('V9 operation requires PSW9 state');
          const packet = parseV9Packet(data);
          commitments = packet.commitments.map((bytes) => BigInt(`0x${bytes.toString('hex')}`));
          const inline = decodeTripleNoteBinaryV9(packet.delivery);
          modernDeliveries = inline.envelopes.map((envelope, index) => ({
            commitment: commitments[index], envelope,
          }));
          const accountIndexes = instruction.accountKeyIndexes ?? instruction.accounts;
          if (accountIndexes?.length !== 22 || Array.from(accountIndexes).some((index) => !keys[index])) throw new Error('missing V9 execution accounts');
          v9AccountKeys = Array.from(accountIndexes, (index) => keys[index].toBase58());
          v9 = { payer: keys[accountIndexes[0]].toBase58(),
            nullifiers: packet.nullifiers.map((nf) => nf.toString('hex')),
            feeAmount: packet.feeAmount.toString(), commitment: commitments[3].toString(),
            ephemeralPublicKey: inline.envelopes[0].ephemeralPublicKey };
        } else continue;
        if (tree.count + commitments.length > snapshotCount) {
          throw new Error('operation crosses state snapshot append count');
        }
        for (const commitment of commitments) tree.append(commitment);
        events.push({ signature, selector, commitments, ...(selector === 13 ? { packet: data.toString('base64') } : {}),
          ...(v9 ? { v9, accountKeys: v9AccountKeys } : {}),
          deliveries: modernDeliveries,
        });
      }
    }
  }
  const stateCount = widenedState.count;
  const stateRoot = widenedState.root;
  if (stateCount !== tree.count
    || stateRoot.toString('hex') !== tree.root().toString(16).padStart(64, '0')) {
    if (cache && !ignoreCache) return loadChainTree(connection, programId, { ignoreCache: true });
    throw new Error(`reconstructed Merkle tree differs from onchain state (${tree.count}/${stateCount} commitments). Full recovery requires available transaction history; use an archival RPC if history was pruned`);
  }
  mkdirSync(dirname(cachePath), { recursive: true });
  const temporary = `${cachePath}.${randomUUID()}.tmp`;
  const latestSignature = events.at(-1)?.signature ?? null;
  const payload = {
    version: 2, depth, programId: programId.toBase58(), latestSignature, snapshotSlot,
    leaves: tree.leaves.map(String),
    events: events.map((event) => ({ ...event, commitments: event.commitments.map(String),
      deliveries: event.deliveries.map((delivery) => ({
        ...delivery, commitment: delivery.commitment === null ? null : String(delivery.commitment),
      })),
    })),
  };
  writeFileSync(temporary, JSON.stringify({ ...payload, checksum: chainCacheChecksum(payload) }));
  renameSync(temporary, cachePath);
  return { tree, events, stateAddress, snapshotSlot };
}
