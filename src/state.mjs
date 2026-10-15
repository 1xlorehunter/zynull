import { bucketIdV7 as bucketIdV9 } from './account-addresses.mjs';
const V9_ROOT_HISTORY = 512, V9_TREE_DEPTH = 32;
const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const canonical = (bytes) => BigInt(`0x${bytes.toString('hex')}`) < FR;

export const V9_STATE_MAGIC = 'PSW9';
export const V9_STATE_OFFSETS = Object.freeze({ count: 5, rootsLength: 13, nextRoot: 15,
  root: 17, frontier: 49, roots: 49 + V9_TREE_DEPTH * 32 });
export const V9_STATE_BYTES = V9_STATE_OFFSETS.roots + V9_ROOT_HISTORY * 32;
export const V9_BUCKET_CAPACITY = 131072;
export const V9_BUCKET_MAGIC = 'PSN7';

export function parseV9State(data) {
  if (!Buffer.isBuffer(data) || data.length !== V9_STATE_BYTES
    || data.subarray(0, 4).toString() !== V9_STATE_MAGIC) throw new Error('invalid widened V9 state');
  const count = data.readBigUInt64LE(V9_STATE_OFFSETS.count);
  const rootsLength = data.readUInt16LE(V9_STATE_OFFSETS.rootsLength);
  const nextRoot = data.readUInt16LE(V9_STATE_OFFSETS.nextRoot);
  const completedOperations = count / 4n;
  const expectedRootsLength = Number(completedOperations + 1n < BigInt(V9_ROOT_HISTORY)
    ? completedOperations + 1n : BigInt(V9_ROOT_HISTORY));
  const expectedNextRoot = Number((completedOperations + 1n) % BigInt(V9_ROOT_HISTORY));
  if (count > (1n << BigInt(V9_TREE_DEPTH)) || count % 4n !== 0n
    || rootsLength !== expectedRootsLength || nextRoot !== expectedNextRoot) {
    throw new Error('invalid widened V9 state counters');
  }
  const root = data.subarray(V9_STATE_OFFSETS.root, V9_STATE_OFFSETS.root + 32);
  const roots = Array.from({ length: rootsLength }, (_, i) =>
    data.subarray(V9_STATE_OFFSETS.roots + i * 32, V9_STATE_OFFSETS.roots + (i + 1) * 32));
  if (!canonical(root) || roots.some((entry) => !canonical(entry))
    || Array.from({ length: V9_TREE_DEPTH }, (_, i) => data.subarray(49 + i * 32, 49 + (i + 1) * 32)).some((entry) => !canonical(entry))) {
    throw new Error('noncanonical V9 state field');
  }
  const latestIndex = (nextRoot + V9_ROOT_HISTORY - 1) % V9_ROOT_HISTORY;
  if (!roots[latestIndex]?.equals(root)) throw new Error('current V9 root missing from latest history slot');
  return { bump: data[4], count: Number(count), rootsLength, nextRoot, root, roots,
    depth: V9_TREE_DEPTH, capacity: 2 ** V9_TREE_DEPTH };
}

export function findV9RootIndex(data, root) {
  const expected = Buffer.isBuffer(root) ? root
    : Buffer.from(BigInt(root).toString(16).padStart(64, '0'), 'hex');
  if (expected.length !== 32) throw new Error('invalid V9 root');
  const index = parseV9State(data).roots.findIndex((known) => known.equals(expected));
  if (index < 0) throw new Error('V9 root expired; refresh the witness');
  return index;
}

// A borrowed view keeps lookup logarithmic and avoids building a Set containing
// every spent entry just to check one wallet note. Entries must be sorted.
export function parseV9SpentBucket(data, expectedBucket) {
  if (!Buffer.isBuffer(data) || data.length < 8 || data.subarray(0, 4).toString() !== V9_BUCKET_MAGIC) {
    throw new Error('invalid widened V9 spent bucket');
  }
  const count = data.readUInt32LE(4);
  if (count > V9_BUCKET_CAPACITY || data.length !== 8 + count * 32) throw new Error('invalid V9 bucket count');
  if (expectedBucket !== undefined && (!Number.isInteger(expectedBucket) || expectedBucket < 0 || expectedBucket > 31)) {
    throw new Error('invalid V9 bucket index');
  }
  const entry = (i) => data.subarray(8 + i * 32, 8 + (i + 1) * 32);
  for (let i = 0; i < count; i++) {
    if (!canonical(entry(i)) || (expectedBucket !== undefined && bucketIdV9(entry(i)) !== expectedBucket)
      || (i > 0 && Buffer.compare(entry(i - 1), entry(i)) >= 0)) throw new Error('invalid V9 bucket ordering or shard');
  }
  return { count, has(nullifier) {
    if (!Buffer.isBuffer(nullifier) || nullifier.length !== 32) throw new Error('invalid V9 nullifier');
    let low = 0, high = count;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      const comparison = Buffer.compare(entry(middle), nullifier);
      if (comparison < 0) low = middle + 1;
      else high = middle;
    }
    return low < count && entry(low).equals(nullifier);
  } };
}
