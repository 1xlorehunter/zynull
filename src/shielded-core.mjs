import { buildPoseidon } from 'circomlibjs';
import { SparseMerkleTree } from './sparse-merkle-tree.mjs';

const FR = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export async function buildShieldedCore() {
  const poseidon = await buildPoseidon();
  const field = poseidon.F;
  const hash = (...values) => BigInt(field.toString(poseidon(values.map(BigInt))));
  const ownerPublic = (secret) => hash(31n, secret);
  const commitment = ({ asset, amount, ownerPub, nonce }) => hash(11n, asset, amount, ownerPub, nonce);
  const nullifier = (secret, noteCommitment) => hash(21n, secret, noteCommitment);

  class MerkleTree extends SparseMerkleTree {
    constructor(depth) {
      super({ depth, hashPair: hash, validateValue: (value) => value < FR });
      const tree = this;
      // Compatibility with older CLI callers without tying the count to an
      // Array's 32-bit length. The sequence visits actual leaves on demand.
      const sequence = {
        get length() { return tree.count; },
        *[Symbol.iterator]() { for (let i = 0; i < tree.count; i++) yield tree.leaf(i); },
        map(callback) {
          if (tree.count >= 2 ** 32) throw new Error('use streaming leaves at full capacity');
          return Array.from(this, (value, index) => callback(value, index, this));
        },
        indexOf(value) {
          for (let i = 0; i < tree.count; i++) if (tree.leaf(i) === value) return i;
          return -1;
        },
      };
      this.leaves = new Proxy(sequence, { get(target, key, receiver) {
        if (typeof key === 'string' && /^(0|[1-9]\d*)$/.test(key)) {
          const index = Number(key);
          return Number.isSafeInteger(index) && index < tree.count ? tree.leaf(index) : undefined;
        }
        return Reflect.get(target, key, receiver);
      } });
    }
    levels() {
      if (this.depth > 16) throw new Error('dense Merkle levels disabled; use sparse snapshot or paths');
      const zeroLevels = [0n];
      for (let level = 0; level < this.depth; level++) {
        zeroLevels.push(hash(zeroLevels[level], zeroLevels[level]));
      }
      return this.snapshot().nodes.map((entries, level) => {
        const nodes = new Map(entries.map(([index, value]) => [index, BigInt(value)]));
        return Array.from({ length: 2 ** (this.depth - level) },
          (_, index) => nodes.get(index) ?? zeroLevels[level]);
      });
    }
  }
  return { hash, ownerPublic, commitment, nullifier, MerkleTree };
}
