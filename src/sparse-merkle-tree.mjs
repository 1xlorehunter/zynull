// Sequential Merkle tree with arithmetic indices. JavaScript's bitwise operators
// truncate indices to signed 32 bits, so they must not be used at depth 32.
export class SparseMerkleTree {
  #depth;
  #capacity;
  #count = 0;
  #hashPair;
  #validateValue;
  #zeroLevels;
  #nodes;

  constructor({ depth, hashPair, defaultLeaf = 0n, validateValue } = {}) {
    if (!Number.isInteger(depth) || depth < 1 || depth > 32) throw new Error('invalid Merkle depth');
    if (typeof hashPair !== 'function') throw new TypeError('Merkle hashPair must be a function');
    if (validateValue !== undefined && typeof validateValue !== 'function') {
      throw new TypeError('Merkle validateValue must be a function');
    }
    this.#depth = depth;
    this.#capacity = 2 ** depth;
    this.#hashPair = hashPair;
    this.#validateValue = validateValue;
    this.#zeroLevels = [this.#value(defaultLeaf, 'default leaf')];
    for (let level = 0; level < depth; level++) {
      const zero = this.#zeroLevels[level];
      this.#zeroLevels.push(this.#hash(zero, zero));
    }
    this.#nodes = Array.from({ length: depth + 1 }, () => new Map());
  }

  #value(value, label) {
    if (typeof value === 'number' && !Number.isSafeInteger(value)) {
      throw new TypeError(`invalid Merkle ${label}: unsafe integer`);
    }
    if (!['bigint', 'number', 'string'].includes(typeof value)
      || (typeof value === 'string' && value.trim() === '')) {
      throw new TypeError(`invalid Merkle ${label}`);
    }
    let parsed;
    try { parsed = BigInt(value); }
    catch { throw new TypeError(`invalid Merkle ${label}`); }
    if (parsed < 0n || this.#validateValue?.(parsed, label) === false) {
      throw new Error(`invalid Merkle ${label}`);
    }
    return parsed;
  }

  #hash(left, right) { return this.#value(this.#hashPair(left, right), 'hash result'); }
  #at(level, index) { return this.#nodes[level].get(index) ?? this.#zeroLevels[level]; }

  get depth() { return this.#depth; }
  get capacity() { return this.#capacity; }
  get count() { return this.#count; }
  get defaultLeaf() { return this.#zeroLevels[0]; }

  append(leaf) {
    if (this.#count >= this.#capacity) throw new Error('Merkle tree full');
    const index = this.#count;
    let cursor = index;
    let value = this.#value(leaf, 'leaf');
    const updates = [{ level: 0, index: cursor, value }];
    // Stage the whole path before mutating the tree. A rejected field value or
    // failed hash must leave the root, count and stored nodes unchanged.
    for (let level = 0; level < this.#depth; level++) {
      const bit = cursor % 2;
      const sibling = this.#at(level, bit === 0 ? cursor + 1 : cursor - 1);
      value = bit === 0 ? this.#hash(value, sibling) : this.#hash(sibling, value);
      cursor = Math.floor(cursor / 2);
      updates.push({ level: level + 1, index: cursor, value });
    }
    for (const update of updates) {
      if (update.value === this.#zeroLevels[update.level]) this.#nodes[update.level].delete(update.index);
      else this.#nodes[update.level].set(update.index, update.value);
    }
    this.#count++;
    return index;
  }

  root() { return this.#at(this.#depth, 0); }

  #checkLeafIndex(index) {
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.#count) throw new Error('unknown leaf');
  }

  leaf(index) {
    this.#checkLeafIndex(index);
    return this.#at(0, index);
  }

  path(index) {
    this.#checkLeafIndex(index);
    const siblings = [];
    const pathBits = [];
    let cursor = index;
    for (let level = 0; level < this.#depth; level++) {
      const bit = cursor % 2;
      pathBits.push(BigInt(bit));
      siblings.push(this.#at(level, bit === 0 ? cursor + 1 : cursor - 1));
      cursor = Math.floor(cursor / 2);
    }
    return { root: this.root(), siblings, pathBits };
  }

  // Missing entries mean the configured default subtree, not opaque or trusted
  // historical subtrees. A snapshot therefore retains every nondefault leaf.
  snapshot() {
    return {
      version: 1,
      depth: this.#depth,
      count: this.#count,
      defaultLeaf: String(this.defaultLeaf),
      root: String(this.root()),
      nodes: this.#nodes.map((nodes) => [...nodes.entries()]
        .sort(([a], [b]) => a - b).map(([index, value]) => [index, String(value)])),
    };
  }

  static fromSnapshot(snapshot, { hashPair, validateValue } = {}) {
    if (!snapshot || snapshot.version !== 1) throw new Error('invalid Merkle snapshot version');
    const tree = new SparseMerkleTree({ depth: snapshot.depth, hashPair,
      defaultLeaf: snapshot.defaultLeaf, validateValue });
    if (!Number.isSafeInteger(snapshot.count) || snapshot.count < 0 || snapshot.count > tree.capacity) {
      throw new Error('invalid Merkle snapshot count');
    }
    if (!Array.isArray(snapshot.nodes) || snapshot.nodes.length !== tree.depth + 1) {
      throw new Error('invalid Merkle snapshot levels');
    }
    const claimedRoot = tree.#value(snapshot.root, 'snapshot root');
    for (let level = 0; level <= tree.depth; level++) {
      const entries = snapshot.nodes[level];
      if (!Array.isArray(entries)) throw new Error('invalid Merkle snapshot nodes');
      for (const entry of entries) {
        if (!Array.isArray(entry) || entry.length !== 2) throw new Error('invalid Merkle snapshot node');
        const [index, rawValue] = entry;
        if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** (tree.depth - level)
          || index * 2 ** level >= snapshot.count) throw new Error('invalid Merkle snapshot node index');
        if (tree.#nodes[level].has(index)) throw new Error('duplicate Merkle snapshot node');
        const value = tree.#value(rawValue, 'snapshot node');
        if (value === tree.#zeroLevels[level]) throw new Error('noncanonical Merkle default node');
        tree.#nodes[level].set(index, value);
      }
    }
    // Verify every stored parent against its children, including missing parents.
    // Work is proportional to the materialized nodes, never to tree capacity.
    for (let level = 0; level < tree.depth; level++) {
      const parentIndices = new Set([...tree.#nodes[level].keys()].map((index) => Math.floor(index / 2)));
      const expected = new Map();
      for (const index of parentIndices) {
        const value = tree.#hash(tree.#at(level, index * 2), tree.#at(level, index * 2 + 1));
        if (value !== tree.#zeroLevels[level + 1]) expected.set(index, value);
      }
      const actual = tree.#nodes[level + 1];
      if (expected.size !== actual.size || [...expected].some(([index, value]) => actual.get(index) !== value)) {
        throw new Error('inconsistent Merkle snapshot topology');
      }
    }
    if (tree.root() !== claimedRoot) throw new Error('Merkle snapshot root mismatch');
    tree.#count = snapshot.count;
    return tree;
  }
}
