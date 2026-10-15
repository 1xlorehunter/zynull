// Experimental mapping of a 32-byte SPL mint into the circuit's BN254 field.
// The Solana program must reproduce this Poseidon call byte-for-byte before
// accepting a real token deposit or withdrawal.
export function mintToAssetId(core, mintBytes) {
  if (!(mintBytes instanceof Uint8Array) || mintBytes.length !== 32) {
    throw new Error('SPL mint must be 32 bytes');
  }
  const first = BigInt(`0x${Buffer.from(mintBytes.subarray(0, 16)).toString('hex')}`);
  const second = BigInt(`0x${Buffer.from(mintBytes.subarray(16)).toString('hex')}`);
  const id = core.hash(51n, first, second);
  if (id === 0n) throw new Error('mint ID collides with reserved SOL identifier');
  return id;
}
