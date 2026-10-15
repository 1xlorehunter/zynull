import { PublicKey, SYSVAR_SLOT_HASHES_PUBKEY } from '@solana/web3.js';

const SYSVAR_OWNER = new PublicKey('Sysvar1111111111111111111111111111111111111');
const MAX_SLOTS = 512, ENTRY_BYTES = 40;

// getSlot may return the current bank, which is not yet in SlotHashes and is
// rejected by the address lookup program. Select a slot actually in the sysvar.
export async function readRecentLookupSlot(connection) {
  const { context, value } = await connection.getAccountInfoAndContext(SYSVAR_SLOT_HASHES_PUBKEY, 'confirmed');
  if (!Number.isSafeInteger(context?.slot) || context.slot <= 0 || !value || value.executable
    || !value.owner?.equals(SYSVAR_OWNER)) throw Error('Invalid SlotHashes sysvar account or context');
  const bytes = Buffer.from(value.data);
  if (bytes.length < 8 || bytes.length > 8 + MAX_SLOTS * ENTRY_BYTES) throw Error('Invalid SlotHashes sysvar size');
  const countValue = bytes.readBigUInt64LE(0);
  if (countValue < 1n || countValue > BigInt(MAX_SLOTS)) throw Error('Invalid SlotHashes entry count');
  const count = Number(countValue), expected = 8 + count * ENTRY_BYTES;
  if (bytes.length < expected || (bytes.length !== expected && bytes.length !== 8 + MAX_SLOTS * ENTRY_BYTES)) throw Error('Truncated SlotHashes sysvar');
  let first, previous = BigInt(context.slot);
  for (let index = 0; index < count; index++) {
    const slot = bytes.readBigUInt64LE(8 + index * ENTRY_BYTES);
    if (slot >= previous || slot > BigInt(Number.MAX_SAFE_INTEGER)) throw Error('Invalid SlotHashes slot ordering');
    if (first === undefined) first = Number(slot);
    previous = slot;
  }
  return { recentSlot: first, contextSlot: context.slot };
}
