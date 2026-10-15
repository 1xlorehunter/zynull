import { PublicKey } from '@solana/web3.js';
import { mintToAssetId } from './assets.mjs';
import { vaultPda } from './program-addresses.mjs';

const scalar = (bytes) => BigInt(`0x${bytes.toString('hex')}`);
export function addressLimbsV7(address) {
  const bytes = new PublicKey(address).toBuffer();
  return [scalar(bytes.subarray(0, 16)), scalar(bytes.subarray(16))];
}
export function lanePaddingPdaV7(programId, laneIndex, component) {
  if (!Number.isInteger(laneIndex) || laneIndex < 0 || laneIndex > 3
    || !Number.isInteger(component) || component < 0 || component > 2) throw new Error('invalid lane padding');
  return PublicKey.findProgramAddressSync([Buffer.from('lane-padding'),
    Buffer.from([laneIndex]), Buffer.from([component])], programId)[0];
}
export function bucketPaddingPdaV7(programId, index) {
  if (!Number.isInteger(index) || index < 0 || index > 2) throw new Error('invalid V7 bucket padding');
  return PublicKey.findProgramAddressSync([Buffer.from('bucket-padding'), Buffer.from([index])], programId)[0];
}

export function bucketIdV7(nullifier) {
  if (!Buffer.isBuffer(nullifier) || nullifier.length !== 32) throw new Error('invalid V7 nullifier');
  return nullifier[31] & 31;
}

export function spentBucketPdaV7(programId, nullifier) {
  return PublicKey.findProgramAddressSync([Buffer.from('spent-bucket'),
    Buffer.from([bucketIdV7(nullifier)])], programId)[0];
}

export function normalizeV7Lanes(core, programId, payer, input = []) {
  if (!Array.isArray(input) || input.length > 4) throw new Error('V7 requires four public lane slots');
  return Array.from({ length: 4 }, (_, index) => {
    const lane = input[index] ?? { kind: 0, amount: 0n };
    const kind = Number(lane.kind ?? 0);
    const amount = BigInt(lane.amount ?? 0n);
    if (![0, 1, 2].includes(kind) || amount < 0n || amount >= 1n << 64n
      || (kind === 0 ? amount !== 0n : amount === 0n)) throw new Error('invalid V7 lane kind/amount');
    const pads = [0, 1, 2].map((component) => lanePaddingPdaV7(programId, index, component));
    if (kind === 0) return { kind, amount, asset: 0n, address: pads[0], vault: pads[1], mint: pads[2] };
    const address = new PublicKey(lane.address ?? (index < 2 && kind === 1 ? payer : undefined));
    if (kind === 1) {
      if (index < 2 && !address.equals(payer)) throw new Error('SOL deposit lane must use submitter');
      return { kind, amount, asset: 0n, address, vault: pads[1], mint: pads[2] };
    }
    const mint = new PublicKey(lane.mint);
    return { kind, amount, asset: mintToAssetId(core, mint.toBytes()), address,
      vault: vaultPda(programId, mint), mint };
  });
}

export function publicContextV7(core, programId, payer, lanes) {
  if (!Array.isArray(lanes) || lanes.length !== 4) throw new Error('V7 requires four lanes');
  const hashes = lanes.map((lane) => core.hash(81n, BigInt(lane.kind), BigInt(lane.asset),
    BigInt(lane.amount), ...addressLimbsV7(lane.address)));
  return core.hash(82n, ...addressLimbsV7(programId), ...addressLimbsV7(payer), ...hashes);
}
