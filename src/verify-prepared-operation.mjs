import { groth16 } from 'snarkjs';
import { PublicKey } from '@solana/web3.js';
import { parseV9State } from './state.mjs';
import { parseV9Packet, normalizeV9Lanes, publicContextV9 } from './instructions.mjs';
import { bindDeliveryV9 } from './notes.mjs';

const FP = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const scalar = (bytes) => BigInt(`0x${bytes.toString('hex')}`);

// Exact inverse of export-solana-proof: the runtime consumes -A, Fp2 c1/c0,
// then C. This transformation already passed real archive proof verification.
export function decodeSolanaGroth16Proof(input) {
  if (!(input instanceof Uint8Array) || input.length !== 256) throw new Error('Expected exactly 256 Solana Groth16 proof bytes');
  const bytes = Buffer.from(input), c = Array.from({ length: 8 }, (_, i) => scalar(bytes.subarray(i * 32, (i + 1) * 32)));
  if (c.some((n) => n >= FP)) throw new Error('Noncanonical Solana proof coordinate');
  return { protocol: 'groth16', curve: 'bn128', pi_a: [String(c[0]), String(c[1] === 0n ? 0n : FP - c[1]), '1'],
    pi_b: [[String(c[3]), String(c[2])], [String(c[5]), String(c[4])], ['1', '0']], pi_c: [String(c[6]), String(c[7]), '1'] };
}

// The caller supplies fresh, owner/PDA-checked general state and a pinned VK.
// This pure check sends no RPC requests and must precede public ALT spending.
// Separately check the DH fee owner/current fixed F before extending an ALT.
// Membership against retained history does not establish that NF is unspent;
// onchain simulation/replay/vault/account checks remain necessary.
export async function verifyPreparedOperation(core, { programId, payer, packet, stateData, vk, laneInput = [] }) {
  if (!(packet instanceof Uint8Array) || !(stateData instanceof Uint8Array)) throw new Error('Prepared operation/state must be binary');
  if (!core || typeof core.hash !== 'function' || !vk || vk.protocol !== 'groth16' || vk.curve !== 'bn128'
    || vk.nPublic !== 10 || !Array.isArray(vk.IC) || vk.IC.length !== 11) throw new Error('Pinned V9 Groth16 verifying key with ten public signals is required');
  const program = new PublicKey(programId), submitter = new PublicKey(payer);
  const decoded = parseV9Packet(Buffer.from(packet)), state = parseV9State(Buffer.from(stateData));
  const root = state.roots[decoded.rootIndex]; if (!root) throw new Error('Prepared operation root history slot expired/unavailable');
  const lanes = normalizeV9Lanes(core, program, submitter, laneInput);
  for (let i = 0; i < 4; i++) if (lanes[i].kind !== decoded.laneKinds[i] || lanes[i].amount !== decoded.laneAmounts[i]) throw new Error('Prepared public lanes differ from packet');
  const publicSignals = [scalar(root), ...decoded.nullifiers.map(scalar), ...decoded.commitments.map(scalar),
    bindDeliveryV9(core, decoded.commitments.map(scalar), decoded.delivery), publicContextV9(core, program, submitter, lanes, decoded.feeAmount)].map(String);
  let verified;
  try { verified = await groth16.verify(vk, publicSignals, decodeSolanaGroth16Proof(decoded.proof)); }
  catch { throw new Error('Prepared operation proof verification failed'); }
  if (!verified) throw new Error('Prepared operation proof verification failed');
  return Object.freeze({ verified: true, rootIndex: decoded.rootIndex, publicSignals: Object.freeze(publicSignals), feeAmount: decoded.feeAmount });
}
