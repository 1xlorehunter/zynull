const FP = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const be32 = (value, modulus) => {
  const n = BigInt(value);
  if (n < 0n || n >= modulus) throw new Error('noncanonical curve or public-input coordinate');
  return Buffer.from(n.toString(16).padStart(64, '0'), 'hex');
};

export function encodeGroth16Proof(proof) {
  const [x, y] = proof.pi_a.map(BigInt);
  const a = Buffer.concat([be32(x, FP), be32(y === 0n ? 0n : FP - y, FP)]);
  // snarkjs Fp2 order is c0,c1; Solana's alt_bn128 syscall uses c1,c0.
  const b = Buffer.concat(proof.pi_b.slice(0, 2).flatMap(([c0, c1]) => [be32(c1, FP), be32(c0, FP)]));
  const c = Buffer.concat(proof.pi_c.slice(0, 2).map((value) => be32(value, FP)));
  return Buffer.concat([a, b, c]);
}
