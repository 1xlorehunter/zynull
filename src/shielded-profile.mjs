import { createPrivateKey, createPublicKey, hkdfSync } from 'node:crypto';

const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

// Devnet client profile derived from a Solana keypair with domain separation.
// Production needs a wallet-signature based derivation and cross-device UX.
export function deriveShieldedProfile(core, keypair, programId) {
  const salt = programId.toBuffer();
  const secret = Buffer.from(hkdfSync('sha256', keypair.secretKey.subarray(0, 32),
    salt, Buffer.from('privacy-solana-spend-v1'), 31));
  const spendSecret = BigInt(`0x${secret.toString('hex')}`);
  secret.fill(0);
  const viewSeed = Buffer.from(hkdfSync('sha256', keypair.secretKey.subarray(0, 32),
    salt, Buffer.from('privacy-solana-view-v1'), 32));
  const viewPrivate = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, viewSeed]), format: 'der', type: 'pkcs8',
  });
  viewSeed.fill(0);
  const viewPublicKey = createPublicKey(viewPrivate).export({ type: 'spki', format: 'der' }).toString('base64');
  return {
    spendSecret, ownerPub: core.ownerPublic(spendSecret), viewPrivate, viewPublicKey,
  };
}
