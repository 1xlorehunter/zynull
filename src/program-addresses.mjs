import { PublicKey, SystemProgram, TransactionInstruction } from '@solana/web3.js';

function statePda(programId) {
  return PublicKey.findProgramAddressSync([Buffer.from('state')], programId)[0];
}
function vaultPda(programId, mint) {
  return PublicKey.findProgramAddressSync([Buffer.from('vault'), mint.toBuffer()], programId)[0];
}
function account(pubkey, isSigner, isWritable) {
  return { pubkey, isSigner, isWritable };
}

export function initializeInstruction(programId, payer) {
  return new TransactionInstruction({
    programId,
    keys: [account(payer, true, true), account(statePda(programId), false, true), account(SystemProgram.programId, false, false)],
    data: Buffer.from([2]),
  });
}

export { statePda, vaultPda };
