//! Exactly the legacy SPL CPI instruction bytes used by this program.
//! Account/Mint decoding remains the SDK Pack implementation, including all
//! COption tags, state and initialization checks; no state parser is replaced.
use solana_program::{instruction::{AccountMeta, Instruction}, program_error::ProgramError, pubkey::Pubkey};

pub fn transfer(token: &Pubkey, source: &Pubkey, destination: &Pubkey,
    authority: &Pubkey, signers: &[&Pubkey], amount: u64) -> Result<Instruction, ProgramError> {
    spl_token::check_program_account(token)?;
    let mut data = Vec::with_capacity(9); data.push(3);
    data.extend_from_slice(&amount.to_le_bytes());
    let mut accounts = Vec::with_capacity(3 + signers.len());
    accounts.push(AccountMeta::new(*source, false));
    accounts.push(AccountMeta::new(*destination, false));
    accounts.push(AccountMeta::new_readonly(*authority, signers.is_empty()));
    for signer in signers { accounts.push(AccountMeta::new_readonly(**signer, true)); }
    Ok(Instruction { program_id: *token, data, accounts })
}

pub fn initialize_account3(token: &Pubkey, account: &Pubkey, mint: &Pubkey,
    owner: &Pubkey) -> Result<Instruction, ProgramError> {
    spl_token::check_program_account(token)?;
    let mut data = Vec::with_capacity(33); data.push(18); data.extend_from_slice(owner.as_ref());
    Ok(Instruction { program_id: *token, data,
        accounts: vec![AccountMeta::new(*account, false), AccountMeta::new_readonly(*mint, false)] })
}
