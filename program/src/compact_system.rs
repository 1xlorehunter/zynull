//! Exactly the four System Program instruction variants used by this program.
//! Their bincode ABI is a u32LE variant followed by fixed-width payload fields.
use solana_program::{instruction::{AccountMeta, Instruction}, pubkey::Pubkey, system_program};

pub fn create_account(from: &Pubkey, to: &Pubkey, lamports: u64, space: u64, owner: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(52);
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction { program_id: system_program::id(), data,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, true)] }
}

pub fn transfer(from: &Pubkey, to: &Pubkey, lamports: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&lamports.to_le_bytes());
    Instruction { program_id: system_program::id(), data,
        accounts: vec![AccountMeta::new(*from, true), AccountMeta::new(*to, false)] }
}

pub fn allocate(account: &Pubkey, space: u64) -> Instruction {
    let mut data = Vec::with_capacity(12);
    data.extend_from_slice(&8u32.to_le_bytes());
    data.extend_from_slice(&space.to_le_bytes());
    Instruction { program_id: system_program::id(), data,
        accounts: vec![AccountMeta::new(*account, true)] }
}

pub fn assign(account: &Pubkey, owner: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(owner.as_ref());
    Instruction { program_id: system_program::id(), data,
        accounts: vec![AccountMeta::new(*account, true)] }
}
