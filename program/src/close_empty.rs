//! Reclaim only the never-used canonical initial state, authenticated by the
//! current upgrade authority in the program's real loader-v3 ProgramData.
use solana_program::{account_info::AccountInfo, bpf_loader_upgradeable,
    entrypoint::ProgramResult, program_error::ProgramError, pubkey::Pubkey,
    rent::Rent, system_program, sysvar::Sysvar};
use crate::{state::{STATE_LEN, ROOTS_START}, zeroes::EMPTY_ROOT};

// Accounts: authority writable+signer (also recipient), state writable,
// executable Program readonly, ProgramData readonly. No arbitrary recipient.
pub fn close_empty_state(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() != 4 { return Err(ProgramError::InvalidInstructionData); }
    let reserve = Rent::get()?.minimum_balance(STATE_LEN);
    let destination_balance = validate_close(program_id, accounts, reserve)?;
    let authority = &accounts[0]; let state = &accounts[1];
    // Resize can fail, so complete it before moving any lamports. No CPI or
    // fallible operation remains after both lamport borrows have succeeded.
    state.resize(0)?;
    let mut destination_lamports = authority.try_borrow_mut_lamports()?;
    let mut state_lamports = state.try_borrow_mut_lamports()?;
    **destination_lamports = destination_balance;
    **state_lamports = 0;
    drop(state_lamports); drop(destination_lamports);
    state.assign(&system_program::id());
    Ok(())
}

fn validate_close(program_id: &Pubkey, accounts: &[AccountInfo], reserve: u64) -> Result<u64, ProgramError> {
    if accounts.len() != 4 { return Err(ProgramError::InvalidInstructionData); }
    let authority = &accounts[0]; let state = &accounts[1];
    let program = &accounts[2]; let program_data = &accounts[3];
    if !authority.is_signer || !authority.is_writable {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if authority.executable { return Err(ProgramError::InvalidAccountData); }
    let loader = bpf_loader_upgradeable::id();
    let (expected_state, bump) = Pubkey::find_program_address(&[b"state"], program_id);
    let (expected_data, _) = Pubkey::find_program_address(&[program_id.as_ref()], &loader);
    if state.key != &expected_state || state.owner != program_id || !state.is_writable || state.executable
        || program.key != program_id || program.owner != &loader || !program.executable || program.is_writable
        || program_data.key != &expected_data || program_data.owner != &loader || program_data.executable || program_data.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    {
        let data = program.try_borrow_data()?;
        if data.len() != 36 || data[..4] != 2u32.to_le_bytes() || data[4..36] != expected_data.to_bytes() {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    {
        let data = program_data.try_borrow_data()?;
        // ProgramData = enum u32LE3, slot u64LE, Option tag, authority32.
        // Immutable authorityNone and any malformed Option are rejected.
        if data.len() < 45 || data[..4] != 3u32.to_le_bytes() || data[12] != 1
            || data[13..45] != authority.key.to_bytes() {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    {
        let data = state.try_borrow_data()?;
        // Compare the full canonical initial encoding without allocating a
        // second16KiB root array. Count0 alone is insufficient for closure.
        if data.len() != STATE_LEN || &data[..4] != b"PSW9" || data[4] != bump
            || data[5..13] != 0u64.to_le_bytes() || data[13..15] != 1u16.to_le_bytes()
            || data[15..17] != 1u16.to_le_bytes() || data[17..49] != EMPTY_ROOT
            || data[49..ROOTS_START].iter().any(|&byte| byte != 0)
            || data[ROOTS_START..ROOTS_START + 32] != EMPTY_ROOT
            || data[ROOTS_START + 32..].iter().any(|&byte| byte != 0) {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    // Canonical count0 proves that no normal operation ever appended notes.
    // Extra lamports are unsolicited funding, not accepted shielded deposits;
    // return them to the same authenticated upgrade authority with the rent.
    // Any count>0 stays forbidden even when all native funds were withdrawn.
    let lamports = state.lamports();
    if lamports < reserve { return Err(ProgramError::InvalidAccountData); }
    authority.lamports().checked_add(lamports).ok_or(ProgramError::ArithmeticOverflow)
}
