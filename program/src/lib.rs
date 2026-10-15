//! Experimental V9: four private outputs and three compact ciphertexts permit
//! an atomic SPL payment with SOL change and a SOL relay fee. A fresh
//! local program/state is required. Both paths check both spent namespaces;
//! public SOL/SPL balance changes, amounts and recipients remain visible.

mod registry;
mod state;
mod zeroes;
#[cfg(any(feature = "compact-system", test))]
mod compact_system;
#[cfg(any(feature = "compact-token", test))]
mod compact_token;
#[cfg(feature = "close-empty-state")]
mod close_empty;
#[cfg(any(feature = "compact-state", test))]
mod compact_state;
#[cfg(feature = "compact-system")]
use compact_system as system_instruction;
#[cfg(not(feature = "compact-system"))]
use solana_program::system_instruction;

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use registry::{bucket_id, register_nullifier};
use solana_poseidon::{hashv, Endianness, Parameters};
use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    hash::hash,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_program,
    sysvar::Sysvar,
};
#[cfg(not(feature = "compact-state"))]
use solana_program::program_pack::Pack;
#[cfg(not(feature = "compact-state"))]
use spl_token::state::{Account as TokenAccount, Mint};
#[cfg(feature = "compact-state")]
use compact_state::{TokenAccount, Mint};
#[cfg(feature = "compact-token")]
use compact_token as token_instruction;
#[cfg(not(feature = "compact-token"))]
use spl_token::instruction as token_instruction;
use state::{mint_asset_id, State, STATE_LEN};

mod operation_vk {
    include!(concat!(env!("OUT_DIR"), "/vk_operation.rs"));
}
mod exit_vk {
    include!(concat!(env!("OUT_DIR"), "/vk_exit.rs"));
}

#[cfg(not(feature = "no-entrypoint"))]
solana_program::entrypoint!(process_instruction);

#[cfg(all(feature = "custom-panic", target_os = "solana"))]
#[no_mangle]
fn custom_panic(_info: &core::panic::PanicInfo<'_>) {
    // Runtime still aborts the instruction. Omit the heavyweight formatting
    // tree for internal panic diagnostics; explicit ProgramErrors are intact.
    solana_program::log::sol_log("privacy internal panic");
}

const LANE_COUNT: usize = 4;
const ACCOUNT_COUNT: usize = 22;
const PROOF_START: usize = 2;
const FIELDS_START: usize = 258;
const KINDS_START: usize = 482;
const AMOUNTS_START: usize = 486;
const FEE_AMOUNT_START: usize = 518;
const DELIVERY_START: usize = 526;
const DELIVERY_LEN: usize = 303;
const PAYLOAD_LEN: usize = DELIVERY_START + DELIVERY_LEN;
const EXIT_ACCOUNT_COUNT: usize = 16;
const EXIT_KINDS_START: usize = FIELDS_START + 3 * 32;
const EXIT_AMOUNTS_START: usize = EXIT_KINDS_START + 2;
const EXIT_PAYLOAD_LEN: usize = EXIT_AMOUNTS_START + 2 * 8;
const EXIT_MARKER_LEN: usize = 36;
const EXIT_MARKER_MAGIC: &[u8; 4] = b"PSE8";
// A CPI cannot increase the caller's account data by more than 10 KiB in one
// instruction. Selector2 is therefore called twice for this 17,457-byte state.
const INITIAL_STATE_LEN: usize = 10_240;
const PENDING_STATE_MAGIC: &[u8; 4] = b"PSI9";

pub fn process_instruction(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&selector, payload) = data.split_first().ok_or(ProgramError::InvalidInstructionData)?;
    match selector {
        2 if payload.is_empty() => initialize(program_id, accounts),
        13 => operation(program_id, accounts, payload),
        11 => exit(program_id, accounts, payload),
        #[cfg(feature = "close-empty-state")]
        14 if payload.is_empty() => close_empty::close_empty_state(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn require_payer(payer: &AccountInfo) -> ProgramResult {
    if !payer.is_signer || !payer.is_writable { return Err(ProgramError::MissingRequiredSignature); }
    Ok(())
}

fn require_system(system: &AccountInfo) -> ProgramResult {
    if *system.key != system_program::id() { return Err(ProgramError::IncorrectProgramId); }
    Ok(())
}

fn require_token(token: &AccountInfo) -> ProgramResult {
    if *token.key != spl_token::id() { return Err(ProgramError::IncorrectProgramId); }
    Ok(())
}

fn read_state(program_id: &Pubkey, account: &AccountInfo) -> Result<Box<State>, ProgramError> {
    let (expected, bump) = Pubkey::find_program_address(&[b"state"], program_id);
    if account.key != &expected || account.owner != program_id || !account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let state = State::read(&account.try_borrow_data()?)?;
    if state.bump != bump { return Err(ProgramError::InvalidAccountData); }
    Ok(state)
}

fn write_state(account: &AccountInfo, state: &State) -> ProgramResult {
    state.write(&mut account.try_borrow_mut_data()?)
}

/// An attacker may send lamports to an uninitialized PDA. Allocate/assign that
/// system-owned account instead of treating the unsolicited funding as setup.
fn create_pda<'a>(payer: &AccountInfo<'a>, account: &AccountInfo<'a>, system: &AccountInfo<'a>,
    space: usize, owner: &Pubkey, seeds: &[&[u8]]) -> ProgramResult {
    if !account.is_writable || *account.owner != system_program::id() || !account.data_is_empty() {
        return Err(ProgramError::InvalidAccountData);
    }
    let required = Rent::get()?.minimum_balance(space).max(1);
    if account.lamports() == 0 {
        return invoke_signed(&system_instruction::create_account(payer.key, account.key,
            required, space as u64, owner), &[payer.clone(), account.clone(), system.clone()], &[seeds]);
    }
    if account.lamports() < required {
        invoke(&system_instruction::transfer(payer.key, account.key, required - account.lamports()),
            &[payer.clone(), account.clone(), system.clone()])?;
    }
    invoke_signed(&system_instruction::allocate(account.key, space as u64),
        &[account.clone(), system.clone()], &[seeds])?;
    invoke_signed(&system_instruction::assign(account.key, owner),
        &[account.clone(), system.clone()], &[seeds])
}

#[inline(never)]
fn initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    if accounts.len() != 3 { return Err(ProgramError::InvalidInstructionData); }
    let payer = &accounts[0];
    let state_account = &accounts[1];
    let system = &accounts[2];
    require_payer(payer)?;
    require_system(system)?;
    let (expected, bump) = Pubkey::find_program_address(&[b"state"], program_id);
    if state_account.key != &expected || !state_account.is_writable || state_account.executable {
        return Err(ProgramError::InvalidAccountData);
    }
    if *state_account.owner == system_program::id() {
        if !state_account.data_is_empty() { return Err(ProgramError::InvalidAccountData); }
        create_pda(payer, state_account, system, INITIAL_STATE_LEN, program_id, &[b"state", &[bump]])?;
        let mut data = state_account.try_borrow_mut_data()?;
        data.fill(0);
        data[..4].copy_from_slice(PENDING_STATE_MAGIC);
        data[4] = bump;
        return Ok(());
    }
    if state_account.owner != program_id { return Err(ProgramError::InvalidAccountData); }
    validate_pending_state(&state_account.try_borrow_data()?, bump)?;
    let required = Rent::get()?.minimum_balance(STATE_LEN).max(1);
    if state_account.lamports() < required {
        invoke(&system_instruction::transfer(payer.key, state_account.key, required - state_account.lamports()),
            &[payer.clone(), state_account.clone(), system.clone()])?;
    }
    state_account.resize(STATE_LEN)?;
    let initial = State::new(bump)?;
    write_state(state_account, &initial)
}

fn validate_pending_state(data: &[u8], bump: u8) -> ProgramResult {
    if data.len() != INITIAL_STATE_LEN || &data[..4] != PENDING_STATE_MAGIC
        || data[4] != bump || data[5..].iter().any(|byte| *byte != 0) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn field(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    bytes
}

fn address_limbs(address: &Pubkey) -> [[u8; 32]; 2] {
    let bytes = address.to_bytes();
    let mut limbs = [[0u8; 32]; 2];
    limbs[0][16..].copy_from_slice(&bytes[..16]);
    limbs[1][16..].copy_from_slice(&bytes[16..]);
    limbs
}

fn poseidon(values: &[&[u8]]) -> Result<[u8; 32], ProgramError> {
    Ok(hashv(Parameters::Bn254X5, Endianness::BigEndian, values)
        .map_err(|_| ProgramError::InvalidInstructionData)?.to_bytes())
}

fn lane_hash(kind: u8, asset: &[u8; 32], amount: u64, address: &Pubkey) -> Result<[u8; 32], ProgramError> {
    let domain = field(81);
    let kind_field = field(kind as u64);
    let amount_field = field(amount);
    let limbs = address_limbs(address);
    poseidon(&[&domain, &kind_field, asset, &amount_field, &limbs[0], &limbs[1]])
}

fn context_hash(program_id: &Pubkey, payer: &Pubkey, lane_hashes: &[[u8; 32]; 4]) -> Result<[u8; 32], ProgramError> {
    let domain = field(82);
    let program_limbs = address_limbs(program_id);
    let limbs = address_limbs(payer);
    poseidon(&[&domain, &program_limbs[0], &program_limbs[1], &limbs[0], &limbs[1], &lane_hashes[0], &lane_hashes[1],
        &lane_hashes[2], &lane_hashes[3]])
}

fn normal_context_hash(program_id: &Pubkey, payer: &Pubkey, lane_hashes: &[[u8; 32]; 4],
    fee_amount: u64) -> Result<[u8; 32], ProgramError> {
    let domain = field(91);
    let old_context = context_hash(program_id, payer, lane_hashes)?;
    let fee = field(fee_amount);
    poseidon(&[&domain, &old_context, &fee])
}

fn delivery_binding(commitments: &[[u8; 32]; 4], delivery: &[u8]) -> Result<[u8; 32], ProgramError> {
    let digest = hash(delivery).to_bytes();
    let mut truncated = [0u8; 32];
    truncated[1..].copy_from_slice(&digest[..31]);
    poseidon(&[&commitments[0], &commitments[1], &commitments[2], &commitments[3], &truncated])
}

fn exit_context_hash(program_id: &Pubkey, payer: &Pubkey, lanes: &[[u8; 32]; 2]) -> Result<[u8; 32], ProgramError> {
    let domain = field(84);
    let program_limbs = address_limbs(program_id);
    let payer_limbs = address_limbs(payer);
    poseidon(&[&domain, &program_limbs[0], &program_limbs[1], &payer_limbs[0],
        &payer_limbs[1], &lanes[0], &lanes[1]])
}

fn require_unused_exit_marker(program_id: &Pubkey, marker: &AccountInfo,
    nullifier: &[u8; 32], writable: bool) -> ProgramResult {
    let (expected, _) = Pubkey::find_program_address(&[b"exit-nullifier", nullifier], program_id);
    if marker.key != &expected || marker.is_writable != writable || marker.executable {
        return Err(ProgramError::InvalidAccountData);
    }
    if marker.owner == program_id {
        let data = marker.try_borrow_data()?;
        if data.len() != EXIT_MARKER_LEN || &data[..4] != EXIT_MARKER_MAGIC || &data[4..] != nullifier {
            return Err(ProgramError::InvalidAccountData);
        }
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    // An unsolicited lamport gift cannot make an otherwise unused marker
    // unavailable. Creation below safely allocates and assigns this PDA.
    if *marker.owner != system_program::id() || !marker.data_is_empty() {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn create_exit_marker<'a>(program_id: &Pubkey, payer: &AccountInfo<'a>, marker: &AccountInfo<'a>,
    system: &AccountInfo<'a>, nullifier: &[u8; 32]) -> ProgramResult {
    require_unused_exit_marker(program_id, marker, nullifier, true)?;
    let (_, bump) = Pubkey::find_program_address(&[b"exit-nullifier", nullifier], program_id);
    create_pda(payer, marker, system, EXIT_MARKER_LEN, program_id,
        &[b"exit-nullifier", nullifier, &[bump]])?;
    let mut data = marker.try_borrow_mut_data()?;
    data[..4].copy_from_slice(EXIT_MARKER_MAGIC);
    data[4..].copy_from_slice(nullifier);
    Ok(())
}

fn require_unregistered_bucket(program_id: &Pubkey, bucket: &AccountInfo,
    nullifier: &[u8; 32]) -> ProgramResult {
    let id = bucket_id(nullifier);
    let (expected, _) = Pubkey::find_program_address(&[b"spent-bucket", &[id]], program_id);
    if bucket.key != &expected || bucket.is_writable || bucket.executable {
        return Err(ProgramError::InvalidAccountData);
    }
    if *bucket.owner == system_program::id() && bucket.data_is_empty() { return Ok(()); }
    if bucket.owner != program_id { return Err(ProgramError::InvalidAccountData); }
    if registry::contains(&bucket.try_borrow_data()?, nullifier)? {
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    Ok(())
}

fn exit_bucket_slots(program_id: &Pubkey, buckets: &[AccountInfo], nullifiers: &[[u8; 32]; 3])
    -> Result<[usize; 3], ProgramError> {
    if buckets.len() != 3 { return Err(ProgramError::InvalidInstructionData); }
    let mut slots = [0usize; 3];
    for i in 0..3 {
        let id = bucket_id(&nullifiers[i]);
        if let Some(prior) = (0..i).find(|&j| bucket_id(&nullifiers[j]) == id) {
            let (padding, _) = Pubkey::find_program_address(&[b"bucket-padding", &[i as u8]], program_id);
            if buckets[i].key != &padding || buckets[i].is_writable {
                return Err(ProgramError::InvalidAccountData);
            }
            slots[i] = slots[prior];
        } else { slots[i] = i; }
        require_unregistered_bucket(program_id, &buckets[slots[i]], &nullifiers[i])?;
    }
    Ok(slots)
}

fn require_padding(program_id: &Pubkey, lane: usize, component: u8, account: &AccountInfo) -> ProgramResult {
    let (expected, _) = Pubkey::find_program_address(
        &[b"lane-padding", &[lane as u8], &[component]], program_id);
    if account.key != &expected { return Err(ProgramError::InvalidAccountData); }
    Ok(())
}

fn require_mint(mint: &AccountInfo, token: &AccountInfo) -> ProgramResult {
    if mint.owner != token.key { return Err(ProgramError::IncorrectProgramId); }
    Mint::unpack(&mint.try_borrow_data()?)?;
    Ok(())
}

fn token_account(account: &AccountInfo, mint: &Pubkey, token: &AccountInfo) -> Result<TokenAccount, ProgramError> {
    if account.owner != token.key || !account.is_writable { return Err(ProgramError::InvalidAccountData); }
    let parsed = TokenAccount::unpack(&account.try_borrow_data()?)?;
    if parsed.mint != *mint { return Err(ProgramError::InvalidAccountData); }
    Ok(parsed)
}

fn read_vault(program_id: &Pubkey, state: &Pubkey, vault: &AccountInfo,
    mint: &AccountInfo, token: &AccountInfo) -> Result<TokenAccount, ProgramError> {
    let (expected, _) = Pubkey::find_program_address(&[b"vault", mint.key.as_ref()], program_id);
    if vault.key != &expected { return Err(ProgramError::InvalidAccountData); }
    let parsed = token_account(vault, mint.key, token)?;
    if parsed.owner != *state { return Err(ProgramError::InvalidAccountData); }
    Ok(parsed)
}

/// Validate every public lane before computing the proof's context. Zero lanes
/// have canonical account keys, so callers cannot smuggle an unbound recipient.
#[inline(never)]
fn validate_lane(program_id: &Pubkey, lane: usize, kind: u8, amount: u64,
    payer: &AccountInfo, state: &AccountInfo, address: &AccountInfo,
    vault: &AccountInfo, mint: &AccountInfo, token: &AccountInfo) -> Result<[u8; 32], ProgramError> {
    if !address.is_writable || !vault.is_writable || mint.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    match kind {
        0 => {
            if amount != 0 { return Err(ProgramError::InvalidInstructionData); }
            require_padding(program_id, lane, 0, address)?;
            require_padding(program_id, lane, 1, vault)?;
            require_padding(program_id, lane, 2, mint)?;
            Ok([0u8; 32])
        }
        1 => {
            if amount == 0 { return Err(ProgramError::InvalidInstructionData); }
            require_padding(program_id, lane, 1, vault)?;
            require_padding(program_id, lane, 2, mint)?;
            if (lane < 2 && address.key != payer.key) || (lane >= 2 && address.key == state.key) {
                return Err(ProgramError::InvalidAccountData);
            }
            Ok([0u8; 32])
        }
        2 => {
            if amount == 0 { return Err(ProgramError::InvalidInstructionData); }
            require_mint(mint, token)?;
            let (expected, _) = Pubkey::find_program_address(&[b"vault", mint.key.as_ref()], program_id);
            if vault.key != &expected || address.key == vault.key {
                return Err(ProgramError::InvalidAccountData);
            }
            let address_data = token_account(address, mint.key, token)?;
            if lane < 2 && address_data.owner != *payer.key { return Err(ProgramError::InvalidAccountData); }
            if *vault.owner == system_program::id() && vault.data_is_empty() {
                // A prior deposit lane may initialize this vault before a
                // withdrawal lane executes. The execution rechecks its state.
            } else { read_vault(program_id, state.key, vault, mint, token)?; }
            mint_asset_id(&mint.key.to_bytes())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

const FR_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn canonical_public_input(input: &[u8; 32]) -> bool { input < &FR_BE }

fn verify_proof<const N: usize>(proof: &[u8], inputs: &[[u8; 32]; N], key: &Groth16Verifyingkey) -> ProgramResult {
    if proof.len() != 256 { return Err(ProgramError::InvalidInstructionData); }
    #[cfg(feature = "canonical-fr")]
    if inputs.iter().any(|input| !canonical_public_input(input)) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let proof_a: &[u8; 64] = proof[0..64].try_into().map_err(|_| ProgramError::InvalidInstructionData)?;
    let proof_b: &[u8; 128] = proof[64..192].try_into().map_err(|_| ProgramError::InvalidInstructionData)?;
    let proof_c: &[u8; 64] = proof[192..256].try_into().map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut verifier = Groth16Verifier::new(proof_a, proof_b, proof_c, inputs, key)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    #[cfg(feature = "canonical-fr")]
    return verifier.verify_unchecked().map_err(|_| ProgramError::InvalidInstructionData);
    #[cfg(not(feature = "canonical-fr"))]
    verifier.verify().map_err(|_| ProgramError::InvalidInstructionData)
}

fn require_distinct_commitments(commitments: &[[u8; 32]]) -> ProgramResult {
    // A proof can conserve value while producing identical notes. Clients
    // index by commitment, so accepting duplicates would break recovery for
    // the whole history. Enforce the same invariant as the packet parser.
    for i in 0..commitments.len() {
        if commitments[..i].contains(&commitments[i]) {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    Ok(())
}

#[inline(never)]
fn register_all<'a>(program_id: &Pubkey, payer: &AccountInfo<'a>, spent: &[AccountInfo<'a>],
    system: &AccountInfo<'a>, nullifiers: &[[u8; 32]]) -> ProgramResult {
    // A collided bucket still occupies a distinct meta, represented by the
    // same deterministic readonly padding convention as V6.
    let mut slots = [0usize; 3];
    for i in 0..3 {
        let id = bucket_id(&nullifiers[i]);
        if let Some(prior) = (0..i).find(|&j| bucket_id(&nullifiers[j]) == id) {
            let (padding, _) = Pubkey::find_program_address(&[b"bucket-padding", &[i as u8]], program_id);
            if spent[i].key != &padding || spent[i].is_writable {
                return Err(ProgramError::InvalidAccountData);
            }
            slots[i] = slots[prior];
        } else {
            let (expected, _) = Pubkey::find_program_address(&[b"spent-bucket", &[id]], program_id);
            if spent[i].key != &expected || !spent[i].is_writable {
                return Err(ProgramError::InvalidAccountData);
            }
            slots[i] = i;
        }
    }
    for i in 0..3 { register_nullifier(program_id, payer, &spent[slots[i]], system, &nullifiers[i])?; }
    Ok(())
}

#[inline(never)]
fn execute_lane<'a>(program_id: &Pubkey, lane: usize, kind: u8, amount: u64,
    payer: &AccountInfo<'a>, state: &AccountInfo<'a>, state_bump: u8,
    address: &AccountInfo<'a>, vault: &AccountInfo<'a>, mint: &AccountInfo<'a>,
    token: &AccountInfo<'a>, system: &AccountInfo<'a>) -> ProgramResult {
    match kind {
        0 => Ok(()),
        1 if lane < 2 => invoke(
            &system_instruction::transfer(address.key, state.key, amount),
            &[address.clone(), state.clone(), system.clone()]),
        1 => {
            let reserve = Rent::get()?.minimum_balance(STATE_LEN);
            let remaining = state.lamports().checked_sub(amount).ok_or(ProgramError::InsufficientFunds)?;
            if remaining < reserve { return Err(ProgramError::InsufficientFunds); }
            let new_balance = address.lamports().checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
            **state.try_borrow_mut_lamports()? = remaining;
            **address.try_borrow_mut_lamports()? = new_balance;
            Ok(())
        }
        2 if lane < 2 => {
            if *vault.owner == system_program::id() && vault.data_is_empty() {
                let (_, bump) = Pubkey::find_program_address(&[b"vault", mint.key.as_ref()], program_id);
                create_pda(payer, vault, system, TokenAccount::LEN, token.key,
                    &[b"vault", mint.key.as_ref(), &[bump]])?;
                invoke(&token_instruction::initialize_account3(token.key, vault.key, mint.key, state.key)?,
                    &[vault.clone(), mint.clone(), token.clone()])?;
            }
            let before = read_vault(program_id, state.key, vault, mint, token)?.amount;
            invoke(&token_instruction::transfer(token.key, address.key, vault.key, payer.key, &[], amount)?,
                &[address.clone(), vault.clone(), payer.clone(), token.clone()])?;
            let after = read_vault(program_id, state.key, vault, mint, token)?.amount;
            if after.checked_sub(before) != Some(amount) { return Err(ProgramError::InvalidAccountData); }
            Ok(())
        }
        2 => {
            let before = read_vault(program_id, state.key, vault, mint, token)?.amount;
            if before < amount { return Err(ProgramError::InsufficientFunds); }
            invoke_signed(&token_instruction::transfer(token.key, vault.key, address.key, state.key, &[], amount)?,
                &[vault.clone(), address.clone(), state.clone(), token.clone()],
                &[&[b"state", &[state_bump]]],
            )?;
            let after = read_vault(program_id, state.key, vault, mint, token)?.amount;
            if before.checked_sub(after) != Some(amount) { return Err(ProgramError::InvalidAccountData); }
            Ok(())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[inline(never)]
fn operation(program_id: &Pubkey, accounts: &[AccountInfo], payload: &[u8]) -> ProgramResult {
    if accounts.len() != ACCOUNT_COUNT || payload.len() != PAYLOAD_LEN
        || &payload[DELIVERY_START..DELIVERY_START + 4] != b"PSB9" {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payer = &accounts[0];
    let state_account = &accounts[1];
    let system = &accounts[5];
    let token = &accounts[6];
    require_payer(payer)?;
    require_system(system)?;
    require_token(token)?;
    let mut state = read_state(program_id, state_account)?;
    state.ensure_room()?;
    let mut inputs = [[0u8; 32]; 10];
    inputs[0] = state.root_at(u16::from_le_bytes(payload[..2].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?))?;
    for i in 0..7 { inputs[1 + i].copy_from_slice(&payload[FIELDS_START + i * 32..FIELDS_START + (i + 1) * 32]); }
    require_distinct_commitments(&inputs[4..8])?;
    inputs[8] = delivery_binding(&[inputs[4], inputs[5], inputs[6], inputs[7]], &payload[DELIVERY_START..])?;
    let kinds = &payload[KINDS_START..AMOUNTS_START];
    let mut amounts = [0u64; LANE_COUNT];
    let mut lane_hashes = [[0u8; 32]; LANE_COUNT];
    for i in 0..LANE_COUNT {
        amounts[i] = u64::from_be_bytes(payload[AMOUNTS_START + i * 8..AMOUNTS_START + (i + 1) * 8]
            .try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
        let index = 7 + i * 3;
        let asset = validate_lane(program_id, i, kinds[i], amounts[i], payer, state_account,
            &accounts[index], &accounts[index + 1], &accounts[index + 2], token)?;
        lane_hashes[i] = lane_hash(kinds[i], &asset, amounts[i], accounts[index].key)?;
    }
    let fee_amount = u64::from_be_bytes(payload[FEE_AMOUNT_START..DELIVERY_START].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?);
    inputs[9] = normal_context_hash(program_id, payer.key, &lane_hashes, fee_amount)?;
    verify_proof(&payload[PROOF_START..FIELDS_START], &inputs, &operation_vk::VERIFYINGKEY)?;
    // This is unconditional even when buckets are not full. Capacity changes
    // or future bucket rollover cannot make EXIT-spent notes spendable again.
    for i in 0..3 { require_unused_exit_marker(program_id, &accounts[19 + i], &inputs[1 + i], false)?; }
    register_all(program_id, payer, &accounts[2..5], system, &inputs[1..4])?;
    // Complete every CPI before directly moving program-owned SOL. A later
    // CPI that references state but omits a native recipient would otherwise
    // observe an unbalanced account subset during runtime synchronization.
    for i in 0..LANE_COUNT {
        if i >= 2 && kinds[i] == 1 { continue; }
        let index = 7 + i * 3;
        execute_lane(program_id, i, kinds[i], amounts[i], payer, state_account, state.bump,
            &accounts[index], &accounts[index + 1], &accounts[index + 2], token, system)?;
    }
    for i in 2..LANE_COUNT {
        if kinds[i] != 1 { continue; }
        let index = 7 + i * 3;
        execute_lane(program_id, i, kinds[i], amounts[i], payer, state_account, state.bump,
            &accounts[index], &accounts[index + 1], &accounts[index + 2], token, system)?;
    }
    state.append_outputs(&[inputs[4], inputs[5], inputs[6], inputs[7]])?;
    write_state(state_account, &state)
}

#[inline(never)]
fn exit(program_id: &Pubkey, accounts: &[AccountInfo], payload: &[u8]) -> ProgramResult {
    if accounts.len() != EXIT_ACCOUNT_COUNT || payload.len() != EXIT_PAYLOAD_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payer = &accounts[0];
    let state_account = &accounts[1];
    let system = &accounts[5];
    let token = &accounts[6];
    require_payer(payer)?; require_system(system)?; require_token(token)?;
    let state = read_state(program_id, state_account)?;
    // No ensure_room() and no append: a full commitment tree remains exit-able.
    let mut inputs = [[0u8; 32]; 5];
    inputs[0] = state.root_at(u16::from_le_bytes(payload[..2].try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?))?;
    for i in 0..3 {
        inputs[1 + i].copy_from_slice(&payload[FIELDS_START + i * 32..FIELDS_START + (i + 1) * 32]);
    }
    let nullifiers: [[u8; 32]; 3] = [inputs[1], inputs[2], inputs[3]];
    let kinds = &payload[EXIT_KINDS_START..EXIT_AMOUNTS_START];
    let mut amounts = [0u64; 2];
    let mut hashes = [[0u8; 32]; 2];
    for i in 0..2 {
        amounts[i] = u64::from_be_bytes(payload[EXIT_AMOUNTS_START + i * 8..EXIT_AMOUNTS_START + (i + 1) * 8]
            .try_into().map_err(|_| ProgramError::InvalidInstructionData)?);
        let index = 7 + i * 3;
        let asset = validate_lane(program_id, i + 2, kinds[i], amounts[i], payer, state_account,
            &accounts[index], &accounts[index + 1], &accounts[index + 2], token)?;
        hashes[i] = lane_hash(kinds[i], &asset, amounts[i], accounts[index].key)?;
    }
    inputs[4] = exit_context_hash(program_id, payer.key, &hashes)?;
    verify_proof(&payload[PROOF_START..FIELDS_START], &inputs, &exit_vk::VERIFYINGKEY)?;
    // Reject normal-path spent entries even in full buckets. Both namespaces
    // are consulted before any marker creation, rent movement or withdrawal.
    exit_bucket_slots(program_id, &accounts[2..5], &nullifiers)?;
    for i in 0..3 { require_unused_exit_marker(program_id, &accounts[13 + i], &nullifiers[i], true)?; }
    for i in 0..3 { create_exit_marker(program_id, payer, &accounts[13 + i], system, &nullifiers[i])?; }
    // Finish marker rent and SPL CPIs before changing native SOL directly.
    for i in 0..2 {
        if kinds[i] == 1 { continue; }
        let index = 7 + i * 3;
        execute_lane(program_id, i + 2, kinds[i], amounts[i], payer, state_account, state.bump,
            &accounts[index], &accounts[index + 1], &accounts[index + 2], token, system)?;
    }
    for i in 0..2 {
        if kinds[i] != 1 { continue; }
        let index = 7 + i * 3;
        execute_lane(program_id, i + 2, kinds[i], amounts[i], payer, state_account, state.bump,
            &accounts[index], &accounts[index + 1], &accounts[index + 2], token, system)?;
    }
    // EXIT changes spent markers and balances only, never tree/history bytes.
    Ok(())
}
