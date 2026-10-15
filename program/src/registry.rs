use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    program::invoke,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_program,
    sysvar::Sysvar,
};
#[cfg(feature = "compact-system")]
use crate::compact_system as system_instruction;
#[cfg(not(feature = "compact-system"))]
use solana_program::system_instruction;

pub const BUCKET_COUNT: u8 = 32;
// Spent storage is independently bounded; depth32 is not a promise of four
// billion executable operations. Each account stays below Solana's 10 MiB
// account limit. Concentrated nullifiers can fill a shard sooner; insertion
// still moves bytes, and large all-shard ALT profiles hit loaded-data limits.
pub const BUCKET_CAPACITY: usize = 131_072;
pub const BUCKET_HEADER_LEN: usize = 8;
pub const BUCKET_MAX_LEN: usize = BUCKET_HEADER_LEN + BUCKET_CAPACITY * 32;
const MAGIC: &[u8; 4] = b"PSN7";

// The field is big endian. Use the least significant byte, whose five low
// bits do not suffer the bias of the highest BN254 byte.
pub fn bucket_id(nullifier: &[u8; 32]) -> u8 { nullifier[31] & (BUCKET_COUNT - 1) }

fn count(data: &[u8]) -> Result<usize, ProgramError> {
    if data.len() < BUCKET_HEADER_LEN || &data[..4] != MAGIC {
        return Err(ProgramError::InvalidAccountData);
    }
    let count = u32::from_le_bytes(data[4..8].try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?) as usize;
    if count > BUCKET_CAPACITY || data.len() != BUCKET_HEADER_LEN + count * 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(count)
}

fn entry(data: &[u8], position: usize) -> &[u8] {
    &data[BUCKET_HEADER_LEN + position * 32..BUCKET_HEADER_LEN + (position + 1) * 32]
}

// Read-only membership for EXIT. Unlike check_new, a full bucket is readable:
// capacity must never prevent finding an already spent normal-path nullifier.
// Ordering is established by register_nullifier; no untrusted writer exists.
pub fn contains(data: &[u8], nullifier: &[u8; 32]) -> Result<bool, ProgramError> {
    let mut lower = 0usize;
    let mut upper = count(data)?;
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        match entry(data, middle).cmp(nullifier.as_slice()) {
            std::cmp::Ordering::Less => lower = middle + 1,
            std::cmp::Ordering::Greater => upper = middle,
            std::cmp::Ordering::Equal => return Ok(true),
        }
    }
    Ok(false)
}

fn check_new(data: &[u8], nullifier: &[u8; 32]) -> Result<(usize, usize), ProgramError> {
    let count = count(data)?;
    let mut lower = 0usize;
    let mut upper = count;
    // Existing arrays are created and maintained only by this program. The
    // insertion invariant makes lookup logarithmic without rescanning the
    // entire array. Every actual insertion preserves strict ordering.
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        match entry(data, middle).cmp(nullifier.as_slice()) {
            std::cmp::Ordering::Less => lower = middle + 1,
            std::cmp::Ordering::Greater => upper = middle,
            std::cmp::Ordering::Equal => return Err(ProgramError::AccountAlreadyInitialized),
        }
    }
    if count == BUCKET_CAPACITY { return Err(ProgramError::AccountDataTooSmall); }
    // Check insertion boundaries defensively before moving any bytes.
    if (lower > 0 && entry(data, lower - 1) >= nullifier.as_slice())
        || (lower < count && entry(data, lower) <= nullifier.as_slice()) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok((count, lower))
}

fn insert(data: &mut [u8], count: usize, position: usize, nullifier: &[u8; 32]) -> ProgramResult {
    if count >= BUCKET_CAPACITY || position > count
        || data.len() != BUCKET_HEADER_LEN + (count + 1) * 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    let start = BUCKET_HEADER_LEN + position * 32;
    let end = BUCKET_HEADER_LEN + count * 32;
    data.copy_within(start..end, start + 32);
    data[start..start + 32].copy_from_slice(nullifier);
    data[4..8].copy_from_slice(&((count + 1) as u32).to_le_bytes());
    Ok(())
}

pub fn register_nullifier<'a>(program_id: &Pubkey, payer: &AccountInfo<'a>,
    bucket: &AccountInfo<'a>, system: &AccountInfo<'a>, nullifier: &[u8; 32]) -> ProgramResult {
    let id = bucket_id(nullifier);
    let (expected, bump) = Pubkey::find_program_address(&[b"spent-bucket", &[id]], program_id);
    if bucket.key != &expected || !bucket.is_writable || *system.key != system_program::id() {
        return Err(ProgramError::InvalidAccountData);
    }
    if bucket.owner == &system_program::id() && bucket.data_is_empty() {
        crate::create_pda(payer, bucket, system, BUCKET_HEADER_LEN, program_id,
            &[b"spent-bucket", &[id], &[bump]])?;
        let mut data = bucket.try_borrow_mut_data()?;
        data[..4].copy_from_slice(MAGIC);
        data[4..8].copy_from_slice(&0u32.to_le_bytes());
    } else if bucket.owner != program_id { return Err(ProgramError::InvalidAccountData); }
    let (count, position) = check_new(&bucket.try_borrow_data()?, nullifier)?;
    let new_len = BUCKET_HEADER_LEN + (count + 1) * 32;
    if new_len > BUCKET_MAX_LEN { return Err(ProgramError::AccountDataTooSmall); }
    let required = Rent::get()?.minimum_balance(new_len).max(1);
    if required > bucket.lamports() {
        invoke(&system_instruction::transfer(payer.key, bucket.key, required - bucket.lamports()),
            &[payer.clone(), bucket.clone(), system.clone()])?;
    }
    bucket.resize(new_len)?;
    insert(&mut bucket.try_borrow_mut_data()?, count, position, nullifier)
}
