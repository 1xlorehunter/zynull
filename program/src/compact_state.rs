//! Only the fields consumed by this program are copied, while every legacy
//! SPL Pack format/initialization check remains equivalent to the SDK.
use solana_program::{program_error::ProgramError, pubkey::Pubkey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TokenAccount { pub mint: Pubkey, pub owner: Pubkey, pub amount: u64 }
pub struct Mint;

fn option_tag(data: &[u8], offset: usize) -> Result<(), ProgramError> {
    let tag = u32::from_le_bytes(data[offset..offset + 4].try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?);
    if tag > 1 { return Err(ProgramError::InvalidAccountData); }
    Ok(())
}

impl TokenAccount {
    pub const LEN: usize = 165;
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN { return Err(ProgramError::InvalidAccountData); }
        // Delegate, native reserve and close-authority COption tags are all
        // validated, including fields not returned to the caller. None tags
        // do not require zero bodies, matching SDK Pack.
        option_tag(data, 72)?; option_tag(data, 109)?; option_tag(data, 129)?;
        match data[108] {
            0 => return Err(ProgramError::UninitializedAccount),
            1 | 2 => {}, // Frozen2 is initialized; the SPL CPI rejects transfer.
            _ => return Err(ProgramError::InvalidAccountData),
        }
        Ok(Self {
            mint: Pubkey::new_from_array(data[..32].try_into().map_err(|_| ProgramError::InvalidAccountData)?),
            owner: Pubkey::new_from_array(data[32..64].try_into().map_err(|_| ProgramError::InvalidAccountData)?),
            amount: u64::from_le_bytes(data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?),
        })
    }
}

impl Mint {
    pub const LEN: usize = 82;
    pub fn unpack(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN { return Err(ProgramError::InvalidAccountData); }
        option_tag(data, 0)?; option_tag(data, 46)?;
        match data[45] {
            0 => Err(ProgramError::UninitializedAccount),
            1 => Ok(Self),
            _ => Err(ProgramError::InvalidAccountData),
        }
    }
}
