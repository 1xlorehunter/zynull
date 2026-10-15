use solana_program::program_error::ProgramError;
use solana_poseidon::{hashv, Endianness, Parameters};
use crate::zeroes::{EMPTY_ROOT, ZERO_NODES};

pub const DEPTH: usize = 32;
pub const ROOT_HISTORY: usize = 512;
pub const CAPACITY: u64 = 1u64 << DEPTH;
pub const HEADER_LEN: usize = 49;
pub const ROOTS_START: usize = HEADER_LEN + DEPTH * 32;
pub const STATE_LEN: usize = ROOTS_START + ROOT_HISTORY * 32;
const MAGIC: &[u8; 4] = b"PSW9";

pub fn poseidon_pair(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let hash = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[left, right])
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    Ok(hash.to_bytes())
}

pub fn mint_asset_id(mint: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let mut domain = [0u8; 32];
    domain[31] = 51;
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first[16..].copy_from_slice(&mint[..16]);
    second[16..].copy_from_slice(&mint[16..]);
    let id = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&domain, &first, &second])
        .map_err(|_| ProgramError::InvalidInstructionData)?.to_bytes();
    if id == [0u8; 32] { return Err(ProgramError::InvalidInstructionData); }
    Ok(id)
}

// History lives on the heap instead of constructing a 16 KiB stack array.
// State is boxed as well, keeping the instruction frame below SBF's 4096-byte
// bound. The public layout is independent of this in-memory representation.
pub struct State {
    pub bump: u8,
    pub leaf_count: u64,
    roots_len: u16,
    next_root: u16,
    pub root: [u8; 32],
    frontier: [[u8; 32]; DEPTH],
    roots: Box<[[u8; 32]]>,
}

impl State {
    pub fn new(bump: u8) -> Result<Box<Self>, ProgramError> {
        let mut roots = vec![[0u8; 32]; ROOT_HISTORY].into_boxed_slice();
        roots[0] = EMPTY_ROOT;
        Ok(Box::new(Self {
            bump, leaf_count: 0, roots_len: 1, next_root: 1,
            root: EMPTY_ROOT, frontier: [[0u8; 32]; DEPTH], roots,
        }))
    }

    pub fn read(data: &[u8]) -> Result<Box<Self>, ProgramError> {
        if data.len() != STATE_LEN || &data[..4] != MAGIC {
            return Err(ProgramError::InvalidAccountData);
        }
        let leaf_count = u64::from_le_bytes(data[5..13].try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?);
        let roots_len = u16::from_le_bytes(data[13..15].try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?);
        let next_root = u16::from_le_bytes(data[15..17].try_into()
            .map_err(|_| ProgramError::InvalidAccountData)?);
        // History contains the initial root and only the final root of each
        // completed operation; its four outputs are appended atomically.
        let total_roots = leaf_count / 4 + 1;
        if leaf_count > CAPACITY || leaf_count % 4 != 0
            || roots_len as u64 != total_roots.min(ROOT_HISTORY as u64)
            || next_root as u64 != total_roots % ROOT_HISTORY as u64 {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut state = Self::new(data[4])?;
        state.leaf_count = leaf_count;
        state.roots_len = roots_len;
        state.next_root = next_root;
        state.root.copy_from_slice(&data[17..HEADER_LEN]);
        for (i, item) in state.frontier.iter_mut().enumerate() {
            item.copy_from_slice(&data[HEADER_LEN + i * 32..HEADER_LEN + (i + 1) * 32]);
        }
        for (i, item) in state.roots.iter_mut().enumerate() {
            item.copy_from_slice(&data[ROOTS_START + i * 32..ROOTS_START + (i + 1) * 32]);
        }
        let latest = (next_root as usize + ROOT_HISTORY - 1) % ROOT_HISTORY;
        if state.roots[latest] != state.root { return Err(ProgramError::InvalidAccountData); }
        Ok(state)
    }

    pub fn write(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() != STATE_LEN { return Err(ProgramError::InvalidAccountData); }
        data[..4].copy_from_slice(MAGIC);
        data[4] = self.bump;
        data[5..13].copy_from_slice(&self.leaf_count.to_le_bytes());
        data[13..15].copy_from_slice(&self.roots_len.to_le_bytes());
        data[15..17].copy_from_slice(&self.next_root.to_le_bytes());
        data[17..HEADER_LEN].copy_from_slice(&self.root);
        for (i, item) in self.frontier.iter().enumerate() {
            data[HEADER_LEN + i * 32..HEADER_LEN + (i + 1) * 32].copy_from_slice(item);
        }
        for (i, item) in self.roots.iter().enumerate() {
            data[ROOTS_START + i * 32..ROOTS_START + (i + 1) * 32].copy_from_slice(item);
        }
        Ok(())
    }

    pub fn root_at(&self, index: u16) -> Result<[u8; 32], ProgramError> {
        if index >= self.roots_len { return Err(ProgramError::InvalidInstructionData); }
        Ok(self.roots[index as usize])
    }

    pub fn ensure_room(&self) -> Result<(), ProgramError> {
        if self.leaf_count.checked_add(4).filter(|count| *count <= CAPACITY).is_none() {
            return Err(ProgramError::AccountDataTooSmall);
        }
        Ok(())
    }

    fn append_leaf(&mut self, leaf: [u8; 32]) -> Result<(), ProgramError> {
        let index = self.leaf_count;
        let mut node = leaf;
        for (level, zero) in ZERO_NODES.iter().enumerate() {
            if ((index >> level) & 1) == 0 {
                self.frontier[level] = node;
                node = poseidon_pair(&node, zero)?;
            } else { node = poseidon_pair(&self.frontier[level], &node)?; }
        }
        self.leaf_count = self.leaf_count.checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        self.root = node;
        Ok(())
    }

    pub fn append_outputs(&mut self, leaves: &[[u8; 32]; 4]) -> Result<(), ProgramError> {
        self.ensure_room()?;
        for leaf in leaves { self.append_leaf(*leaf)?; }
        self.roots[self.next_root as usize] = self.root;
        self.next_root = (self.next_root + 1) % ROOT_HISTORY as u16;
        if self.roots_len < ROOT_HISTORY as u16 { self.roots_len += 1; }
        Ok(())
    }
}
