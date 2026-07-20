use std::{
    io::{ErrorKind, Read},
    path::PathBuf,
    process::ExitCode,
};

use context_relay_native_runner::{
    HydrationFile, HydrationOutcome, RunnerError, StagePath, install_hydrated_closure,
};

const MAGIC: &[u8; 8] = b"CRHYDR1\0";
const MAX_TEXT_BYTES: usize = 32 * 1024;
const MAX_FILES: usize = 64;
const MAX_FILE_BYTES: usize = 268_435_456;
const MAX_TOTAL_BYTES: usize = 768 * 1024 * 1024;

fn main() -> ExitCode {
    match run(&mut std::io::stdin().lock()) {
        Ok(HydrationOutcome::Installed) => {
            println!("installed");
            ExitCode::SUCCESS
        }
        Ok(HydrationOutcome::AlreadyExists) => {
            println!("exists");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("guarded hydration failed: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(reader: &mut impl Read) -> Result<HydrationOutcome, RunnerError> {
    let mut magic = [0_u8; 8];
    read_exact(reader, &mut magic)?;
    if &magic != MAGIC {
        return Err(RunnerError::InvalidFrame);
    }
    let workspace_length = read_u32(reader)? as usize;
    let workspace = PathBuf::from(read_text(reader, workspace_length)?);
    let target_length = usize::from(read_u16(reader)?);
    let target = read_text(reader, target_length)?;
    let mut manifest = [0_u8; 32];
    let mut nonce = [0_u8; 16];
    read_exact(reader, &mut manifest)?;
    read_exact(reader, &mut nonce)?;
    let count = usize::from(read_u16(reader)?);
    if count == 0 || count > MAX_FILES {
        return Err(RunnerError::LimitExceeded);
    }
    let mut total = 0_usize;
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let path_length = usize::from(read_u16(reader)?);
        let path = StagePath::try_from(read_text(reader, path_length)?)?;
        let executable = match read_u8(reader)? {
            0 => false,
            1 => true,
            _ => return Err(RunnerError::InvalidFrame),
        };
        let size = usize::try_from(read_u64(reader)?).map_err(|_| RunnerError::LimitExceeded)?;
        total = total.checked_add(size).ok_or(RunnerError::LimitExceeded)?;
        if size > MAX_FILE_BYTES || total > MAX_TOTAL_BYTES {
            return Err(RunnerError::LimitExceeded);
        }
        let mut digest = [0_u8; 32];
        read_exact(reader, &mut digest)?;
        let mut bytes = vec![0_u8; size];
        read_exact(reader, &mut bytes)?;
        files.push(HydrationFile::new(path, bytes, digest, executable)?);
    }
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(RunnerError::InvalidFrame),
        Err(error) if error.kind() == ErrorKind::UnexpectedEof => {}
        Err(_) => return Err(RunnerError::Io),
    }
    install_hydrated_closure(&workspace, &target, manifest, nonce, files)
}

fn read_text(reader: &mut impl Read, length: usize) -> Result<String, RunnerError> {
    if length == 0 || length > MAX_TEXT_BYTES {
        return Err(RunnerError::InvalidFrame);
    }
    let mut bytes = vec![0_u8; length];
    read_exact(reader, &mut bytes)?;
    String::from_utf8(bytes).map_err(|_| RunnerError::InvalidFrame)
}

fn read_u8(reader: &mut impl Read) -> Result<u8, RunnerError> {
    let mut bytes = [0_u8; 1];
    read_exact(reader, &mut bytes)?;
    Ok(bytes[0])
}

fn read_u16(reader: &mut impl Read) -> Result<u16, RunnerError> {
    let mut bytes = [0_u8; 2];
    read_exact(reader, &mut bytes)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(reader: &mut impl Read) -> Result<u32, RunnerError> {
    let mut bytes = [0_u8; 4];
    read_exact(reader, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(reader: &mut impl Read) -> Result<u64, RunnerError> {
    let mut bytes = [0_u8; 8];
    read_exact(reader, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), RunnerError> {
    reader
        .read_exact(bytes)
        .map_err(|_| RunnerError::InvalidFrame)
}
