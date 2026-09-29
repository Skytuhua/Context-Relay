//! Bounded inspection, followed by dynamic validation, for packaged library constraints.

use sha2::{Digest, Sha256};

fn inspect_constraint(bytes: &[u8], expected: &[u8; 32]) -> Option<[u8; 20]> {
    fn word(bytes: &[u8], offset: usize, little: bool) -> Option<u32> {
        let value = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        })
    }
    let le = |offset| word(bytes, offset, true);
    if bytes.len() > 256 * 1024 * 1024
        || le(0)? != 0xfeedfacf
        || le(4)? != 0x0100000c
        || le(12)? != 2
    {
        return None;
    }
    let count = le(16)? as usize;
    let end = 32_usize.checked_add(le(20)? as usize)?;
    if end > bytes.len() || count == 0 || count > (end - 32) / 8 {
        return None;
    }
    let mut offset = 32_usize;
    let mut signature = None;
    for _ in 0..count {
        if offset.checked_add(8)? > end {
            return None;
        }
        let command = le(offset)?;
        let size = le(offset + 4)? as usize;
        let next = offset.checked_add(size)?;
        if size < 8 || !size.is_multiple_of(8) || next > end {
            return None;
        }
        if command == 0x1d {
            if size != 16 || signature.is_some() {
                return None;
            }
            let start = le(offset + 8)? as usize;
            let length = le(offset + 12)? as usize;
            if start < end || length > 16 * 1024 * 1024 {
                return None;
            }
            signature = Some(bytes.get(start..start.checked_add(length)?)?);
        }
        offset = next;
    }
    if offset != end {
        return None;
    }
    let signature = signature?;
    let be = |offset| word(signature, offset, false);
    if be(0)? != 0xfade0cc0 {
        return None;
    }
    let length = be(4)? as usize;
    let count = be(8)? as usize;
    if count == 0 || count > 64 || length > signature.len() {
        return None;
    }
    let table_end = 12 + count * 8;
    if table_end > length {
        return None;
    }
    let mut directory = None;
    let mut constraint = None;
    let mut entries = Vec::new();
    for index in 0..count {
        let slot = be(12 + index * 8)?;
        let start = be(16 + index * 8)? as usize;
        let size = be(start.checked_add(4)?)? as usize;
        let end = start.checked_add(size)?;
        if start < table_end
            || size < 8
            || end > length
            || (0x1000..0x1006).contains(&slot)
            || entries
                .iter()
                .any(|&(prior, a, b)| prior == slot || (start < b && end > a))
        {
            return None;
        }
        entries.push((slot, start, end));
        match slot {
            0 => directory = Some(&signature[start..end]),
            11 => constraint = Some(&signature[start..end]),
            _ => {}
        }
    }
    let directory = directory?;
    let be = |offset| word(directory, offset, false);
    let minimum = match be(8)? {
        0x20500 => 96,
        0x20600 => 108,
        _ => return None,
    };
    if directory.len() < minimum
        || be(0)? != 0xfade0c02
        || directory[36] != 32
        || directory[37] != 2
    {
        return None;
    }
    let special = be(24)? as usize;
    let code = be(28)? as usize;
    let hashes = be(16)? as usize;
    if special < 11
        || hashes.checked_sub(special.checked_mul(32)?)? < minimum
        || hashes.checked_add(code.checked_mul(32)?)? > directory.len()
    {
        return None;
    }
    let recorded = directory.get(hashes.checked_sub(11 * 32)?..hashes.checked_sub(10 * 32)?)?;
    if recorded != expected || Sha256::digest(constraint?)[..] != expected[..] {
        return None;
    }
    Sha256::digest(directory)[..20].try_into().ok()
}

/// Bind the inspected constraint to this running process before loading native code.
/// `expected` must be compiled into the caller from the release signing inputs.
#[cfg(target_os = "macos")]
pub fn verify_current_library_constraint(
    expected: &[u8; 32],
) -> Result<(), crate::macos::MacPolicyError> {
    use crate::macos::MacPolicyError::IdentityMismatch;
    use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

    let mut release = [0_u8; 128];
    let mut length = release.len();
    if unsafe {
        libc::sysctlbyname(
            c"kern.osrelease".as_ptr(),
            release.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length > release.len()
    {
        return Err(IdentityMismatch);
    }
    let major = std::str::from_utf8(&release[..length])
        .ok()
        .and_then(|version| version.split('.').next())
        .and_then(|major| major.parse::<u32>().ok());
    // Darwin 23 is macOS 14, the first release enforcing library constraints.
    if !major.is_some_and(|major| major >= 23) {
        return Err(IdentityMismatch);
    }

    let executable = std::env::current_exe().map_err(|_| IdentityMismatch)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(executable)
        .map_err(|_| IdentityMismatch)?;
    let metadata = file.metadata().map_err(|_| IdentityMismatch)?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 * 1024 {
        return Err(IdentityMismatch);
    }
    let mut bytes = Vec::new();
    (&file)
        .take(256 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| IdentityMismatch)?;
    let cdhash = inspect_constraint(&bytes, expected).ok_or(IdentityMismatch)?;
    let hex: String = cdhash.iter().map(|byte| format!("{byte:02x}")).collect();
    let requirement: SecRequirement = format!("cdhash H\"{hex}\"")
        .parse()
        .map_err(|_| IdentityMismatch)?;
    let code = SecCode::for_self(Flags::NONE).map_err(|_| IdentityMismatch)?;
    code.check_validity(
        Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
        &requirement,
    )
    .map_err(|_| IdentityMismatch)?;
    verify_dynamic_status(&code)
}

fn acceptable_dynamic_status(status: u32) -> bool {
    // CS_VALID, CS_RUNTIME; reject CS_DEBUGGED and CS_GET_TASK_ALLOW.
    status & 0x10001 == 0x10001 && status & 0x10000004 == 0
}

#[cfg(target_os = "macos")]
fn verify_dynamic_status(
    code: &security_framework::os::macos::code_signing::SecCode,
) -> Result<(), crate::macos::MacPolicyError> {
    use crate::macos::MacPolicyError::IdentityMismatch;
    use core_foundation::base::TCFType;
    use core_foundation_sys::{
        base::{CFGetTypeID, CFRelease},
        dictionary::{CFDictionaryGetValue, CFDictionaryRef},
        number::{CFNumberGetTypeID, CFNumberGetValue, kCFNumberSInt64Type},
        string::CFStringRef,
    };
    use std::ffi::c_void;
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecCodeInfoStatus: CFStringRef;
        fn SecCodeCopySigningInformation(
            code: *mut c_void,
            flags: u32,
            information: *mut CFDictionaryRef,
        ) -> i32;
    }
    let mut information = std::ptr::null();
    // Public kSecCSDynamicInformation, not the private constraint-information SPI.
    if unsafe {
        SecCodeCopySigningInformation(code.as_concrete_TypeRef().cast(), 1 << 3, &mut information)
    } != 0
        || information.is_null()
    {
        return Err(IdentityMismatch);
    }
    let result = (|| {
        let value = unsafe { CFDictionaryGetValue(information, kSecCodeInfoStatus.cast()) };
        if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFNumberGetTypeID() } {
            return Err(IdentityMismatch);
        }
        let mut status = 0_i64;
        if !unsafe {
            CFNumberGetValue(
                value.cast(),
                kCFNumberSInt64Type,
                (&mut status as *mut i64).cast(),
            )
        } {
            return Err(IdentityMismatch);
        }
        if u32::try_from(status)
            .ok()
            .is_some_and(acceptable_dynamic_status)
        {
            Ok(())
        } else {
            Err(IdentityMismatch)
        }
    })();
    unsafe {
        CFRelease(information.cast());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn fixture() -> (Vec<u8>, [u8; 32]) {
        let constraint = b"\xfa\xde\x81\x81\0\0\0\x0ctest";
        let digest: [u8; 32] = Sha256::digest(constraint).into();
        let mut directory = vec![0; 96 + 11 * 32 + 32];
        let length = directory.len() as u32;
        for (offset, value) in [
            (0, 0xfade0c02),
            (4, length),
            (8, 0x20500),
            (16, 96 + 11 * 32),
            (24, 11),
            (28, 1),
        ] {
            directory[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        directory[36] = 32;
        directory[37] = 2;
        directory[96..128].copy_from_slice(&digest);
        let mut signature = vec![0; 28];
        let total = (signature.len() + directory.len() + constraint.len()) as u32;
        for (offset, value) in [
            (0, 0xfade0cc0),
            (4, total),
            (8, 2),
            (12, 0),
            (16, 28),
            (20, 11),
            (24, 28 + directory.len() as u32),
        ] {
            signature[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        signature.extend_from_slice(&directory);
        signature.extend_from_slice(constraint);
        let mut executable = vec![0; 48];
        for (offset, value) in [
            (0, 0xfeedfacf_u32),
            (4, 0x0100000c),
            (12, 2),
            (16, 1),
            (20, 16),
            (32, 0x1d),
            (36, 16),
            (40, 48),
            (44, total),
        ] {
            executable[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        executable.extend_from_slice(&signature);
        (executable, digest)
    }

    #[test]
    fn signed_constraint_inspection_binds_the_exact_blob_and_code_directory() {
        let (bytes, digest) = fixture();
        let expected = Sha256::digest(&bytes[76..76 + 480]);
        assert_eq!(
            inspect_constraint(&bytes, &digest),
            Some(expected[..20].try_into().unwrap())
        );
        assert_eq!(inspect_constraint(&bytes, &[0; 32]), None);
        for length in 0..bytes.len() {
            assert_eq!(inspect_constraint(&bytes[..length], &digest), None);
        }
        for offset in [
            0, 4, 12, 16, 20, 32, 36, 40, 44, 48, 52, 56, 64, 68, 72, 76, 80, 84, 92, 100, 104,
            112, 113, 172,
        ] {
            let mut malformed = bytes.clone();
            malformed[offset] ^= 0xff;
            assert_eq!(
                inspect_constraint(&malformed, &digest),
                None,
                "offset {offset}"
            );
        }
    }

    #[test]
    fn library_constraint_requires_valid_hardened_non_debugged_execution() {
        assert!(acceptable_dynamic_status(0x10001));
        for status in [0, 1, 0x10000, 0x10010001, 0x10005] {
            assert!(!acceptable_dynamic_status(status));
        }
    }
}
