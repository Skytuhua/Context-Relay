use std::{
    ffi::{OsString, c_void},
    os::windows::ffi::OsStringExt,
    path::PathBuf,
    ptr::null_mut,
};

use windows_sys::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            Authorization::ConvertSidToStringSidW,
            FreeSid,
            Isolation::{
                CreateAppContainerProfile, DeleteAppContainerProfile,
                DeriveAppContainerSidFromAppContainerName, GetAppContainerFolderPath,
            },
            PSID,
        },
        System::Com::CoTaskMemFree,
    },
    core::PWSTR,
};

use super::{CreateProfileOutcome, LaunchError, ProfileApi, ProfileIdentity, ProfileMoniker};

const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00b7_u32 as i32;
const MAX_RETURNED_WIDE_CHARS: usize = 32_768;

#[derive(Default)]
pub struct Win32ProfileApi;

impl Win32ProfileApi {
    pub const fn new() -> Self {
        Self
    }

    pub fn profile_folder(&self, identity: &ProfileIdentity) -> Result<PathBuf, LaunchError> {
        let sid = wide(identity.sid());
        let mut raw_path: PWSTR = null_mut();
        let result = unsafe { GetAppContainerFolderPath(sid.as_ptr(), &mut raw_path) };
        hresult(result)?;
        let path = CoTaskWide::new(raw_path)?;
        Ok(PathBuf::from(path.to_os_string()?))
    }
}

pub fn cleanup_recovered_profile(moniker: &str, sid: &str) -> Result<(), LaunchError> {
    let moniker = ProfileMoniker::from_journaled(moniker)?;
    if !valid_recovery_sid(sid) {
        return Err(LaunchError::InvalidProfileIdentity);
    }
    let identity = ProfileIdentity::from_derived(moniker, sid)?;
    Win32ProfileApi::new().delete_profile(&identity)
}

fn valid_recovery_sid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-15-2-") else {
        return false;
    };
    let mut parts = rest.split('-');
    (0..7).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && (part.len() == 1 || !part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u32>().is_ok()
        })
    }) && parts.next().is_none()
}

impl ProfileApi for Win32ProfileApi {
    fn derive_identity(
        &mut self,
        moniker: &ProfileMoniker,
    ) -> Result<ProfileIdentity, LaunchError> {
        let moniker_wide = wide(moniker.as_str());
        let mut raw_sid: PSID = null_mut();
        let result = unsafe {
            DeriveAppContainerSidFromAppContainerName(moniker_wide.as_ptr(), &mut raw_sid)
        };
        hresult(result)?;
        let sid = OwnedSid::new(raw_sid)?;
        ProfileIdentity::from_derived(moniker.clone(), sid.to_text()?)
    }

    fn create_profile(
        &mut self,
        identity: &ProfileIdentity,
    ) -> Result<CreateProfileOutcome, LaunchError> {
        let moniker = wide(identity.moniker().as_str());
        let display_name = wide("Context Relay isolated native runner");
        let description = wide("Single-transaction zero-capability AppContainer");
        let mut raw_sid: PSID = null_mut();
        let result = unsafe {
            CreateAppContainerProfile(
                moniker.as_ptr(),
                display_name.as_ptr(),
                description.as_ptr(),
                std::ptr::null(),
                0,
                &mut raw_sid,
            )
        };
        if result == HRESULT_ALREADY_EXISTS {
            if !raw_sid.is_null() {
                drop(OwnedSid(raw_sid));
            }
            return Ok(CreateProfileOutcome::AlreadyExists);
        }
        if result < 0 {
            if !raw_sid.is_null() {
                drop(OwnedSid(raw_sid));
            }
            return Err(LaunchError::HResult(result));
        }
        let returned = OwnedSid::new(raw_sid)?;
        if returned.to_text()? != identity.sid() {
            return Err(LaunchError::ProfileIdentityMismatch);
        }
        Ok(CreateProfileOutcome::Created)
    }

    fn delete_profile(&mut self, identity: &ProfileIdentity) -> Result<(), LaunchError> {
        let derived = self.derive_identity(identity.moniker())?;
        if &derived != identity {
            return Err(LaunchError::ProfileIdentityMismatch);
        }
        let moniker = wide(identity.moniker().as_str());
        hresult(unsafe { DeleteAppContainerProfile(moniker.as_ptr()) })
    }
}

pub(crate) struct OwnedSid(PSID);

impl OwnedSid {
    fn new(sid: PSID) -> Result<Self, LaunchError> {
        if sid.is_null() {
            return Err(LaunchError::InvalidProfileIdentity);
        }
        Ok(Self(sid))
    }

    pub(crate) fn as_ptr(&self) -> PSID {
        self.0
    }

    pub(crate) fn to_text(&self) -> Result<String, LaunchError> {
        let mut raw_text: PWSTR = null_mut();
        if unsafe { ConvertSidToStringSidW(self.0, &mut raw_text) } == 0 {
            return Err(last_error());
        }
        LocalWide::new(raw_text)?.to_string()
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        unsafe {
            FreeSid(self.0);
        }
    }
}

struct LocalWide(PWSTR);

impl LocalWide {
    fn new(value: PWSTR) -> Result<Self, LaunchError> {
        if value.is_null() {
            return Err(LaunchError::InvalidProfileIdentity);
        }
        Ok(Self(value))
    }

    fn to_string(&self) -> Result<String, LaunchError> {
        self.to_os_string()?
            .into_string()
            .map_err(|_| LaunchError::InvalidProfileIdentity)
    }

    fn to_os_string(&self) -> Result<OsString, LaunchError> {
        unsafe { copy_wide(self.0) }
    }
}

impl Drop for LocalWide {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0.cast::<c_void>() as HLOCAL);
        }
    }
}

struct CoTaskWide(PWSTR);

impl CoTaskWide {
    fn new(value: PWSTR) -> Result<Self, LaunchError> {
        if value.is_null() {
            return Err(LaunchError::InvalidProfileIdentity);
        }
        Ok(Self(value))
    }

    fn to_os_string(&self) -> Result<OsString, LaunchError> {
        unsafe { copy_wide(self.0) }
    }
}

impl Drop for CoTaskWide {
    fn drop(&mut self) {
        unsafe {
            CoTaskMemFree(self.0.cast());
        }
    }
}

unsafe fn copy_wide(value: PWSTR) -> Result<OsString, LaunchError> {
    let mut length = 0;
    while length < MAX_RETURNED_WIDE_CHARS {
        if unsafe { *value.add(length) } == 0 {
            let units = unsafe { std::slice::from_raw_parts(value, length) };
            return Ok(OsString::from_wide(units));
        }
        length += 1;
    }
    Err(LaunchError::InvalidProfileIdentity)
}

pub(crate) fn derive_owned_sid(identity: &ProfileIdentity) -> Result<OwnedSid, LaunchError> {
    let moniker = wide(identity.moniker().as_str());
    let mut raw_sid: PSID = null_mut();
    hresult(unsafe { DeriveAppContainerSidFromAppContainerName(moniker.as_ptr(), &mut raw_sid) })?;
    let sid = OwnedSid::new(raw_sid)?;
    if sid.to_text()? != identity.sid() {
        return Err(LaunchError::ProfileIdentityMismatch);
    }
    Ok(sid)
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn hresult(result: i32) -> Result<(), LaunchError> {
    if result < 0 {
        Err(LaunchError::HResult(result))
    } else {
        Ok(())
    }
}

pub(crate) fn last_error() -> LaunchError {
    LaunchError::Win32(unsafe { windows_sys::Win32::Foundation::GetLastError() })
}
