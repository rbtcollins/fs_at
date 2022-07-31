use std::{fmt, mem::MaybeUninit};

use ntapi::ntrtl::{RtlInitUnicodeStringEx, RtlNtStatusToDosError};
use winapi::shared::ntdef::{NTSTATUS, NT_SUCCESS, UNICODE_STRING};

pub struct NTStatusError {
    pub status: NTSTATUS,
}

impl NTStatusError {
    pub fn from(status: NTSTATUS) -> std::result::Result<(), NTStatusError> {
        if NT_SUCCESS(status) {
            Ok(())
        } else {
            Err(NTStatusError { status })
        }
    }
}

impl fmt::Display for NTStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = unsafe { RtlNtStatusToDosError(self.status) };
        let err = std::io::Error::from_raw_os_error(code as i32);
        err.fmt(f)
    }
}

impl From<NTStatusError> for std::io::Error {
    fn from(status: NTStatusError) -> Self {
        let code: i32 = unsafe { RtlNtStatusToDosError(status.status) as i32 };
        std::io::Error::from_raw_os_error(code)
    }
}

// This does not have (or need) Drop: the vec retains the content, and we
// don't call RtlAnsiStringToUnicodeString
pub struct OSUnicodeString {
    _content: Vec<u16>,
    pub inner: UNICODE_STRING,
}

impl TryFrom<Vec<u16>> for OSUnicodeString {
    type Error = NTStatusError;

    fn try_from(content: Vec<u16>) -> std::result::Result<Self, Self::Error> {
        let mut content = content;
        content.push(0);
        let mut inner = MaybeUninit::uninit();
        unsafe {
            NTStatusError::from(RtlInitUnicodeStringEx(
                inner.as_mut_ptr(),
                content.as_mut_ptr(),
            ))
        }?;
        Ok(OSUnicodeString {
            _content: content,
            inner: unsafe { inner.assume_init() },
        })
    }
}
