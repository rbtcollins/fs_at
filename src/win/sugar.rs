use std::{fmt, mem::MaybeUninit};

use windows_sys::Win32::{
    Foundation::{
        RtlNtStatusToDosError, NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, UNICODE_STRING,
    },
    System::{SystemServices::UNICODE_STRING_MAX_CHARS, WindowsProgramming::RtlInitUnicodeString},
};

pub struct NTStatusError {
    pub status: NTSTATUS,
}

impl NTStatusError {
    pub fn from(status: NTSTATUS) -> std::result::Result<(), NTStatusError> {
        if status >= 0 {
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
            NTStatusError::from(init_unicode_string(
                inner.as_mut_ptr(),
                content.as_mut_ptr(),
            ))
        }?;
        // The manual copying of fields is because RtlInitUnicodeStringEx is
        // working on the winapi type definition.
        let winapi_string = unsafe { inner.assume_init() };
        Ok(OSUnicodeString {
            _content: content,
            inner: UNICODE_STRING {
                Length: winapi_string.Length,
                MaximumLength: winapi_string.MaximumLength,
                Buffer: winapi_string.Buffer,
            },
        })
    }
}

// RtlInitUnicodeStringEx isn't available in windows_sys at this time (see https://github.com/microsoft/win32metadata/issues/1461)
// so we're going to roll our own. We'll rely on RtlInitUnicodeString to do this, and just make sure we don't pass it information that would
// induce an error.
unsafe fn init_unicode_string(
    destination_string: *mut UNICODE_STRING,
    source_string: *mut u16,
) -> NTSTATUS {
    if destination_string.is_null() && !source_string.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut cursor = 0;
    while *(source_string.offset(cursor)) != 0 {
        cursor += 1;
        if cursor == UNICODE_STRING_MAX_CHARS as isize {
            return STATUS_INVALID_PARAMETER;
        }
    }
    RtlInitUnicodeString(destination_string, source_string);
    STATUS_SUCCESS
}
