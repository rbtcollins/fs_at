mod sugar;

use std::{
    ffi, fmt,
    fs::File,
    io::Result,
    mem::{size_of, zeroed, MaybeUninit},
    os::windows::prelude::{AsRawHandle, FromRawHandle, OsStrExt},
    path::Path,
    ptr::null_mut,
};

use ntapi::ntioapi::{FILE_CREATE, FILE_CREATED, FILE_DIRECTORY_FILE};
use winapi::{
    ctypes,
    shared::{
        minwindef::ULONG,
        ntdef::{NULL, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, PLARGE_INTEGER, PVOID},
    },
    um::winnt::{
        DELETE, FILE_ATTRIBUTE_NORMAL, FILE_LIST_DIRECTORY, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TRAVERSE, PSECURITY_QUALITY_OF_SERVICE,
        SECURITY_CONTEXT_TRACKING_MODE, SECURITY_DESCRIPTOR, SECURITY_QUALITY_OF_SERVICE,
    },
};

use sugar::{NTStatusError, OSUnicodeString};

use crate::OpenOptions;

pub mod exports {
    pub use super::OpenOptionsExt;
    #[doc(no_inline)]
    pub use winapi::um::winnt::SECURITY_CONTEXT_TRACKING_MODE;
    #[doc(no_inline)]
    pub use winapi::um::winnt::SECURITY_DESCRIPTOR;
}

#[derive(Default)]
pub(crate) struct OpenOptionsImpl {
    // LARGE_INTEGER defined as signed 64-bit
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-large_integer-r1
    allocation_size: i64,
    //https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#dwFlagsAndAttributes
    file_attributes: ULONG,
    object_attributes: ULONG,
    security_descriptor: Option<SECURITY_DESCRIPTOR>,
    security_qos: Option<SECURITY_QUALITY_OF_SERVICE>,
}

impl fmt::Debug for OpenOptionsImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let qos_value = self.security_qos.and(Some("SET")).unwrap_or("NOTSET");
        let descriptor_value = self
            .security_descriptor
            .and(Some("SET"))
            .unwrap_or("NOTSET");
        f.debug_struct("OpenOptionsImpl")
            .field("object_attributes", &self.object_attributes)
            .field("security_qos", &qos_value)
            .field("security_descriptor", &descriptor_value)
            .finish()
    }
}

impl OpenOptionsImpl {
    pub fn mkdirat(&self, f: &mut File, path: &Path) -> Result<File> {
        let mut handle = MaybeUninit::uninit();
        let mut object_attributes: OBJECT_ATTRIBUTES = unsafe { zeroed() };
        object_attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        object_attributes.RootDirectory = f.as_raw_handle() as *mut ctypes::c_void;
        let u16_path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
        let mut rtl_string = OSUnicodeString::try_from(u16_path)?;
        object_attributes.ObjectName = &mut rtl_string.inner;
        // Only OBJ_CASE_INSENSITIVE is defined currently. What of
        // https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
        // should be permitted through? Everything?
        // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
        // only specifies OBJ_CASE_INSENSITIVE
        object_attributes.Attributes = self.object_attributes & OBJ_CASE_INSENSITIVE;
        // Should allow setting this; NULL is sane but not fully flexible.
        // https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors
        let mut security_descriptor = self.security_descriptor;
        object_attributes.SecurityDescriptor = match security_descriptor {
            Some(ref mut val) => val as *mut SECURITY_DESCRIPTOR as PVOID,
            None => NULL,
        };
        // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service
        let mut security_qos = self.security_qos;
        object_attributes.SecurityQualityOfService = match security_qos {
            Some(ref mut val) => val as PSECURITY_QUALITY_OF_SERVICE as PVOID,
            None => NULL,
        };
        let mut status_block = MaybeUninit::uninit();

        // Perhaps not worth exposing?
        let mut allocation_size = self.allocation_size;
        let allocation_size_ptr = if allocation_size > 0 {
            &mut allocation_size as *mut i64 as PLARGE_INTEGER
        } else {
            0 as PLARGE_INTEGER
        };

        // Do we need FILE_FLAG_OPEN_REPARSE_POINT
        // handling at this layer? Perhaps users should choose.
        let file_attributes = if self.file_attributes == 0 {
            FILE_ATTRIBUTE_NORMAL
        } else {
            self.file_attributes
        };

        let file_disposition = FILE_CREATE;
        let create_options = FILE_DIRECTORY_FILE;
        // TODO: support EA attributes if someone asks for it.
        let ea_buffer = null_mut();
        let ea_length = 0;
        // This should be exposed (e.g. to permit secure temp dirs, secure untarring etc).
        let share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        unsafe {
            let ntstatus = ntapi::ntioapi::NtCreateFile(
                handle.as_mut_ptr(),
                DELETE | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
                &mut object_attributes,
                status_block.as_mut_ptr(),
                allocation_size_ptr,
                file_attributes,
                share_access,
                file_disposition,
                create_options,
                ea_buffer,
                ea_length,
            );
            NTStatusError::from(ntstatus)
        }?;
        let status_block = unsafe { status_block.assume_init() };
        // can be
        // FILE_CREATED
        // FILE_OPENED
        // FILE_OVERWRITTEN
        // FILE_SUPERSEDED
        // FILE_EXISTS
        // FILE_DOES_NOT_EXIST
        // we want FILE_CREATED only
        if ULONG::try_from(status_block.Information).unwrap() == FILE_CREATED {
            // success
            Ok(unsafe { File::from_raw_handle(handle.assume_init() as *mut ffi::c_void) })
            // Ok(unsafe { File::from_raw_handle(handle) })
        } else {
            unimplemented!("expected FILE_CREATED, got {}", status_block.Information);
        }
    }

    fn with_security_qos<F>(&mut self, mutator: F)
    where
        F: FnOnce(&mut SECURITY_QUALITY_OF_SERVICE),
    {
        if self.security_qos.is_none() {
            self.security_qos =
                Some(unsafe { zeroed::<SECURITY_QUALITY_OF_SERVICE>() }).map(|mut qos| {
                    qos.Length = size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32;
                    qos
                });
        }
        self.security_qos = self.security_qos.map(|mut qos| {
            mutator(&mut qos);
            qos
        });
    }
}

pub trait OpenOptionsExt {
    /**
    Set the AllocationSize parameter to NTCreateFile.

    Only takes effect when creating a file.

    ```no_run
    extern crate winapi;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.allocation_size(12345);
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```
    */
    fn allocation_size(&mut self, val: i64) -> &mut Self;

    /**
    Set the FileAttributes field used with NTCreateFile.

    When this is not called, fs_at uses FILE_ATTRIBUTE_NORMAL

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#dwFlagsAndAttributes) - see the dwFlagsAndAttributes values.

    ```no_run
    extern crate winapi;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.file_attributes(winapi::um::winnt::FILE_ATTRIBUTE_TEMPORARY);
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```

    */
    fn file_attributes(&mut self, val: ULONG) -> &mut Self;

    /**
    Set the Attributes field of the ObjectAttributes parameter to NTCreateFile.

    ```no_run
    extern crate winapi;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.object_attributes(winapi::shared::ntdef::OBJ_CASE_INSENSITIVE);
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```

    The default behaviour requests case sensitive behaviour from Windows, but due to Windows kernel behaviour unless explicit configuration outside of the scope of this crate has been done, case preserving case insensitive semantics will always apply.
    */
    fn object_attributes(&mut self, val: ULONG) -> &mut Self;

    /**
    Set the SecurityDescriptor field of the ObjectsAttributes parameter to NTCreateFile.

    This is optional, but allows for fine grained control if needed.

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors)
     */
    fn security_descriptor(&mut self, descriptor: SECURITY_DESCRIPTOR) -> &mut Self;

    /**
    Set the SecurityQualityOfService ImpersonationLevel field of the ObjectsAttributes parameter to NTCreateFile.

    This **should** be set if working with named pipes - or if users can control the paths that your process will open.

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service)

    ```no_run
    extern crate winapi;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.security_qos_impersonation(winapi::um::winnt::SecurityIdentification);
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```
     */
    fn security_qos_impersonation(&mut self, level: u32) -> &mut Self;

    /**
    Set the SecurityQualityOfService ContextTrackingMode field of the ObjectsAttributes parameter to NTCreateFile.

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service)

    ```no_run
    extern crate winapi;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.security_qos_context_tracking(winapi::um::winnt::SECURITY_DYNAMIC_TRACKING);
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```
     */
    fn security_qos_context_tracking(&mut self, mode: SECURITY_CONTEXT_TRACKING_MODE) -> &mut Self;

    /**
    Set the SecurityQualityOfService EffectiveOnly field of the ObjectsAttributes parameter to NTCreateFile.

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service)

    ```no_run
    extern crate winapi;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.security_qos_effective_only(true);
    let dir_file = options.mkdirat(&mut parent_dir, "foo");
    ```
     */
    fn security_qos_effective_only(&mut self, effective_only: bool) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    fn allocation_size(&mut self, val: i64) -> &mut Self {
        self._impl.allocation_size = val;
        self
    }

    fn file_attributes(&mut self, val: ULONG) -> &mut Self {
        self._impl.file_attributes = val;
        self
    }

    fn object_attributes(&mut self, val: ULONG) -> &mut Self {
        self._impl.object_attributes = val;
        self
    }

    fn security_descriptor(&mut self, descriptor: SECURITY_DESCRIPTOR) -> &mut Self {
        self._impl.security_descriptor = Some(descriptor);
        self
    }

    fn security_qos_impersonation(&mut self, level: u32) -> &mut Self {
        self._impl
            .with_security_qos(|mut qos| qos.ImpersonationLevel = level);
        self
    }

    fn security_qos_context_tracking(&mut self, mode: SECURITY_CONTEXT_TRACKING_MODE) -> &mut Self {
        self._impl
            .with_security_qos(|mut qos| qos.ContextTrackingMode = mode);
        self
    }

    fn security_qos_effective_only(&mut self, effective_only: bool) -> &mut Self {
        let native_value = if effective_only { 1 } else { 0 };
        self._impl
            .with_security_qos(|mut qos| qos.EffectiveOnly = native_value);
        self
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::rename, io::Result};

    use tempfile::TempDir;
    use winapi::shared::ntdef::OBJ_CASE_INSENSITIVE;

    use crate::{os::windows::OpenOptionsExt, testsupport::open_dir, OpenOptions};

    #[test]
    #[should_panic(expected = "Cannot create a file when that file already exists.")]
    fn mkdirat_case_insensitive() {
        // This tests that when case insensitivity is enabled, making a
        // colliding dir fails - but we have no way to easily/reliably turn case
        // insensitivity off for now. So its a bit unnecessary.
        || -> Result<()> {
            let tmp = TempDir::new()?;
            let parent = tmp.path().join("parent");
            let renamed_parent = tmp.path().join("renamed-parent");
            std::fs::create_dir(&parent)?;
            let mut parent_file = open_dir(&parent)?;
            rename(parent, &renamed_parent)?;
            let mut create_opt = OpenOptions::default();
            create_opt.mkdirat(&mut parent_file, "child")?;
            create_opt.object_attributes(OBJ_CASE_INSENSITIVE);
            create_opt.mkdirat(&mut parent_file, "Child")?;
            Ok(())
        }()
        .unwrap();
    }
}
