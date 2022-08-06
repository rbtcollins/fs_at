mod sugar;

use std::{
    ffi::{c_void, OsStr, OsString},
    fmt,
    fs::File,
    io::Result,
    mem::{size_of, zeroed, MaybeUninit},
    os::windows::prelude::{AsRawHandle, FromRawHandle, OsStrExt, OsStringExt},
    path::Path,
    ptr::null_mut,
    slice,
};

use ntapi::ntioapi::{
    FILE_CREATE, FILE_CREATED, FILE_DIRECTORY_FILE, FILE_DOES_NOT_EXIST, FILE_EXISTS, FILE_OPEN,
    FILE_OPENED, FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_OVERWRITTEN, FILE_SUPERSEDED,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use winapi::{
    ctypes,
    shared::{
        minwindef::{LPVOID, ULONG},
        ntdef::{HANDLE, NULL, OBJECT_ATTRIBUTES, OBJ_CASE_INSENSITIVE, PLARGE_INTEGER, PVOID},
        winerror::{ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES},
    },
    um::{
        fileapi::FILE_ID_BOTH_DIR_INFO,
        minwinbase::{FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo},
        winbase::GetFileInformationByHandleEx,
        winnt::{
            DELETE, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_LIST_DIRECTORY,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_DATA,
            GENERIC_READ, GENERIC_WRITE, PSECURITY_QUALITY_OF_SERVICE,
            SECURITY_CONTEXT_TRACKING_MODE, SECURITY_DESCRIPTOR, SECURITY_QUALITY_OF_SERVICE,
            SYNCHRONIZE,
        },
    },
};

use sugar::{NTStatusError, OSUnicodeString};

use crate::{OpenOptions, OpenOptionsWriteMode};

pub mod exports {
    pub use super::OpenOptionsExt;
    #[doc(no_inline)]
    pub use winapi::um::winnt::SECURITY_CONTEXT_TRACKING_MODE;
    #[doc(no_inline)]
    pub use winapi::um::winnt::SECURITY_DESCRIPTOR;
}

#[derive(Default)]
pub(crate) struct OpenOptionsImpl {
    create: bool,
    create_new: bool,
    truncate: bool,
    read: bool,
    write: OpenOptionsWriteMode,
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

struct DesiredAccess(u32);
struct FileDisposition(u32);
struct CreateOptions(u32);

impl OpenOptionsImpl {
    pub fn read(&mut self, read: bool) {
        self.read = read;
    }

    pub fn write(&mut self, write: OpenOptionsWriteMode) {
        self.write = write;
    }

    pub fn truncate(&mut self, truncate: bool) {
        self.truncate = truncate;
    }

    pub fn create(&mut self, create: bool) {
        self.create = create;
    }

    pub fn create_new(&mut self, create_new: bool) {
        self.create_new = create_new;
    }

    fn do_create_file(
        &self,
        f: &mut File,
        path: &Path,
        desired_access: DesiredAccess,
        create_disposition: FileDisposition,
        create_options: CreateOptions,
    ) -> Result<File> {
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

        let create_disposition = create_disposition.0;
        let create_options = create_options.0;
        let desired_access = desired_access.0;
        // TODO: support EA attributes if someone asks for it.
        let ea_buffer = null_mut();
        let ea_length = 0;
        // This should be exposed (e.g. to permit secure temp dirs, secure untarring etc).
        let share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        unsafe {
            let ntstatus = ntapi::ntioapi::NtCreateFile(
                handle.as_mut_ptr(),
                desired_access,
                &mut object_attributes,
                status_block.as_mut_ptr(),
                allocation_size_ptr,
                file_attributes,
                share_access,
                create_disposition,
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
        // shouldn't ever fail, but JIC.
        let information = ULONG::try_from(status_block.Information)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        match information {
            FILE_CREATED | FILE_OPENED | FILE_OVERWRITTEN => {
                // success, we have an FD
                Ok(unsafe { File::from_raw_handle(handle.assume_init() as *mut c_void) })
            }

            FILE_SUPERSEDED | FILE_EXISTS | FILE_DOES_NOT_EXIST => {
                unimplemented!("expected FILE_CREATED|FILE_OPENED|FILE_OVERWRITTEN|FILE_SUPERSEDED|FILE_EXISTS|FILE_DOES_NOT_EXIST, got {}", status_block.Information);
            }

            _ => {
                unimplemented!("expected FILE_CREATED|FILE_OPENED|FILE_OVERWRITTEN|FILE_SUPERSEDED|FILE_EXISTS|FILE_DOES_NOT_EXIST, got {}", status_block.Information);
            }
        }
    }

    pub fn mkdir_at(&self, f: &mut File, path: &Path) -> Result<File> {
        // get_access_mode must not be used for opening a directory
        // ... see docs or we must have file use the Ext trait always.
        let desired_access = DesiredAccess(DELETE | FILE_LIST_DIRECTORY | FILE_TRAVERSE);
        let mut create_disposition = self.get_file_disposition(true)?;
        if create_disposition.0 & (FILE_CREATE | FILE_OPEN_IF) == 0 {
            // per docs: create/open/openif required to open a dir, and this
            // function - mkdir - only creates. Permit users to opt into
            // create-or-open by calling .create(true) themselves.
            create_disposition.0 |= FILE_CREATE;
        }
        let create_options = CreateOptions(FILE_DIRECTORY_FILE);
        self.do_create_file(f, path, desired_access, create_disposition, create_options)
    }

    pub fn open_at(&self, f: &mut File, path: &Path) -> Result<File> {
        let desired_access = self.get_access_mode()?;
        let create_disposition = self.get_file_disposition(false)?;
        // create options needs to be controlled through OpenOptions too.
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode. We should permit users to
        // expect particular types, but until we make that explicit, we need to
        // open any kind of file when requested # FILE_NON_DIRECTORY_FILE |
        let create_options = CreateOptions(FILE_SYNCHRONOUS_IO_NONALERT);

        self.do_create_file(f, path, desired_access, create_disposition, create_options)
    }

    fn get_file_disposition(&self, call_defaults_create: bool) -> Result<FileDisposition> {
        if self.create_new {
            Ok(FileDisposition(FILE_CREATE))
        } else if self.truncate {
            Ok(FileDisposition(FILE_OVERWRITE_IF))
        } else if self.create {
            Ok(FileDisposition(FILE_OPEN_IF))
        } else if call_defaults_create {
            // mkdir should still work without create / truncate called -
            // its poor ergonomics otherwise.
            Ok(FileDisposition(FILE_CREATE))
        } else {
            // just open the existing file.
            Ok(FileDisposition(FILE_OPEN))
            // Err(std::io::Error::from_raw_os_error(
            //     ERROR_INVALID_PARAMETER as i32,
            // ))
        }
    }

    fn get_access_mode(&self) -> Result<DesiredAccess> {
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode.
        let mut desired_access = SYNCHRONIZE;
        if self.read {
            desired_access |= GENERIC_READ;
        }

        // rust has match (self.read, self.write, self.append, self.access_mode) {
        desired_access |= match (self.write, None) {
            (.., Some(mode)) => mode,
            (OpenOptionsWriteMode::Write, None) => GENERIC_WRITE,
            (OpenOptionsWriteMode::Append, None) => FILE_GENERIC_WRITE & !FILE_WRITE_DATA,
            _ => 0,
        };

        if desired_access == SYNCHRONIZE {
            // neither read nor write modes selected
            return Err(std::io::Error::from_raw_os_error(
                ERROR_INVALID_PARAMETER as i32,
            ));
        }
        Ok(DesiredAccess(desired_access))
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
    options.read(true);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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
    options.read(true);
    options.file_attributes(winapi::um::winnt::FILE_ATTRIBUTE_TEMPORARY);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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
    options.read(true);
    options.object_attributes(winapi::shared::ntdef::OBJ_CASE_INSENSITIVE);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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
    options.read(true);
    options.security_qos_impersonation(winapi::um::winnt::SecurityIdentification);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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
    options.read(true);
    options.security_qos_context_tracking(winapi::um::winnt::SECURITY_DYNAMIC_TRACKING);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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
    options.read(true);
    options.security_qos_effective_only(true);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
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

#[derive(Debug)]
pub(crate) struct ReadDirImpl<'a> {
    /// FILE_ID_BOTH_DIR_INFO is a variable-length struct, otherwise this would
    /// be a vec of that. None indicates end of iterator from the OS.
    buffer: Option<Vec<u8>>,
    d: &'a mut File,
    // byte offset in buffer to next entry to yield
    offset: usize,
}

impl<'a> ReadDirImpl<'a> {
    pub fn new(d: &mut File) -> Result<ReadDirImpl> {
        let mut result = ReadDirImpl {
            // Start with a page, can always grow it statically or dynamically if
            // needed.
            buffer: Some(vec![0_u8; 4096]),
            d,
            offset: 0,
        };
        // TODO: can this ever fail as FindFirstFile does?
        result.fill_buffer(FileIdBothDirectoryRestartInfo)?;
        Ok(result)
    }

    fn fill_buffer(&mut self, class: ULONG) -> Result<bool> {
        let buffer = self.buffer.as_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "Attempt to fill buffer after end of dir",
            )
        })?;
        // Implement
        // https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea
        // without ever doing path resolution... the docs for
        // GetFileInformationByHandleEx do not mention how to detect end of dir,
        // but FindNextFile does:
        //
        // ```
        //If the function fails because no more matching files can be found,
        //the GetLastError function returns ERROR_NO_MORE_FILES.
        // ```
        let result = cvt::cvt(unsafe {
            GetFileInformationByHandleEx(
                self.d.as_raw_handle() as HANDLE,
                class,
                buffer.as_mut_ptr() as LPVOID,
                buffer.len() as u32,
            )
        });
        match result {
            Ok(_) => Ok(false),
            Err(e) if e.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) => Ok(true),
            Err(e) => Err(e),
        }
    }
}

impl Iterator for ReadDirImpl<'_> {
    type Item = Result<DirEntryImpl>;

    fn next(&mut self) -> Option<Self::Item> {
        // if the buffer is empty, fill it; if the buffer is None, exit early.
        if self.offset >= self.buffer.as_ref()?.len() {
            match self.fill_buffer(FileIdBothDirectoryInfo) {
                Ok(false) => {
                    self.offset = 0;
                }
                Ok(true) => {
                    self.buffer = None;
                    return None;
                }
                Err(e) => return Some(Err(e)),
            }
        }
        // offset is now valid. Dereference into a struct.
        let struct_mem = &self.buffer.as_ref()?[self.offset..];
        let info = unsafe { &*struct_mem.as_ptr().cast::<FILE_ID_BOTH_DIR_INFO>() };
        self.offset = if info.NextEntryOffset == 0 {
            self.buffer.as_ref()?.len()
        } else {
            info.NextEntryOffset as usize + self.offset
        };

        let name = OsString::from_wide(unsafe {
            slice::from_raw_parts(
                info.FileName.as_ptr(),
                info.FileNameLength as usize / size_of::<u16>(),
            )
        });
        Some(Ok(DirEntryImpl { name }))
        //
        //
        // Read Attributes, Delete, Synchronize
        // Disposition:	Open
        // Options:	Synchronous IO Non-Alert, Open Reparse Point
        //
    }
}

#[derive(Debug)]
pub(crate) struct DirEntryImpl {
    name: OsString,
}

impl DirEntryImpl {
    pub fn name(&self) -> &OsStr {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::rename, io::Result};

    use tempfile::TempDir;
    use winapi::shared::ntdef::OBJ_CASE_INSENSITIVE;

    use crate::{os::windows::OpenOptionsExt, testsupport::open_dir, OpenOptions};

    #[test]
    // #[should_panic(expected = "Cannot create a file when that file already exists.")]
    fn mkdir_at_case_insensitive() {
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
            create_opt.create(true);
            create_opt.mkdir_at(&mut parent_file, "child")?;
            create_opt.object_attributes(OBJ_CASE_INSENSITIVE);
            // Incorrectly passes because we're just using .create() now
            create_opt.mkdir_at(&mut parent_file, "Child")?;
            Ok(())
        }()
        .unwrap();
    }
}
