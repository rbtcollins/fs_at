mod sugar;

use std::{
    ffi::{c_void, OsStr, OsString},
    fmt,
    fs::File,
    io::{self, ErrorKind, Result},
    mem::{self, size_of, zeroed, MaybeUninit},
    os::windows::prelude::{AsRawHandle, FromRawHandle, MetadataExt, OsStrExt, OsStringExt},
    path::Path,
    ptr::{self, null_mut},
    slice,
};

use aligned::{Aligned, A8};

use sugar::{NTStatusError, OSUnicodeString};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
            FILE_OPEN_REPARSE_POINT, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT,
            REPARSE_DATA_BUFFER, REPARSE_DATA_BUFFER_0_2, SYMLINK_FLAG_RELATIVE,
        },
    },
    Win32::{
        Foundation::{
            ERROR_CANT_RESOLVE_FILENAME, ERROR_DIRECTORY, ERROR_INVALID_FUNCTION,
            ERROR_INVALID_PARAMETER, ERROR_NOT_A_REPARSE_POINT, ERROR_NOT_SUPPORTED,
            ERROR_NO_MORE_FILES, HANDLE, TRUE,
        },
        Security::{SECURITY_DESCRIPTOR, SECURITY_QUALITY_OF_SERVICE},
        Storage::FileSystem::{
            FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx, FileIdBothDirectoryInfo,
            FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx,
            SetFileInformationByHandle, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
            FILE_BASIC_INFO, FILE_DISPOSITION_FLAG_DELETE,
            FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
            FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_ID_BOTH_DIR_INFO, FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY,
            FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
            MAXIMUM_REPARSE_DATA_BUFFER_SIZE, SYNCHRONIZE,
        },
        System::{
            Ioctl::{FSCTL_GET_REPARSE_POINT, FSCTL_SET_REPARSE_POINT},
            Kernel::OBJ_CASE_INSENSITIVE,
            SystemServices::{IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK},
            WindowsProgramming::{
                FILE_CREATED, FILE_DOES_NOT_EXIST, FILE_EXISTS, FILE_OPENED, FILE_OVERWRITTEN,
                FILE_SUPERSEDED,
            },
            IO::DeviceIoControl,
        },
    },
};

use crate::{LinkEntryType, OpenOptions, OpenOptionsWriteMode};

use exports::SECURITY_CONTEXT_TRACKING_MODE;

pub mod exports {
    pub use super::{FileExt, OpenOptionsExt};

    pub use windows_sys::Wdk::System::SystemServices::SECURITY_CONTEXT_TRACKING_MODE;

    #[doc(no_inline)]
    pub use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
}

// These definitions should come from windows_sys, but don't exist right now.
pub(crate) mod windows_sys_gap_defs {
    use windows_sys::Win32::{
        Foundation::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, UNICODE_STRING},
        System::{
            SystemServices::UNICODE_STRING_MAX_CHARS, WindowsProgramming::RtlInitUnicodeString,
        },
    };

    // since windows-sys 0.52 this is available : use
    // windows_sys::Wdk::Storage::FileSystem::RtlInitUnicodeStringEx; but
    // haven't had time to switch to it yet. RtlInitUnicodeStringEx isn't
    // available in windows_sys at this time, and won't be (see
    // https://github.com/microsoft/win32metadata/issues/1461) so we're going to
    // roll our own. We'll rely on RtlInitUnicodeString to do this, and just
    // make sure we don't pass it information that would induce an error.
    pub unsafe fn init_unicode_string(
        destination_string: *mut UNICODE_STRING,
        source_string: &mut [u16],
    ) -> NTSTATUS {
        if source_string.len() > UNICODE_STRING_MAX_CHARS as usize
            || !source_string.iter().rev().any(|i| *i == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        RtlInitUnicodeString(destination_string, source_string.as_mut_ptr());
        STATUS_SUCCESS
    }
}

#[derive(Clone, Default)]
pub(crate) struct OpenOptionsImpl {
    create: bool,
    create_new: bool,
    truncate: bool,
    read: bool,
    write: OpenOptionsWriteMode,
    follow: Option<bool>,
    // LARGE_INTEGER defined as signed 64-bit
    // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-large_integer-r1
    allocation_size: i64,
    desired_access: Option<DesiredAccess>,
    create_options: Option<CreateOptions>,
    //https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#dwFlagsAndAttributes
    file_attributes: u32,
    object_attributes: u32,
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

#[derive(Clone, Copy, Default)]
struct DesiredAccess(u32);
struct FileOpenDisposition(u32);
#[derive(Clone, Default)]
struct CreateOptions(u32);

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum OpenSymLink<MLE>
where
    MLE: Fn() -> io::Error,
{
    OpenLinkFile,
    RaiseError(MLE),
}

fn open_link_file() -> OpenSymLink<impl Fn() -> io::Error> {
    // maybe a trait would be easier.
    #[allow(unused_assignments)]
    let mut right_type_wrong_value = OpenSymLink::RaiseError(make_already_exists_error);
    right_type_wrong_value = OpenSymLink::OpenLinkFile;
    right_type_wrong_value
}

fn make_already_exists_error() -> io::Error {
    io::Error::from(ErrorKind::AlreadyExists)
}

pub(crate) fn make_loop_error() -> io::Error {
    io::Error::from_raw_os_error(ERROR_CANT_RESOLVE_FILENAME as i32)
}

// Cache the workaround for https://twitter.com/rbtcollins/status/1617211985384407044
#[cfg(feature = "workaround-procmon")]
mod procmon {
    use std::{
        io::Error,
        sync::atomic::{AtomicBool, Ordering},
    };

    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;

    static WORKAROUND_CHECKED: once_cell::sync::Lazy<AtomicBool> =
        once_cell::sync::Lazy::new(|| false.into());
    static WORKAROUND_VALUE: once_cell::sync::Lazy<AtomicBool> =
        once_cell::sync::Lazy::new(|| false.into());
    const ENV_VAR_NAME: &str = "FS_AT_WORKAROUND_PROCMON";

    pub(crate) fn workaround<T>(e: Error, ok: T) -> Result<T, Error> {
        if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
            // https://twitter.com/rbtcollins/status/1617211985384407044
            let workaround = if !AtomicBool::load(&WORKAROUND_CHECKED, Ordering::Relaxed) {
                use std::env::var;
                let workaround = var(ENV_VAR_NAME).is_ok();
                AtomicBool::store(&WORKAROUND_VALUE, workaround, Ordering::Relaxed);
                AtomicBool::store(&WORKAROUND_CHECKED, true, Ordering::Relaxed);
                workaround
            } else {
                AtomicBool::load(&WORKAROUND_VALUE, Ordering::Relaxed)
            };
            if workaround {
                // run under procmon this library receives ACCESS_DENIED on some
                // DeviceIOControl calls :- but they seem to still take effect
                // for write calls, and succeed for reading links when an actual
                // link is present. e.g. ERROR_NOT_A_REPARSE_POINT. this
                // could mask other errors too but this code path is opt-in.
                return Ok(ok);
            }
        }
        Err(e)
    }
}

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

    pub fn follow(&mut self, follow: bool) {
        self.follow = Some(follow);
    }

    // NtCreateFile has too many arguments, and making a builder in our build
    // interface itself seems overkill.
    #[allow(clippy::too_many_arguments)]
    fn do_create_file<MLE>(
        &self,
        f: &File,
        path: &Path,
        desired_access: DesiredAccess,
        create_disposition: FileOpenDisposition,
        create_options: CreateOptions,
        open_symlink: OpenSymLink<MLE>,
    ) -> Result<File>
    where
        MLE: Fn() -> io::Error,
    {
        let mut handle: MaybeUninit<HANDLE> = MaybeUninit::uninit();
        let mut object_attributes: OBJECT_ATTRIBUTES = unsafe { zeroed() };
        object_attributes.Length = size_of::<OBJECT_ATTRIBUTES>() as u32;
        object_attributes.RootDirectory = f.as_raw_handle() as isize;
        let u16_path = path.as_os_str().encode_wide().collect::<Vec<u16>>();
        let mut rtl_string = OSUnicodeString::try_from(u16_path)?;
        object_attributes.ObjectName = &mut rtl_string.inner;
        // Only OBJ_CASE_INSENSITIVE is defined currently. What of
        // https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes
        // should be permitted through? Everything?
        // https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
        // only specifies OBJ_CASE_INSENSITIVE
        object_attributes.Attributes = self.object_attributes & OBJ_CASE_INSENSITIVE as u32;
        // Should allow setting this; NULL is sane but not fully flexible.
        // https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptors
        let mut security_descriptor = self.security_descriptor;
        object_attributes.SecurityDescriptor = match security_descriptor {
            Some(ref mut val) => val as *mut SECURITY_DESCRIPTOR as *mut c_void,
            None => ptr::null_mut(),
        };
        // https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service
        let mut security_qos = self.security_qos;
        object_attributes.SecurityQualityOfService = match security_qos {
            Some(ref mut val) => val as *mut SECURITY_QUALITY_OF_SERVICE as *mut c_void,
            None => ptr::null_mut(),
        };
        let mut status_block = MaybeUninit::uninit();

        // Perhaps not worth exposing?
        let mut allocation_size = self.allocation_size;
        let allocation_size_ptr = if allocation_size > 0 {
            &mut allocation_size as *mut i64
        } else {
            ptr::null_mut::<i64>()
        };

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
            let ntstatus = NtCreateFile(
                handle.as_mut_ptr(),
                desired_access,
                &object_attributes,
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
        let information = u32::try_from(status_block.Information)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        match information {
            FILE_CREATED | FILE_OPENED | FILE_OVERWRITTEN => {
                // could be success : we have an FD
                // Check if we're opening
                let handle: HANDLE = unsafe { handle.assume_init() };

                if matches!(open_symlink, OpenSymLink::RaiseError(_)) && Self::is_symlink(handle)? {
                    // we found a symlink (due to setting
                    // FILE_OPEN_REPARSE_POINT), but we're not permitted to open
                    // the link itself (e.g. follow(false) was set). Synthesis an OS error.
                    match open_symlink {
                        OpenSymLink::RaiseError(make_link_error) => Err(make_link_error()),
                        _ => unreachable!(),
                    }
                } else {
                    Ok(unsafe { File::from_raw_handle(handle as *mut c_void) })
                }
            }

            FILE_SUPERSEDED | FILE_EXISTS | FILE_DOES_NOT_EXIST => {
                // Not covered by test coverage yet.
                unimplemented!("expected FILE_CREATED|FILE_OPENED|FILE_OVERWRITTEN|FILE_SUPERSEDED|FILE_EXISTS|FILE_DOES_NOT_EXIST, got {}", status_block.Information);
            }

            _ => {
                // Not covered by test coverage yet.
                unimplemented!("expected FILE_CREATED|FILE_OPENED|FILE_OVERWRITTEN|FILE_SUPERSEDED|FILE_EXISTS|FILE_DOES_NOT_EXIST, got {}", status_block.Information);
            }
        }
    }

    pub fn mkdir_at(&self, f: &File, path: &Path) -> Result<File> {
        // get_access_mode must not be used for opening a directory
        // ... see docs or we must have file use the Ext trait always.
        let desired_access =
            DesiredAccess(DELETE | FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_WRITE_ATTRIBUTES);
        let mut create_disposition = self.get_file_disposition(true)?;
        if create_disposition.0 & (FILE_CREATE | FILE_OPEN_IF) == 0 {
            // per docs: create/open/openif required to open a dir, and this
            // function - mkdir - only creates. Permit users to opt into
            // create-or-open by calling .create(true) themselves.
            create_disposition.0 |= FILE_CREATE;
        }
        // we must open a directory.
        // For consistency with unix.rs, never follow a symlink at the location of
        // the mkdir target.
        let create_options = CreateOptions(FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT);
        let open_symlink = OpenSymLink::RaiseError(make_already_exists_error);
        self.do_create_file(
            f,
            path,
            desired_access,
            create_disposition,
            create_options,
            open_symlink,
        )
        .map_err(|e| {
            if e.raw_os_error() == Some(ERROR_DIRECTORY as i32) {
                // NotADirectory happens when opening with FILE_OPEN_IF a Symlink
                // with link-type File and FILE_OPEN_REPARSE_POINT - nofollow. But
                // AlreadyExists is a better error consistent with Unix : the
                // NotADirectory error is leakage from the implementation of
                // symlinks on Windows.
                io::Error::new(ErrorKind::AlreadyExists, e)
            } else {
                e
            }
        })
    }

    pub fn open_at(&self, f: &File, path: &Path) -> Result<File> {
        let desired_access = self.get_open_at_access_mode()?;
        let create_disposition = self.get_file_disposition(false)?;
        // TODO: create options needs to be controlled through OpenOptions too.
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode. We should permit users to
        // expect particular types, but until we make that explicit, we need to
        // open any kind of file when requested
        let create_options = CreateOptions(
            FILE_SYNCHRONOUS_IO_NONALERT
                | if let Some(CreateOptions(custom_options)) = self.create_options {
                    custom_options
                } else if matches!(self.follow, Some(false)) || self.create_new {
                    // Follow is disabled, or create_new, which for unix is ==
                    // O_EXCL | O_CREAT and defined as rejecting a symlink at
                    // the target path.
                    FILE_OPEN_REPARSE_POINT
                } else {
                    0
                },
        );
        #[cfg(feature = "log")]
        log::trace!(
            "open_at: {}, access: {:#0x?} create_options: {:#0x?}",
            path.display(),
            desired_access.0,
            create_options.0
        );
        let open_symlink = if self.follow.unwrap_or(true) {
            OpenSymLink::OpenLinkFile
        } else {
            // Be compatible with Unix code - O_NOFOLLOW without O_PATH generates ELOOP.
            OpenSymLink::RaiseError(make_loop_error)
        };

        self.do_create_file(
            f,
            path,
            desired_access,
            create_disposition,
            create_options,
            open_symlink,
        )
        .map_err(|e| {
            if e.raw_os_error() == Some(ERROR_DIRECTORY as i32) {
                // NotADirectory happens when opening with FILE_OVERWRITE_IF
                // (e.g. truncate) a Symlink with link-type Dir and follow enabled. But
                // AlreadyExists is a better error consistent with Unix : the
                // NotADirectory error is leakage from the implementation of
                // symlinks on Windows. Here we need to retry
                io::Error::new(ErrorKind::AlreadyExists, e)
            } else {
                e
            }
        })
    }

    pub fn open_dir_at(&self, f: &File, path: &Path) -> Result<File> {
        let desired_access = self.get_open_dir_at_access_mode()?;
        let create_disposition = self.get_file_disposition(false)?;
        // TODO: create options needs to be controlled through OpenOptions too.
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode. We should permit users to
        // expect particular types, but until we make that explicit, we need to
        // open any kind of file when requested # FILE_NON_DIRECTORY_FILE |
        let create_options = CreateOptions(
            FILE_SYNCHRONOUS_IO_NONALERT
                | if let Some(CreateOptions(custom_options)) = self.create_options {
                    custom_options
                } else if matches!(self.follow, Some(true)) {
                    0
                } else {
                    FILE_OPEN_REPARSE_POINT
                },
        );
        #[cfg(feature = "log")]
        log::trace!(
            "open_dir_at: {}, access: {:#0x?} create_options: {:#0x?}",
            path.display(),
            desired_access.0,
            create_options.0
        );
        let open_symlink = {
            // Be compatible with Unix code - O_NOFOLLOW without O_PATH generates ELOOP.
            OpenSymLink::RaiseError(make_loop_error)
        };

        self.do_create_file(
            f,
            path,
            desired_access,
            create_disposition,
            create_options,
            open_symlink,
        )
    }

    pub fn open_path_at(&self, f: &File, path: &Path) -> Result<File> {
        let desired_access = DesiredAccess(SYNCHRONIZE | self.desired_access.unwrap_or_default().0);

        let create_disposition = self.get_file_disposition(false)?;
        // TODO: create options needs to be controlled through OpenOptions too.
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode.
        let create_options = CreateOptions(
            FILE_SYNCHRONOUS_IO_NONALERT
                | if let Some(CreateOptions(custom_options)) = self.create_options {
                    custom_options
                } else {
                    FILE_OPEN_REPARSE_POINT
                },
        );
        #[cfg(feature = "log")]
        log::trace!(
            "open_path_at: {}, access: {:#0x?} create_options: {:#0x?}",
            path.display(),
            desired_access.0,
            create_options.0
        );

        self.do_create_file(
            f,
            path,
            desired_access,
            create_disposition,
            create_options,
            open_link_file(),
        )
    }

    pub fn symlink_at(
        &self,
        d: &File,
        linkname: &Path,
        link_entry_type: LinkEntryType,
        target: &Path,
    ) -> Result<()> {
        // 1 - create a plain old file/dir  atomically.
        let link_file = match link_entry_type {
            LinkEntryType::Dir => OpenOptions::default()
                .create_new(true)
                .write(OpenOptionsWriteMode::Write)
                .mkdir_at(d, linkname),
            LinkEntryType::File => OpenOptions::default()
                .create_new(true)
                .write(OpenOptionsWriteMode::Write)
                .open_at(d, linkname),
            LinkEntryType::Other => unimplemented!("can't create reparse points [yet["),
        }?;

        // 2 - convert it to a symlink

        // Symlinks can be absolute or relative. The discriminator rules are not
        // clear for this, but it seems like we want the following for a
        // absolute path
        // - no dependence on implicit state like 'current working directory on
        // drive X'.

        //is_absolute is perhaps good enough. Ultimately callers of this need to
        // provide reasonable working data.
        let os_target = target.as_os_str().to_owned();
        let mut final_target = OsString::new();
        let absolute = target.is_absolute();
        // target might not start with \??\.
        if absolute
            && os_target.encode_wide().take(4).collect::<Vec<_>>()
                != [0x005C, 0x003F, 0x003F, 0x005C]
        {
            // prefix target with \??\
            final_target.push(r"\??\");
        }
        final_target.push(&os_target);

        // Symlink needs two strings: print (e.g. d:\foo) and substitute (e.g.
        // \??\d:\foo) for print string we take the supplied path. For
        // substitute, final_target.

        // TODO: make this more like zero-copy.
        let print_path = os_target.encode_wide().collect::<Vec<_>>();
        let subst_path = final_target.encode_wide().collect::<Vec<_>>();
        let path_length = print_path.len() + subst_path.len();

        // Size of the union, -1 for the 1 byte in-struct array, + path lengths.
        let reparse_data_length = mem::size_of::<REPARSE_DATA_BUFFER_0_2>() - 1 + path_length * 2;
        // u32 + USHORT*2
        let reparse_length = reparse_data_length + 8;
        let mut reparse_data_vec: Vec<u8> = vec![0; reparse_length];

        // todo alignment safety: calculate the size in multiples of
        // REPARSE_DATA_BUFFER.len and then cast down.
        let (head, aligned, _tail) =
            unsafe { reparse_data_vec.align_to_mut::<REPARSE_DATA_BUFFER>() };
        if !head.is_empty() {
            // TODO: use body instead later on?
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "non-aligned struct allocation",
            ));
        }
        let reparse_data = &mut aligned[0];

        reparse_data.ReparseTag = IO_REPARSE_TAG_SYMLINK;

        let to_u16 = |l| {
            TryFrom::try_from(l)
                .map_err(|_e| io::Error::new(io::ErrorKind::Other, "path length too long"))
        };

        reparse_data.ReparseDataLength = to_u16(reparse_data_length)?;
        if !absolute {
            reparse_data.Anonymous.SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
        }
        reparse_data
            .Anonymous
            .SymbolicLinkReparseBuffer
            .SubstituteNameLength = to_u16(subst_path.len() * 2)?;
        reparse_data
            .Anonymous
            .SymbolicLinkReparseBuffer
            .SubstituteNameOffset = 0;
        reparse_data
            .Anonymous
            .SymbolicLinkReparseBuffer
            .PrintNameLength = to_u16(print_path.len() * 2)?;
        reparse_data
            .Anonymous
            .SymbolicLinkReparseBuffer
            .PrintNameOffset = to_u16(subst_path.len() * 2)?;
        let path_addr = unsafe {
            reparse_data
                .Anonymous
                .SymbolicLinkReparseBuffer
                .PathBuffer
                .as_ptr() as *const u8
        };
        let path_offset = unsafe { path_addr.offset_from(aligned.as_ptr() as *const u8) } as usize;
        // copy the strings in:

        let print_path_u8 = unsafe {
            std::slice::from_raw_parts(print_path.as_ptr().cast::<u8>(), print_path.len() * 2)
        };
        let subst_path_u8 = unsafe {
            std::slice::from_raw_parts(subst_path.as_ptr().cast::<u8>(), subst_path.len() * 2)
        };

        reparse_data_vec[path_offset..path_offset + subst_path.len() * 2]
            .copy_from_slice(subst_path_u8);
        reparse_data_vec[path_offset + subst_path.len() * 2
            ..path_offset + subst_path.len() * 2 + print_path.len() * 2]
            .copy_from_slice(print_path_u8);

        let bool_result = unsafe {
            DeviceIoControl(
                link_file.as_raw_handle() as HANDLE,
                FSCTL_SET_REPARSE_POINT,
                reparse_data_vec.as_ptr() as *const c_void,
                reparse_data_vec.len() as u32,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        let r = cvt::cvt(bool_result).map(|_v| ());
        #[cfg(feature = "workaround-procmon")]
        return r.or_else(|e| procmon::workaround(e, ()));
        #[cfg(not(feature = "workaround-procmon"))]
        return r;
    }

    pub fn rmdir_at(&self, f: &File, p: &Path) -> Result<()> {
        // we must open a directory
        self.mark_for_deletion(f, p, CreateOptions(FILE_DIRECTORY_FILE))
    }

    pub fn unlink_at(&self, f: &File, p: &Path) -> Result<()> {
        self.mark_for_deletion(f, p, CreateOptions(0))
    }

    fn mark_for_deletion(&self, f: &File, p: &Path, create_options: CreateOptions) -> Result<()> {
        let desired_access = DesiredAccess(DELETE);
        let create_disposition = FileOpenDisposition(FILE_OPEN);
        // Only delete what was named :- do not do link processing
        let create_options = CreateOptions(create_options.0 | FILE_OPEN_REPARSE_POINT);
        let open_symlink = open_link_file();
        let to_remove = self.do_create_file(
            f,
            p,
            desired_access,
            create_disposition,
            create_options,
            open_symlink,
        )?;

        to_remove.delete_by_handle().map_err(|(_, e)| e)
    }

    fn is_symlink(handle: HANDLE) -> Result<bool> {
        let mut reparse_buffer: Aligned<
            A8,
            [MaybeUninit<u8>; MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize],
        > = Aligned([MaybeUninit::<u8>::uninit(); MAXIMUM_REPARSE_DATA_BUFFER_SIZE as usize]);
        let mut out_size = 0;
        let bool_result = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_GET_REPARSE_POINT,
                ptr::null(),
                0,
                // output buffer
                reparse_buffer.as_mut_ptr().cast(),
                // size of output buffer
                MAXIMUM_REPARSE_DATA_BUFFER_SIZE,
                // number of bytes returned
                &mut out_size,
                // OVERLAPPED structure
                ptr::null_mut(),
            )
        };
        let result = cvt::cvt(bool_result);
        if let Err(e) = result {
            if e.raw_os_error() != Some(ERROR_NOT_A_REPARSE_POINT as i32) {
                // This is ugly. But procmon seems to interfere.
                #[cfg(feature = "workaround-procmon")]
                return procmon::workaround(e, false);
                #[cfg(not(feature = "workaround-procmon"))]
                return Err(e);
            }
            return Ok(false);
        };
        if out_size < size_of::<u32>() as u32 {
            // Success but not enough data to read the tag
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Insufficient data from DeviceIOControl",
            ));
        }
        let reparse_buffer = reparse_buffer.as_ptr().cast::<REPARSE_DATA_BUFFER>();
        Ok(unsafe {
            matches!(
                (*reparse_buffer).ReparseTag,
                IO_REPARSE_TAG_SYMLINK | IO_REPARSE_TAG_MOUNT_POINT
            )
        })
    }

    fn get_file_disposition(&self, call_defaults_create: bool) -> Result<FileOpenDisposition> {
        if self.create_new {
            Ok(FileOpenDisposition(FILE_CREATE))
        } else if self.truncate {
            Ok(FileOpenDisposition(FILE_OVERWRITE_IF))
        } else if self.create {
            Ok(FileOpenDisposition(FILE_OPEN_IF))
        } else if call_defaults_create {
            // mkdir should still work without create / truncate called -
            // its poor ergonomics otherwise.
            Ok(FileOpenDisposition(FILE_CREATE))
        } else {
            // just open the existing file.
            Ok(FileOpenDisposition(FILE_OPEN))
        }
    }

    fn get_open_at_access_mode(&self) -> Result<DesiredAccess> {
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode.
        let mut desired_access = SYNCHRONIZE;
        if let Some(DesiredAccess(custom_access)) = self.desired_access {
            return Ok(DesiredAccess(custom_access | desired_access));
        }

        if self.read {
            desired_access |= FILE_GENERIC_READ;
        }

        // rust has match (self.read, self.write, self.append, self.access_mode) {
        desired_access |= match (self.write, None) {
            (.., Some(mode)) => mode,
            (OpenOptionsWriteMode::Write, None) => FILE_GENERIC_WRITE,
            (OpenOptionsWriteMode::Append, None) => FILE_GENERIC_WRITE & !FILE_WRITE_DATA,
            _ => 0,
        };

        if desired_access == SYNCHRONIZE {
            // neither read nor write modes selected
            return Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32));
        }
        Ok(DesiredAccess(desired_access))
    }

    fn get_open_dir_at_access_mode(&self) -> Result<DesiredAccess> {
        // FILE_SYNCHRONOUS_IO_NONALERT is set by CreateFile with the options
        // Rust itself uses - this lets the OS position tracker work. It also
        // requires SYNCHRONIZE on the access mode.
        let mut desired_access = SYNCHRONIZE;
        if let Some(DesiredAccess(custom_access)) = self.desired_access {
            return Ok(DesiredAccess(custom_access | desired_access));
        }

        if self.read {
            desired_access |= FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE;
        }

        // rust has match (self.read, self.write, self.append, self.access_mode) {
        desired_access |= match (self.write, None) {
            (.., Some(mode)) => mode,
            (OpenOptionsWriteMode::Write, None) => FILE_WRITE_ATTRIBUTES | DELETE,
            (OpenOptionsWriteMode::Append, None) => FILE_WRITE_ATTRIBUTES | DELETE,
            _ => 0,
        };

        if desired_access == SYNCHRONIZE {
            // neither read nor write modes selected
            return Err(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32));
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

/// Extends OpenOptions with Windows specific parameters.
///
/// Note that `open_at` uses `NTCreateFile`, not `CreateFile` and as such the
/// flags and attributes values differ.
pub trait OpenOptionsExt {
    /**
    Set the AllocationSize parameter to NTCreateFile.

    Only takes effect when creating a file.

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

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
    Set the DesiredAccess parameter to NTCreateFile for `open_at()`.

    Mostly overrides the parameter, giving caller control. In order to work with
    the IO model provided today, SYNCHRONIZE is always included. This is an
    implementation detail and could change in future.

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS,FILE_READ_ATTRIBUTES};

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.desired_access(FILE_READ_ATTRIBUTES);
    let child_file = options.open_at(&parent_dir, "child").unwrap();
    child_file.metadata();
    ```
    */
    fn desired_access(&mut self, desired_access: u32) -> &mut Self;

    /**
    Set the CreateOptions parameter to NTCreateFile for `open_at()`.

    Mostly overrides the parameter, giving callers detailed control. This causes
    methods such as `follow` to have no effect.

    In order to work with the IO model provided today, FILE_SYNCHRONOUS_IO_NONALERT
    is always included. This is an implementation detail and could change in future.

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS,FILE_READ_ATTRIBUTES};
    use windows_sys::Wdk::Storage::FileSystem::FILE_NO_EA_KNOWLEDGE;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.create_options(FILE_NO_EA_KNOWLEDGE);
    let child_file = options.open_at(&parent_dir, "child");
    ```
    */
    fn create_options(&mut self, create_options: u32) -> &mut Self;

    /**
    Set the FileAttributes field used with NTCreateFile.

    When this is not called, fs_at uses FILE_ATTRIBUTE_NORMAL

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea#dwFlagsAndAttributes) - see the dwFlagsAndAttributes values.

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_BACKUP_SEMANTICS};

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.read(true);
    options.file_attributes(FILE_ATTRIBUTE_TEMPORARY);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
    ```

    */
    fn file_attributes(&mut self, val: u32) -> &mut Self;

    /**
    Set the Attributes field of the ObjectAttributes parameter to NTCreateFile.

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.read(true);
    options.object_attributes(OBJ_CASE_INSENSITIVE as u32);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
    ```

    The default behaviour requests case sensitive behaviour from Windows, but due to Windows kernel behaviour unless explicit configuration outside of the scope of this crate has been done, case preserving case insensitive semantics will always apply.
    */
    fn object_attributes(&mut self, val: u32) -> &mut Self;

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
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::{Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS, Security::SecurityIdentification};

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS as u32);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.read(true);
    options.security_qos_impersonation(SecurityIdentification as u32);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
    ```
     */
    fn security_qos_impersonation(&mut self, level: u32) -> &mut Self;

    /**
    Set the SecurityQualityOfService ContextTrackingMode field of the ObjectsAttributes parameter to NTCreateFile.

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service)

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::{Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS, Security::SECURITY_DYNAMIC_TRACKING};

    use fs_at::OpenOptions;
    use fs_at::os::windows::OpenOptionsExt;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    let mut parent_dir = options.open(".").unwrap();

    let mut options = OpenOptions::default();
    options.read(true);
    options.security_qos_context_tracking(SECURITY_DYNAMIC_TRACKING);
    let dir_file = options.mkdir_at(&mut parent_dir, "foo");
    ```
     */
    fn security_qos_context_tracking(&mut self, mode: SECURITY_CONTEXT_TRACKING_MODE) -> &mut Self;

    /**
    Set the SecurityQualityOfService EffectiveOnly field of the ObjectsAttributes parameter to NTCreateFile.

    [Microsoft API documentation](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-security_quality_of_service)

    ```no_run
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt as StdOpenOptionsExt;

    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

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

    fn create_options(&mut self, create_options: u32) -> &mut Self {
        self._impl.create_options = Some(CreateOptions(create_options));
        self
    }

    fn desired_access(&mut self, desired_access: u32) -> &mut Self {
        self._impl.desired_access = Some(DesiredAccess(desired_access));
        self
    }

    fn file_attributes(&mut self, val: u32) -> &mut Self {
        self._impl.file_attributes = val;
        self
    }

    fn object_attributes(&mut self, val: u32) -> &mut Self {
        self._impl.object_attributes = val;
        self
    }

    fn security_descriptor(&mut self, descriptor: SECURITY_DESCRIPTOR) -> &mut Self {
        self._impl.security_descriptor = Some(descriptor);
        self
    }

    fn security_qos_impersonation(&mut self, level: u32) -> &mut Self {
        self._impl
            .with_security_qos(|qos| qos.ImpersonationLevel = level as i32);
        self
    }

    fn security_qos_context_tracking(&mut self, mode: SECURITY_CONTEXT_TRACKING_MODE) -> &mut Self {
        self._impl
            .with_security_qos(|qos| qos.ContextTrackingMode = mode);
        self
    }

    fn security_qos_effective_only(&mut self, effective_only: bool) -> &mut Self {
        let native_value = u8::from(effective_only);
        self._impl
            .with_security_qos(|qos| qos.EffectiveOnly = native_value);
        self
    }
}

/// Extends `File` with Windows capabilities.
pub trait FileExt {
    // Deletes the file by the open handle. This will attempt to use posix
    // semantics, if that fails with an appropriate error code, it will then
    // attempt win7 deletion semantics, and if that fails with access denied, it
    // will attempt to remove the readonly attribute, mark the file for
    // deletion, and finally restore the attribute (for correctness with
    // hardlinked files).
    //
    // On unhandled errors, the file is returned along with the error, to permit
    // alternative code paths by the caller.
    fn delete_by_handle(self) -> std::result::Result<(), (File, io::Error)>;
}

fn delete_with_posix(f: File) -> std::result::Result<File, (File, io::Error)> {
    // Try for modern delete semantics: POSIX_SEMANTICS and bypass the
    // readonly flag.
    let mut delete_disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    match cvt::cvt(unsafe {
        SetFileInformationByHandle(
            f.as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            &mut delete_disposition as *mut FILE_DISPOSITION_INFO_EX as *const c_void,
            mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    }) {
        Ok(_) => Ok(f),
        Err(e) => Err((f, e)),
    }
}

fn delete_with_win7(f: File) -> std::result::Result<File, (File, io::Error)> {
    let mut delete_disposition = FILE_DISPOSITION_INFO {
        DeleteFile: TRUE as u8,
    };
    match cvt::cvt(unsafe {
        SetFileInformationByHandle(
            f.as_raw_handle() as HANDLE,
            FileDispositionInfo,
            &mut delete_disposition as *mut FILE_DISPOSITION_INFO as *const c_void,
            mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }) {
        Ok(_) => Ok(f),
        Err(e) => Err((f, e)),
    }
}

fn delete_with_win7_readonly(
    f: File,
    e: io::Error,
) -> std::result::Result<File, (File, io::Error)> {
    // 1) reset readonly attribute
    let m = match f.metadata() {
        Ok(m) => m,
        Err(e) => return Err((f, e)),
    };
    if !m.permissions().readonly() {
        return Err((f, e));
    }
    let mut info = FILE_BASIC_INFO {
        FileAttributes: m.file_attributes() & !FILE_ATTRIBUTE_READONLY,
        CreationTime: m.creation_time() as _,
        LastAccessTime: m.last_access_time() as _,
        LastWriteTime: m.last_write_time() as _,
        ChangeTime: 0,
    };
    match cvt::cvt(unsafe {
        SetFileInformationByHandle(
            f.as_raw_handle() as HANDLE,
            FileBasicInfo,
            &mut info as *mut FILE_BASIC_INFO as *mut _,
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }) {
        Ok(_) => (),
        Err(e) => return Err((f, e)),
    };
    // 2) mark for deletion
    let f = delete_with_win7(f)?;
    // 3) reapply readonly attribute
    info.FileAttributes |= FILE_ATTRIBUTE_READONLY;
    match cvt::cvt(unsafe {
        SetFileInformationByHandle(
            f.as_raw_handle() as HANDLE,
            FileBasicInfo,
            &mut info as *mut FILE_BASIC_INFO as *mut _,
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }) {
        Ok(_) => Ok(f),
        Err(e) => Err((f, e)),
    }
}

impl FileExt for File {
    fn delete_by_handle(self) -> std::result::Result<(), (File, io::Error)> {
        match delete_with_posix(self)
            .or_else(|(f, e)| {
                match e.raw_os_error().map(|i| i as u32) {
                    Some(ERROR_NOT_SUPPORTED)
                    | Some(ERROR_INVALID_PARAMETER)
                    | Some(ERROR_INVALID_FUNCTION) => {
                        // failed and looks like a compatibility issue, try deleting with windows 7 compatible logic
                        delete_with_win7(f)
                    }
                    _ => Err((f, e)),
                }
            })
            .or_else(|(f, e)| match e.kind() {
                // ACCESSDENIED may mean 'file was readonly'.
                ErrorKind::PermissionDenied => delete_with_win7_readonly(f, e),
                _ => Err((f, e)),
            }) {
            Ok(f) => {
                // Make it explicit that we're dropping the handle, as that can
                // cause IO and it makes profiling easier to have a single
                // callsite to instrument etc.
                mem::drop(f);
                Ok(())
            }
            // return the file handle back so the user can take alternative
            // action if desired.
            Err((f, e)) => Err((f, e)),
        }
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

    fn fill_buffer(&mut self, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<bool> {
        let buffer = self.buffer.as_mut().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
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
                buffer.as_mut_ptr() as *mut c_void,
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
    use test_log::test;
    use windows_sys::Win32::System::Kernel::OBJ_CASE_INSENSITIVE;

    use crate::{os::windows::OpenOptionsExt, testsupport::open_dir, OpenOptions};

    #[test]
    // #[should_panic(expected = "Cannot create a file when that file already exists.")]
    fn mkdir_at_case_insensitive() -> Result<()> {
        // This tests that when case insensitivity is enabled, making a
        // colliding dir fails - but we have no way to easily/reliably turn case
        // insensitivity off for now. So its a bit unnecessary.
        let tmp = TempDir::new()?;
        let parent = tmp.path().join("parent");
        let renamed_parent = tmp.path().join("renamed-parent");
        std::fs::create_dir(&parent)?;
        let parent_file = open_dir(&parent)?;
        rename(parent, renamed_parent)?;
        let mut create_opt = OpenOptions::default();
        create_opt.create(true);
        create_opt.mkdir_at(&parent_file, "child")?;
        create_opt.object_attributes(OBJ_CASE_INSENSITIVE as u32);
        // Incorrectly passes because we're just using .create() now
        create_opt.mkdir_at(&parent_file, "Child")?;
        Ok(())
    }
}
