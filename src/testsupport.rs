use std::{
    fs::{File, OpenOptions},
    io::Result,
    path::Path,
};

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        pub fn open_dir(p:&Path) -> Result<File> {
            use std::os::windows::fs::OpenOptionsExt;

            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

            let mut options = OpenOptions::new();
            options.read(true);
            options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
            options.open(p)
        }
    } else {
        pub fn open_dir(p:&Path) -> Result<File> {
            use std::os::unix::fs::OpenOptionsExt;

            use libc;

            let mut options = OpenOptions::new();
            options.read(true);
            options.custom_flags(libc::O_NOFOLLOW);
            options.open(p)
        }
    }
}
