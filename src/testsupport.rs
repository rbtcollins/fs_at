use std::{
    fs::{File, OpenOptions},
    io::Result,
    path::Path,
};

#[cfg(windows)]
pub fn open_dir(p: &Path) -> Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;

    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    options.open(p)
}

#[cfg(unix)]
pub fn open_dir(p: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    options.open(p)
}
