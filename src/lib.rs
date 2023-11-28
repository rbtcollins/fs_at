//! Extension for operations that manipulate the file system relative to an open
//! directory, rather than the global namespace.
//!
//! NB: If a missing capability or platform is found, I will happily add /
//! accept patches : features are being added as needed, rather than
//! speculatively.
//!
//! The Rust standard library does not (yet) offer at-style  filesystem calls as
//! a core feature. For instance `mkdirat`. These calls are essential for
//! writing race-free filesystem code, since otherwise the state of the
//! filesystem path that operations are executed against can change silently,
//! leading to TOC-TOU race conditions. For Unix these calls are readily
//! available in the libc crate, but for Windows some more plumbing is needed.
//! This crate provides a unified Rust-y interface to these calls.
//!
//! Not all platforms behave identically in their underlying syscalls, and this
//! crate doesn't abstract over fundamental differences, but it does attempt to
//! provide consistent errors for key scenarios. As a concrete example creating
//! a directory at the path of an existing link with follow disabled errors with
//! AlreadyExists. In general platform documentation should be consulted to
//! understand the underlying behaviour.
//!
//! On Linux this is achieved by reading back the path that was requested, as
//! atomic mkdir isn't yet available. `mkdirat` is used so the parent directory
//! is reliable, but the presence of a link pointing to another part of the file
//! system cannot be precluded.
//!
//! On Windows this same scenario will either result in `fs_at` receiving a
//! `NotADirectory` error from `NtCreateFile`, or the open succeeding but a
//! race-free detection of the presence of the link is done using
//! `DeviceIoControl`. Both cases are reported as `AlreadyExists`. The two
//! codepaths exist because on Windows symlinks can themselves be files or
//! directories, and the kernel type-checks some operations such as creating a
//! directory or truncating a file at both the link target and the link source.
//!
//! Truncate+nofollow also varies by platform: See OpenOptions::truncate.
//!
//!
//! Caveats:
//! - On windows, procmon will cause the symlink resolution check to receive an
//!   incorrect error code. Enabling the workaround-procmon feature and setting
//!   FS_AT_WORKAROUND_PROCMON will treat ACCESS_DENIED as
//!   ERROR_NOT_REPARSE_POINT.
//!   https://twitter.com/rbtcollins/status/1617211985384407044
//!
//! Feature flags:
//! - workaround-procmon: enables the FS_AT_WORKAROUND_PROCMON environment
//!   variable.
//! - log: enables trace log messages for debugging

use std::{
    ffi::OsStr,
    fs::File,
    io::{Error, ErrorKind, Result},
    path::Path,
};

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        mod win;

        use win::{OpenOptionsImpl, ReadDirImpl, DirEntryImpl};
    } else {
        mod unix;

        use unix::{OpenOptionsImpl, ReadDirImpl, DirEntryImpl};
    }
}

/// Similar to [`std::fs::OpenOptions`], this struct is used to parameterise the
/// various at functions, which are then called on the struct itself. Typical
/// use is to create a struct via [`Default::default`] or
/// [`OpenOptions::default()`], and then customise it as desired (e.g. setting
/// security descriptors on windows, or mode on unix) using an appropriate
/// platform specific trait, finishing up with the desired manipulation e.g.
/// `mkdirat`.
///
/// A note on the manipulations: they take a directory handle as &File. This is
/// believed safe but if you have reason to disagree please file a bug.
///
/// - Rust's borrow checker ensures that File::drop() will not be called
///   concurrently with a manipulation, thus the file will still be open (in the
///   absence of unsafe Rust or non-Rust libraries)
/// - the openat family of functions do not document any state changes to the
///   base fd that names are resolved against. Only `read_dir` is documented as
///   changing state.
/// - similarly on Windows, NtCreateFile is not documented as changing any state
///   when creating a file relative to the handle.
#[derive(Default, Debug)]
#[non_exhaustive]
pub struct OpenOptions {
    _impl: OpenOptionsImpl,
}

/// Controls the way writes to an opened file are performed. Write modes do not
/// affect how the file is opened - creating the file or truncating it require
/// separate options.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum OpenOptionsWriteMode {
    /// No writing permitted. Allows opening files where the process lacks write permissions, and attempts to write will fail.
    #[default]
    None,
    /// Writes permitted. The file location pointer tracked by the OS determines
    /// where writes in the file will take place.
    Write,
    /// Writes permitted. The OS will place each write at the current end of the
    /// file. These may still change the file location pointer, so if reads are
    /// being used as well, be sure to seek to the desired location before
    /// reading. One way to do this is to use seek to save the file location
    /// pointer (`seek(SeekFrom::Current(0))`) and then apply the result before
    /// the next read.
    ///
    /// Most OSes and filesystems make these writes atomically, such that
    /// different threads or even processes can collaborate safely on a single
    /// file, as long as each write call provides a full unit of data (e.g. a
    /// line, or a binary struct etc). This can be done by building up the data
    /// to write, or using a buffered writer that is large enough and calling
    /// flush after each unit is complete.
    ///
    /// In particular NFS on Linux is documented as not providing atomic appends.
    ///
    /// ```no_compile
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(OpenOptionsWriteMode::Append).open_at(&mut parent, "foo.txt");
    /// ```
    Append,
}

impl OpenOptions {
    /// Sets the option for read access.
    ///
    /// This option, when true, will indicate that the file should be read-able if opened.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().read(true).open_at(&mut parent, "foo");
    /// ```
    pub fn read(&mut self, read: bool) -> &mut Self {
        self._impl.read(read);
        self
    }

    /// Sets the option for write access.
    ///
    /// See [`OpenOptionsWriteMode`] for the details of each mode.
    ///
    /// This option on its own is not enough to create a new file.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().write(OpenOptionsWriteMode::Write).open_at(&mut parent, "foo.txt");
    /// ```
    pub fn write(&mut self, write: OpenOptionsWriteMode) -> &mut Self {
        self._impl.write(write);
        self
    }

    /// Sets the option for truncating a previous file.
    ///
    /// If a file is successfully opened with this option set it will truncate
    /// the file to 0 length if it already exists.
    ///
    /// The file must be opened with write access for truncate to work.
    ///
    /// Behaviour of truncate on directories and symlink files is unspecified.
    ///
    /// On Windows a file-symlink from A to B when truncated with no-follow
    /// `(.write(true).truncate(true).follow(false) )` will convert the target
    /// from a symlink to an empty file. The Windows behaviour is compatible
    /// with the definition of O_TRUNC on Unix - this case is unspecified. This
    /// cannot be made race-free, however it seems like a race will at most
    /// destroy a link, not permit elevation of privileges, so this can be
    /// handled by the caller by doing a readlink first, treating a success as
    /// an EEXISTS error, and then actually performing the no-follow truncation.
    ///
    /// On Unix platforms EEXISTS tends to be returned instead.
    ///
    /// ```no_compile
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(OpenOptionsWriteMode::Append).truncate(true).open_at(&mut parent, "foo.txt");
    /// ```
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self._impl.truncate(truncate);
        self
    }

    /// Set the option to create a new file when missing, while still opening
    /// existing files. Unlike the Rust stdlib, an options with write set to
    /// [`OpenOptionsWriteMode::None`] can still be used to create a new file.
    ///
    /// Platform specific:
    /// - on Windows, safely opens existing directories or makes new ones.
    /// - on Linux, consumes EEXIST when making a directory and returns an
    ///   existing directory at that path if it exists.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self._impl.create(create);
        self
    }

    /// Set the option to create a new file, rejecting existing entries at the
    /// pathname, whether links or directories.
    ///
    /// This is requested from the OS as an atomic operation, to provide safety
    /// against TOCTOU conditions. Whether this will occur as an atomic
    /// operation depends on the OS and filesystem in use. In particular NFS
    /// versions below 3 do not support the needed operations for atomicity.
    ///
    /// Unlike the Rust stdlib, an options with write set to
    /// [`OpenOptionsWriteMode::None`] can still be used to create a new file.
    ///
    /// ```no_compile
    /// use fs_at::OpenOptions;
    ///
    /// let file = OpenOptions::default().write(OpenOptionsWriteMode::Write)
    ///                              .create_new(true)
    ///                              .open_at(&mut parent, "foo.txt");
    /// let f = OpenOptions::default()
    ///                              .open_at(&mut parent, "foo.txt").unwrap_err();
    /// ```
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self._impl.create_new(create_new);
        self
    }

    /// Set the option to follow symlinks
    ///
    /// This defaults to true, matching the behaviour of syscalls and most
    /// command line utilities - except for mkdir
    ///
    /// Unix: This corresponds to O_NOFOLLOW, which disables symlink resolution
    /// only for the last element of a path.
    ///
    /// Windows: This corresponds to controlling FILE_FLAG_OPEN_REPARSE_POINT,
    /// which behaves similarly.
    pub fn follow(&mut self, follow: bool) -> &mut Self {
        self._impl.follow(follow);
        self
    }

    /// Create a directory relative to an open directory. Errors if a rooted
    /// path is provided.
    ///
    /// Returns a [`File`] opened on the created directory.
    ///
    /// Platform specific:
    /// - on Windows, atomically creates a new directory (two syscalls: one to
    ///   create the directory with link following disabled, and one to probe
    ///   whether the opened directory is itself a link).
    /// - on Unix, treats EEXIST as an error, but on success requires a separate
    ///   `openat` syscall to open the created directory. This limitation may be
    ///   lifted in future if the mooted mkdirat2 call gets created.. The mode
    ///   of the new directory defaults to 0o777.
    pub fn mkdir_at<P: AsRef<Path>>(&self, d: &File, p: P) -> Result<File> {
        self._impl
            .mkdir_at(d, OpenOptions::ensure_rootless(p.as_ref())?)
    }

    /// Opens a file at the path p relative to the directory d.
    ///
    /// This will honour the options set for creation/append etc, but will only
    /// operate relative to d. To open a file with an absolute path, use the
    /// stdlib fs::OpenOptions.
    ///
    /// Platform specific:
    ///
    /// Windows: Backed by
    /// [NTCreateFile](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).
    /// This function does not perform file name separator translations. If
    /// passing a path containing a separator, it must be a platform native one.
    /// e.g. `foo\\bar` on Windows, vs `foo/bar` on most other OS's. This
    /// function cannot open the parent directory (e.g. open_at(&d, "..")). It
    /// is possible for callers to determine the [path of a
    /// handle](https://learn.microsoft.com/en-us/windows/win32/memory/obtaining-a-file-name-from-a-file-handle),
    /// and then open that using normal stdlib functions.
    ///
    /// Unix: Backed by openat(2).
    pub fn open_at<P: AsRef<Path>>(&self, d: &File, p: P) -> Result<File> {
        self._impl
            .open_at(d, OpenOptions::ensure_rootless(p.as_ref())?)
    }

    /// Opens a directory.
    ///
    /// This is a thin layer over [open_at] which handles the platform specific
    /// variation involved in opening a directory. Follow handling defaults off.
    ///
    /// As with [open_at], extension methods can be used to override the
    /// underlying behaviour.
    ///
    /// Before 0.1.6 follow was always disabled.
    ///
    /// Platform specific:
    ///
    /// Windows: sets FILE_FLAG_OPEN_REPARSE_POINT for createOptions when follow
    /// is disabled, and for dwAccessFlag adds in FILE_LIST_DIRECTORY and
    /// FILE_TRAVERSE. Further, read and write requests are translated to
    /// FILE_READ_ATTRIBUTES, and FILE_WRITE_ATTRIBUTES|DELETE respectively.
    ///
    /// Unix: sets O_NOFOLLOW depending on the  but honours `follow`. Also
    /// O_PATH on platforms that define it.
    pub fn open_dir_at<P: AsRef<Path>>(&self, d: &File, p: P) -> Result<File> {
        self._impl
            .open_dir_at(d, OpenOptions::ensure_rootless(p.as_ref())?)
    }

    /// Opens a path.
    ///
    /// This will open a file that refers to a path which could be normally
    /// unopenable. This is useful for inspecting files in a race-free fashion
    /// without requiring full permissions to them.
    ///
    /// Platform specific:
    ///
    /// Windows: sets FILE_FLAG_OPEN_REPARSE_POINT for createOptions. The
    /// windows extension trait can be used to set dwAccessFlags. All
    /// normal operations can be performed on a file opened in this way
    /// (assuming appropriate access flags).
    ///
    /// Unix: sets O_NOFOLLOW | O_PATH. Many operations on the file handle are
    /// restricted.
    ///
    /// AIX, DragonFlyBSD, iOS, MacOSX, NetBSD, OpenBSD, and illumos: Not
    /// implemented as O_PATH is not defined.
    #[cfg(not(any(
        target_os = "aix",
        target_os = "dragonfly",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    pub fn open_path_at<P: AsRef<Path>>(&self, d: &File, p: P) -> Result<File> {
        self._impl
            .open_path_at(d, OpenOptions::ensure_rootless(p.as_ref())?)
    }

    /// Creates a symlink at the path linkname pointing to target.
    ///
    /// This will fail if the path linkname is already used.
    ///
    /// Unlike [`open_at`] this doesn't return a File object: opening symlink
    /// files directly is not portable.
    ///
    /// Note: on Windows two syscalls are required to create a symlink. The
    /// creation of the backing file is atomic and safe, but it is possible if
    /// the process is interrupted that it will remain as a an blank
    /// [`LinkEntryType`] rather than being converted to a symlink.
    /// https://github.com/rbtcollins/fs_at/issues/10
    ///
    /// The target may be an absolute or relative path, and will be inspected to
    /// determine that before creation - but as with [`open_at`] native OS path
    /// separators must be used, and minimal processing is done - to use
    /// absolute paths, canonicalise them first.
    ///
    /// The `entry_type` is unused on *nix OS's; if writing *nix only software,
    /// just pass in LinkEntryType::default(). Similarly if writing portable
    /// software where the only consumers will be symlink aware. But if humans
    /// using a UI are expected to interact with the link, choose an appropriate
    /// type based on how the UI should behave when viewing the parent.
    ///
    /// Stability: it isn't clear whether entry_type should be exposed, or the
    /// default should be just a file(or dir) always and then fine grained
    /// control via an extension trait.
    pub fn symlink_at<P, Q>(
        &self,
        d: &File,
        linkname: P,
        entry_type: LinkEntryType,
        target: Q,
    ) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        self._impl.symlink_at(
            d,
            OpenOptions::ensure_rootless(linkname.as_ref())?,
            entry_type,
            target.as_ref(),
        )
    }

    /// Unlink a non-directory at a path relative to d.
    ///
    /// If the path referred to is a symbolic link, the link itself is removed.
    ///
    /// Platform specific: some platforms treat unlink and rmdir as equivalent.
    /// Others such as Mac OSX do not, and rmdir must be used when deleting a
    /// directory.
    pub fn unlink_at<P>(&self, d: &File, p: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self._impl
            .unlink_at(d, OpenOptions::ensure_rootless(p.as_ref())?)
    }

    /// Remove a directory at a path relative to d.
    ///
    /// Platform specific: some platforms treat unlink and rmdir as equivalent.
    /// Others such as Mac OSX do not, and rmdir must be used when deleting a
    /// directory.
    pub fn rmdir_at<P>(&self, d: &File, p: P) -> Result<()>
    where
        P: AsRef<Path>,
    {
        self._impl
            .rmdir_at(d, OpenOptions::ensure_rootless(p.as_ref())?)
    }

    fn ensure_rootless(p: &Path) -> Result<&Path> {
        if p.has_root() {
            return Err(Error::new(
                ErrorKind::Other,
                format!("Rooted file path {p:?}"),
            ));
        }
        Ok(p)
    }
}

/// Iterate over the contents of a directory. Created by calling read_dir() on
/// an opened directory. Each item yielded by the iterator is an io::Result to
/// allow communication of io errors as the iterator is advanced.
///
/// To the greatest extent possible the underlying OS semantics are preserved.
/// That means that `.` and `..` entries are exposed, and that no sort order is
/// guaranteed by the iterator.
///
/// On both unix and Windows directory iteration affects shared mutable state,
/// thus this iterator holds an &mut File for the lifetime of the iterator. The
/// workaround - opening a new file - can be performed by users of the library
/// if desired.
///
/// (On Unix fdopendir is used to obtain a directory stream, but as closedir
/// closes the file descriptor the original descriptor is dup2'd first. But as
/// dup2 duplicated descriptors share the open file description, the position in
/// readdir() is shared: permitting other concurrent readdir iterations to be
/// started concurrently might be memory safe, but its clearly not safe safe.
///
/// On Windows a similar situation applies with FileIdBothDirectoryInfo /
/// FileIdBothDirectoryRestartInfo and DuplicateHandle: DuplicateHandle aliases
/// into kernel state rather than creating an entirely separate accounting.
#[derive(Debug)]
pub struct ReadDir<'a> {
    _impl: ReadDirImpl<'a>,
}

impl<'a> ReadDir<'a> {
    pub fn new(d: &'a mut File) -> Result<Self> {
        Ok(ReadDir {
            _impl: ReadDirImpl::new(d)?,
        })
    }
}

impl Iterator for ReadDir<'_> {
    type Item = Result<DirEntry>;

    fn next(&mut self) -> Option<Result<DirEntry>> {
        self._impl
            .next()
            .map(|entry| entry.map(|_impl| DirEntry { _impl }))
    }
}

/// The returned type for each entry found by [`read_dir`].
///
/// Each entry represents a single entry inside the directory. Platforms that
/// provide rich metadata may in future expose this through methods or extension
/// traits on DirEntry.
///
/// For now however, only the [`name()`] is exposed. This does not imply any
/// additional IO for most workloads: metadata returned from a directory listing
/// is inherently racy: presuming that what was a dir, or symlink etc when the
/// directory was listed, will still be the same when opened is fallible.
/// Instead, use open_at to open the contents, and then process based on the
/// type of content found.
#[derive(Debug)]
pub struct DirEntry {
    _impl: DirEntryImpl,
}

impl DirEntry {
    pub fn name(&self) -> &OsStr {
        self._impl.name()
    }
}

/// Read the children of the directory d.
///
/// See [`ReadDir`] and [`DirEntry`] for details.
pub fn read_dir(d: &mut File) -> Result<ReadDir> {
    ReadDir::new(d)
}

/// File kind indicator
///
/// On Windows symlinks are implemented an actual directory or file, with
/// reparse data stored in a single global index; the kind of the actual
/// directory or file leaks through to the operations one can perform on the
/// symlink (e.g. cannot chdir from a CMD prompt to a file-backed symlink).
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum LinkEntryType {
    #[default]
    File,
    Dir,
    Other,
}

pub mod os {
    cfg_if::cfg_if! {
        if #[cfg(windows)] {
            pub use crate::win::exports as windows;
        } else {
            pub use crate::unix::exports as unix;
        }
    }
}

#[cfg(test)]
pub mod testsupport;

#[cfg(test)]
mod tests {
    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    use std::path::Path;
    use std::{
        ffi::OsStr,
        fs::{rename, File},
        io::{Error, ErrorKind, Result, Seek, SeekFrom, Write},
        path::PathBuf,
        time::{Duration, SystemTime},
    };

    use rayon::prelude::*;
    use tempfile::TempDir;
    use test_log::test;

    use crate::{
        read_dir, testsupport::open_dir, DirEntry, LinkEntryType, OpenOptions, OpenOptionsWriteMode,
    };

    // Can be inlined when more_io_errors stablises
    cfg_if::cfg_if! {
        if #[cfg(windows)] {
            use windows_sys::Win32::Foundation::{ERROR_CANT_RESOLVE_FILENAME, ERROR_DIRECTORY};

            #[allow(non_snake_case)]
            fn FileSystemLoopError() -> Error { Error::from_raw_os_error(
            ERROR_CANT_RESOLVE_FILENAME as i32)}
            #[allow(non_snake_case)]
            fn NotADirectory() -> Error { Error::from_raw_os_error(
                ERROR_DIRECTORY as i32
            )}
        } else {
            #[allow(non_snake_case)]
            fn FileSystemLoopError() -> Error { Error::from_raw_os_error(libc::ELOOP)}
            #[allow(non_snake_case)]
            fn NotADirectory() -> Error { Error::from_raw_os_error(libc::ENOTDIR)}
        }
    }

    /// Create a directory parent, open it, then rename it to renamed-parent and
    /// create another directory in its place. returns the file handle and the
    /// final path.
    fn setup() -> Result<(TempDir, File, PathBuf)> {
        let tmp = TempDir::new()?;
        let parent = tmp.path().join("parent");
        let renamed_parent = tmp.path().join("renamed-parent");
        std::fs::create_dir(&parent)?;
        let parent_file = open_dir(&parent)?;
        rename(parent, &renamed_parent)?;
        Ok((tmp, parent_file, renamed_parent))
    }

    #[derive(Default, Debug, Clone, PartialEq, PartialOrd)]
    enum Op {
        // Perform a mkdirat call
        #[default]
        MkDir,
        // perform an open call on a file
        OpenFile,
        // perform an open call on a dir ? [should this be extension only?]
        #[allow(unused)]
        OpenDir,
        // perform an unlink of a non-dir
        Unlink,
        // perform a rmdir of a dir
        RmDir,
    }

    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
    enum SymlinkMode {
        // no symlink present
        #[default]
        None,
        // operate on paths that are the target of a symlink e.g. foo/<link>
        LinkIsTarget,
        // operate on paths that are found through a symlink e.g. <link>/foo
        LinkIsParent,
    }

    #[derive(Default, Debug, Clone)]
    struct Test {
        pub create: bool,
        pub create_new: bool,
        pub read: bool,
        pub write: OpenOptionsWriteMode,
        pub truncate: bool,
        pub op: Op,
        pub symlink_mode: SymlinkMode,
        pub symlink_entry_type: LinkEntryType,
        pub follow: Option<bool>,
    }

    impl Test {
        fn create(mut self, create: bool) -> Self {
            self.create = create;
            self
        }

        fn create_new(mut self, create_new: bool) -> Self {
            self.create_new = create_new;
            self
        }

        fn read(mut self, read: bool) -> Self {
            self.read = read;
            self
        }

        fn write(mut self, write: OpenOptionsWriteMode) -> Self {
            self.write = write;
            self
        }

        fn truncate(mut self, truncate: bool) -> Self {
            self.truncate = truncate;
            self
        }

        fn op(mut self, op: Op) -> Self {
            self.op = op;
            self
        }

        fn symlink_mode(mut self, symlink_mode: SymlinkMode) -> Self {
            self.symlink_mode = symlink_mode;
            self
        }

        fn symlink_entry_type(mut self, symlink_entry_type: LinkEntryType) -> Self {
            self.symlink_entry_type = symlink_entry_type;
            self
        }

        fn follow(mut self, follow: Option<bool>) -> Self {
            self.follow = follow;
            self
        }
    }

    fn _check_behaviour(
        test: Test,
        create_in_advance: bool,
        err: Option<&Error>,
        counter: &mut u32,
    ) -> Result<()> {
        eprintln!(
            "testing idx: {counter}, op: {test:?} create_in_advance: {create_in_advance}, err: {err:?}"
        );
        *counter += 1;
        let (_tmp, parent_file, renamed_parent) = setup()?;
        let mut options = OpenOptions::default();

        let (actual_child, child_name) = if test.symlink_mode == SymlinkMode::None {
            ("child", PathBuf::from("child"))
        } else if test.symlink_mode == SymlinkMode::LinkIsTarget {
            ("link_child", PathBuf::from("child"))
        } else {
            /* LinkIsParent */
            ("link_child", PathBuf::from("link_dir").join("link_child"))
        };

        if test.create {
            options.create(true);
        }
        if test.create_new {
            options.create_new(true);
        }
        if test.read {
            options.read(true);
        }
        options.write(test.write);
        if test.truncate {
            options.truncate(true);
        }
        if let Some(follow) = test.follow {
            options.follow(follow);
        }

        if create_in_advance {
            match test.op {
                Op::MkDir | Op::RmDir => {
                    options.mkdir_at(&parent_file, actual_child)?;
                }
                Op::OpenDir => (),
                Op::OpenFile | Op::Unlink => {
                    let mut first_file = OpenOptions::default()
                        .create(true)
                        .write(OpenOptionsWriteMode::Write)
                        .open_at(&parent_file, actual_child)?;
                    assert_eq!(16, first_file.write(b"existing content")?);
                    first_file.flush()?;
                }
            }
        }
        match test.symlink_mode {
            SymlinkMode::None => {}
            SymlinkMode::LinkIsParent => {
                OpenOptions::default().create(true).symlink_at(
                    &parent_file,
                    "link_dir",
                    test.symlink_entry_type,
                    ".",
                )?;
            }
            SymlinkMode::LinkIsTarget => {
                OpenOptions::default().create(true).symlink_at(
                    &parent_file,
                    &child_name,
                    test.symlink_entry_type,
                    actual_child,
                )?;
            }
        }

        if matches!(test.op, Op::MkDir | Op::OpenDir | Op::OpenFile) {
            // functions that return a file handle
            let res = match test.op {
                Op::MkDir => options.mkdir_at(&parent_file, &child_name),
                Op::OpenDir => unimplemented!(),
                Op::OpenFile => options.open_at(&parent_file, &child_name),
                _ => unreachable!(),
            };
            let mut child = match (res, err) {
                (Ok(child), None) => child,
                (Ok(_), Some(e)) => panic!("unexpected success {e:?}"),
                (Err(e), None) => panic!("unexpected error {e:?}"),
                (Err(e), Some(expected_e)) => {
                    assert_eq!(e.kind(), expected_e.kind(), "{e:?} != {expected_e:?}");
                    return Ok(());
                }
            };
            let expected = renamed_parent.join(actual_child);
            let metadata = expected.symlink_metadata()?;
            match test.op {
                Op::MkDir => assert!(metadata.is_dir()),
                Op::OpenDir => (),
                Op::OpenFile => {
                    assert!(metadata.is_file());
                    // If the file was truncated, it will be 0-length.
                    // If the file is new it will be 0-length.
                    let initial_length = metadata.len();
                    if test.truncate || !create_in_advance {
                        assert_eq!(initial_length, 0);
                    } else {
                        assert_eq!(initial_length, 16);
                    }
                    if test.write != OpenOptionsWriteMode::None {
                        child.seek(SeekFrom::Start(10))?;
                        assert_eq!(10, child.write(b"some data\n")?);
                        if test.write == OpenOptionsWriteMode::Write {
                            assert_eq!(expected.symlink_metadata()?.len(), 20);
                        } else {
                            // The write location is ignored in append mode
                            assert_eq!(expected.symlink_metadata()?.len(), initial_length + 10);
                        }
                    }
                    //
                }
                _ => unreachable!(),
            }
        } else {
            // Functions that delete something
            let res = match test.op {
                Op::RmDir => options.rmdir_at(&parent_file, &child_name),
                Op::Unlink => options.unlink_at(&parent_file, &child_name),
                _ => unreachable!(),
            };
            match (res, err) {
                (Ok(()), None) => (),
                (Ok(_), Some(e)) => panic!("unexpected success {e:?}"),
                (Err(e), None) => panic!("unexpected error {e:?}"),
                (Err(e), Some(expected_e)) => {
                    assert_eq!(e.kind(), expected_e.kind(), "{e:?} != {expected_e:?}");
                    return Ok(());
                }
            };
            // in the non-error case child_name should have been removed.
            let expected = renamed_parent.join(&child_name);
            match expected.symlink_metadata() {
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
                Ok(_) => panic!("{child_name:?} not deleted"),
            }?;
        }
        Ok(())
    }

    // basic property based framework. Performs a specific combination of
    // options with a file-or-dir opening call, and verifies the resulting
    // object can be used as expected. Note that this cannot be used to create
    // actual races - but the library depends on the OS behaviour for race
    // safety: what we are checking for here is that we're passing the right
    // semantics down for when races do occur (e.g. O_EXCL is supplied when
    // requested...)
    //
    // Some combinations are illegal on some platforms and they get filtered
    // out. For instance file operations through a LinkEntryType::Dir link will
    // error on windows, and directory operations through a LinkEntryType::File
    // link will error likewise.
    fn check_behaviour(test: Test, counter: &mut u32) -> Result<()> {
        if cfg!(windows)
            && (matches!(test.op, Op::MkDir | Op::OpenDir)
                && matches!(test.symlink_entry_type, LinkEntryType::File))
            || (matches!(test.op, Op::OpenFile)
                && matches!(test.symlink_entry_type, LinkEntryType::Dir))
        {
            // Windows doesn't support dir operations on a file typed link or vice versa.
            return Ok(());
        }
        if cfg!(windows)
            && test.symlink_mode == SymlinkMode::LinkIsTarget
            && test.follow == Some(false)
            && test.symlink_entry_type == LinkEntryType::File
            && test.op == Op::OpenFile
            && test.truncate
        {
            // Windows truncates the *symlink itself* on a truncate operation on
            // a LinkEntryType::File truncated with no-follow. Just skip the test entirely.
            return Ok(());
        }

        let err = if test.symlink_mode == SymlinkMode::LinkIsTarget
            && (test.op == Op::MkDir || test.create_new)
        {
            // mkdirat is specified as failing with EEXIST if pathname exists -
            // including a dangling symlink. Force those scenarios to errors.
            // similarly openat with O_EXCL + O_CREAT == create_new.
            Some(Error::from(ErrorKind::AlreadyExists))
        } else if test.symlink_mode == SymlinkMode::LinkIsTarget && test.follow == Some(false) {
            // follow(false) causes every openat to fail ELOOP when the path as given resolves to a link itself.
            Some(FileSystemLoopError())
        } else if test.symlink_mode == SymlinkMode::LinkIsTarget && (test.op == Op::RmDir) {
            #[cfg(windows)]
            {
                if test.symlink_entry_type == LinkEntryType::Dir {
                    // on windows symlinks can be directories
                    None
                } else {
                    // or they can be files
                    Some(NotADirectory())
                }
            }

            #[cfg(not(windows))]
            {
                // can't rmdir a symlink on unix ...
                Some(NotADirectory())
            }
        } else {
            None
        };

        if test.create_new {
            // run three tests: one that creates the path, and one that expects
            // an error operating on the existing path, and one that expects an
            // error likewise operating on an existing symlink
            _check_behaviour(test.clone(), false, err.as_ref(), counter)?;
            let err = Error::from(ErrorKind::AlreadyExists);
            _check_behaviour(test, true, Some(&err), counter)
        } else if test.create || test.truncate {
            // run two tests: one that creates the path, and once that opens
            // the existing path
            _check_behaviour(test.clone(), true, err.as_ref(), counter)?;
            _check_behaviour(test, false, err.as_ref(), counter)
        } else if matches!(test.op, Op::MkDir) {
            // run two tests: one that creates the path where it didn't exist
            // and one that precreates the path and expects an error
            _check_behaviour(test.clone(), false, err.as_ref(), counter)?;
            let err = Error::from(ErrorKind::AlreadyExists);
            _check_behaviour(test, true, Some(&err), counter)
        } else if matches!(test.op, Op::RmDir) {
            // run two tests: one that unlinks a missing path and expects an error
            // and one that creates the path and expects success when operating on a dir
            // or NotADirectory when operating on a symlink
            let missing_err = if test.symlink_mode == SymlinkMode::LinkIsTarget {
                // On Windows, the link itself may be a dir, which can then be
                // rmdired. Or the link may be a file, where rmdir is wrong, but seems to succeed. Thats a kernel concern!.
                #[cfg(windows)]
                {
                    if test.symlink_entry_type == LinkEntryType::File {
                        Some(NotADirectory())
                    } else {
                        None
                    }
                }
                #[cfg(not(windows))]
                {
                    // when we rmdir a symlink (at least on linux)
                    Some(NotADirectory())
                }
            } else {
                // when we rmdir a missing path we get NotFound.
                Some(Error::from(ErrorKind::NotFound))
            };
            _check_behaviour(test.clone(), false, missing_err.as_ref(), counter)?;
            _check_behaviour(test, true, err.as_ref(), counter)
        } else if matches!(test.op, Op::Unlink) {
            // run two tests: one that unlinks a missing path and expects an error
            // except when operating on a symlink.
            // and one that creates the path and expects success.
            let missing_err = if test.symlink_mode == SymlinkMode::LinkIsTarget {
                None
            } else {
                Some(Error::from(ErrorKind::NotFound))
            };
            _check_behaviour(test.clone(), false, missing_err.as_ref(), counter)?;
            _check_behaviour(test, true, err.as_ref(), counter)
        } else {
            Ok(())
        }
    }

    #[test]
    fn all_mkdir() -> Result<()> {
        let mut counter = 0;
        for create in [false, true] {
            for create_new in [false, true] {
                for read in [false, true] {
                    for write in [
                        OpenOptionsWriteMode::None,
                        OpenOptionsWriteMode::Write,
                        OpenOptionsWriteMode::Append,
                    ] {
                        for symlink_mode in [
                            SymlinkMode::None,
                            SymlinkMode::LinkIsParent,
                            SymlinkMode::LinkIsTarget,
                        ] {
                            for symlink_entry_type in [LinkEntryType::Dir, LinkEntryType::File] {
                                check_behaviour(
                                    Test::default()
                                        .create(create)
                                        .create_new(create_new)
                                        .read(read)
                                        .write(write)
                                        .symlink_mode(symlink_mode)
                                        .symlink_entry_type(symlink_entry_type)
                                        .op(Op::MkDir),
                                    &mut counter,
                                )?;
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn all_rmdir() -> Result<()> {
        let mut counter = 0;

        for symlink_mode in [
            SymlinkMode::None,
            SymlinkMode::LinkIsParent,
            SymlinkMode::LinkIsTarget,
        ] {
            for symlink_entry_type in [LinkEntryType::Dir, LinkEntryType::File] {
                check_behaviour(
                    Test::default()
                        .symlink_mode(symlink_mode)
                        .symlink_entry_type(symlink_entry_type)
                        .op(Op::RmDir),
                    &mut counter,
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn all_unlink() -> Result<()> {
        let mut counter = 0;

        for symlink_mode in [
            SymlinkMode::None,
            SymlinkMode::LinkIsParent,
            SymlinkMode::LinkIsTarget,
        ] {
            for symlink_entry_type in [LinkEntryType::Dir, LinkEntryType::File] {
                check_behaviour(
                    Test::default()
                        .symlink_mode(symlink_mode)
                        .symlink_entry_type(symlink_entry_type)
                        .op(Op::Unlink),
                    &mut counter,
                )?;
            }
        }
        Ok(())
    }

    #[test]
    fn all_open_file() -> Result<()> {
        let mut counter = 0;
        for create in [false, true] {
            for create_new in [false, true] {
                for read in [false, true] {
                    for write in [
                        OpenOptionsWriteMode::None,
                        OpenOptionsWriteMode::Write,
                        OpenOptionsWriteMode::Append,
                    ] {
                        for truncate in [false, true] {
                            // Filter for open: without one of read/write/append all
                            // calls will fail
                            if !read && write == OpenOptionsWriteMode::None {
                                continue;
                            }
                            for symlink_mode in [
                                SymlinkMode::None,
                                SymlinkMode::LinkIsParent,
                                SymlinkMode::LinkIsTarget,
                            ] {
                                for symlink_entry_type in [LinkEntryType::Dir, LinkEntryType::File]
                                {
                                    for follow in [None, Some(true), Some(false)] {
                                        check_behaviour(
                                            Test::default()
                                                .create(create)
                                                .create_new(create_new)
                                                .read(read)
                                                .write(write)
                                                .truncate(truncate)
                                                .symlink_mode(symlink_mode)
                                                .symlink_entry_type(symlink_entry_type)
                                                .follow(follow)
                                                .op(Op::OpenFile),
                                            &mut counter,
                                        )?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn readdir_sync_send() -> Result<()> {
        let (_tmp, mut parent_dir, _pathname) = setup()?;
        let dirstream = read_dir(&mut parent_dir)?;
        dirstream
            .par_bridge()
            .try_for_each(|dir_entry| -> Result<()> {
                dir_entry?;
                Ok(())
            })?;
        Ok(())
    }

    #[test]
    fn readdir() -> Result<()> {
        let (_tmp, mut parent_dir, _pathname) = setup()?;
        assert_eq!(
            2, // . and ..
            read_dir(&mut parent_dir)?
                .collect::<Result<Vec<DirEntry>>>()?
                .len()
        );
        let dir_present =
            |children: &Vec<DirEntry>, name: &OsStr| children.iter().any(|e| e.name() == name);

        let mut options = OpenOptions::default();
        options.create_new(true).write(OpenOptionsWriteMode::Write);
        options.open_at(&parent_dir, "1")?;
        options.open_at(&parent_dir, "2")?;
        options.open_at(&options.mkdir_at(&parent_dir, "child")?, "3")?;
        let children = read_dir(&mut parent_dir)?.collect::<Result<Vec<_>>>()?;
        assert_eq!(
            5,
            children.len(),
            "directory contains 5 entries (., .., 1, 2, child)"
        );
        assert!(dir_present(&children, OsStr::new("1")), "{children:?}");
        assert!(dir_present(&children, OsStr::new("2")), "{children:?}");
        assert!(dir_present(&children, OsStr::new("child")), "{children:?}");

        {
            let mut child = OpenOptions::default()
                .read(true)
                .open_at(&parent_dir, "child")?;
            let children = read_dir(&mut child)?.collect::<Result<Vec<_>>>()?;
            assert_eq!(3, children.len(), "{children:?}");
            assert!(dir_present(&children, OsStr::new("3")), "{children:?}");
        }
        Ok(())
    }

    #[test]
    fn symlink_at() -> Result<()> {
        let (_tmp, mut parent_dir, _pathname) = setup()?;
        OpenOptions::default().symlink_at(
            &parent_dir,
            "linkname1",
            crate::LinkEntryType::Dir,
            "target",
        )?;
        OpenOptions::default().symlink_at(
            &parent_dir,
            "linkname2",
            crate::LinkEntryType::File,
            "target",
        )?;

        let children = read_dir(&mut parent_dir)?.collect::<Result<Vec<DirEntry>>>()?;
        assert_eq!(
            4, // . and .. and the two links
            children.len()
        );
        assert!(children.iter().any(|e| e.name() == "linkname1"));
        assert!(children.iter().any(|e| e.name() == "linkname2"));
        Ok(())
    }

    #[test]
    fn open_dir_at() -> Result<()> {
        let (_tmp, parent_dir, _pathname) = setup()?;
        // setup
        {
            let dir = OpenOptions::default().mkdir_at(&parent_dir, "dir")?;
            OpenOptions::default()
                .create_new(true)
                .write(OpenOptionsWriteMode::Write)
                .open_at(&dir, "file")?;
            OpenOptions::default().symlink_at(
                &parent_dir,
                "linkname",
                LinkEntryType::Dir,
                "dir",
            )?;
        }

        // case 1: no options -> error
        {
            OpenOptions::default()
                .open_dir_at(&parent_dir, "dir")
                .unwrap_err();
        }

        // case 2: write - can we write the dir's date
        let reference_time = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        {
            let dir = OpenOptions::default()
                .write(OpenOptionsWriteMode::Write)
                .open_dir_at(&parent_dir, "dir")?;
            fs_set_times::SetTimes::set_times(
                &dir,
                None,
                Some(fs_set_times::SystemTimeSpec::Absolute(reference_time)),
            )?;
        }

        // case 3: read - can we read the dir's date
        {
            let dir = OpenOptions::default()
                .read(true)
                .open_dir_at(&parent_dir, "dir")?;
            assert_eq!(reference_time, dir.metadata()?.modified()?);
        }

        // case 4: can we traverse the directory
        {
            let mut dir = OpenOptions::default()
                .read(true)
                .open_dir_at(&parent_dir, "dir")?;
            OpenOptions::default().read(true).open_at(&dir, "file")?;
            let children =
                super::read_dir(&mut dir)?.map(|dir_entry| dir_entry.unwrap().name().to_owned());
            assert_eq!(3, children.count());
        }

        // case 5: we cannot open a directory via a symlink by default
        {
            OpenOptions::default()
                .read(true)
                .open_dir_at(&parent_dir, "linkname")
                .unwrap_err();
        }

        // case 6: but we can if we enable follow
        {
            let dir = OpenOptions::default()
                .read(true)
                .follow(true)
                .open_dir_at(&parent_dir, "linkname")?;
            assert_eq!(reference_time, dir.metadata()?.modified()?);
        }

        Ok(())
    }

    #[cfg(not(any(
        target_os = "aix",
        target_os = "dragonfly",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris"
    )))]
    #[test]
    fn open_path_at() -> Result<()> {
        let (_tmp, parent_dir, _pathname) = setup()?;
        // setup
        {
            let dir = OpenOptions::default().mkdir_at(&parent_dir, "dir")?;
            OpenOptions::default()
                .create_new(true)
                .write(OpenOptionsWriteMode::Write)
                .open_at(&dir, "file")?;
            OpenOptions::default().symlink_at(&dir, "linkname", LinkEntryType::File, "target")?;
        }

        // case 1: open a dir
        {
            OpenOptions::default().open_path_at(&parent_dir, "dir")?;
        }

        // case 2: open a file
        {
            OpenOptions::default().open_path_at(&parent_dir, Path::new("dir").join("file"))?;
        }

        // case 3: open a link
        {
            OpenOptions::default().open_path_at(&parent_dir, Path::new("dir").join("linkname"))?;
        }

        // case 4: can we open-and-delete on windows
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::DELETE;

            use super::os::windows::{FileExt, OpenOptionsExt};

            let f = OpenOptions::default()
                .desired_access(DELETE)
                .open_path_at(&parent_dir, "dir\\linkname")?;
            f.delete_by_handle().map_err(|(_, e)| e)?;
        }

        // case 4: can we traverse a directory on windows
        #[cfg(windows)]
        {
            use windows_sys::Win32::Storage::FileSystem::FILE_LIST_DIRECTORY;

            use super::os::windows::OpenOptionsExt;

            let mut dir = OpenOptions::default()
                .desired_access(FILE_LIST_DIRECTORY)
                .open_path_at(&parent_dir, "dir")?;

            let children =
                super::read_dir(&mut dir)?.map(|dir_entry| dir_entry.unwrap().name().to_owned());
            assert_eq!(3, children.count());
        }

        Ok(())
    }

    #[test]
    fn check_eloop_raw_os_value() -> Result<()> {
        let (_tmp, parent_dir, _pathname) = setup()?;
        OpenOptions::default().symlink_at(
            &parent_dir,
            "linkname1",
            crate::LinkEntryType::Dir,
            "linkname2",
        )?;
        OpenOptions::default().symlink_at(
            &parent_dir,
            "linkname2",
            crate::LinkEntryType::Dir,
            "linkname1",
        )?;
        let e = OpenOptions::default()
            .read(true)
            .open_at(&parent_dir, "linkname1")
            .unwrap_err();
        assert_eq!(e.raw_os_error(), FileSystemLoopError().raw_os_error());
        Ok(())
    }
}
