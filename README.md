# `*_at` syscalls for Rust (*nix and Windows)

The Rust standard library does not (yet) offer at-style filesystem calls as a
core feature. For instance `mkdirat`. These calls are essential for writing
race-free filesystem code, since otherwise the state of the filesystem path that
operations are executed against can change silently, leading to TOC-TOU race
conditions. For Unix these calls are readily available in the libc crate, but
for Windows some more plumbing is needed. This crate provides a unified Rust-y
and safe interface to these calls.

Not all platforms behave identically in their underlying syscalls, and this
crate doesn't abstract over fundamental differences, but it does attempt to
provide consistent errors for key scenarios. As a concrete example creating
a directory at the path of an existing link with follow disabled errors with
AlreadyExists.

On Linux this is achieved by reading back the path that was requested, as
atomic mkdir isn't yet available. `mkdirat` is used so the parent directory
is reliable, but the presence of a link pointing to another part of the file
system cannot be precluded.

On Windows this same scenario will either result in `fs_at` receiving a
`NotADirectory` error from `NtCreateFile`, or the open succeeding but a
race-free detection of the presence of the link is done using
`DeviceIoControl`. Both cases are reported as `AlreadyExists`. The two
codepaths exist because on Windows symlinks can themselves be files or
directories, and the kernel type-checks some operations such as creating a
directory or truncating a file at both the link target and the link source.

Truncate+nofollow also varies by platform: See OpenOptions::truncate.

## MSRV policy

I'll keep this compiling against older rusts as long as it is easy, but not at
the expense of a lot of code golf, or past CVEs in old releases of dependencies.
Currently MSRV is 1.71. If there is a lot of interest in older versions I'm open
to patches.

## Usage

See the crate [docs](https://docs.rs/fs_at). But in short: use
`fs_at::OpenOptions`, similar to `std::fs::OpenOptions`.

## vs other crates

### openat

[openat](https://docs.rs/openat) is a nice wrapper around the Unix *at
facilities. It doesn't offer Windows support, and it also requires adoption of a
new Dir struct which owns the fd - which adds friction for interop with the rest
of std.

### cap_std

[cap_std](https://docs.rs/cap-std) is a lovely rethink of many system
interactions as operations on capabilities. Even more than openat, it steps away
from the familiar std APIs and instead provides its own comprehensive ecosystem.

Unfortunately that doesn't use the full capabilities of the underlying OS - it
layers on top of Rust's own IO stack in some cases (e.g. Windows, some
non-Linux), leading to TOCTOU concerns. That is obviously fixable over time - if
you want a high level API that will make insecure usage hard, I think cap-std is
perfect.

The goal of fs_at isn't to reframe how we do IO though - but just to surface
these important calls in an ergonomic way. Perhaps cap_std could layer on fs_at
when it is finished.

## Contributing

PR's as normal on Github.

Coverage - consider grcov.

```rust
export RUSTFLAGS="-Cinstrument-coverage"
export LLVM_PROFILE_FILE="fs-at-%p-%m.profraw"
cargo test && grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/cove
rage/
```

## Code of conduct

Please note that this project is released with a Contributor Code of Conduct. By
participating in this project you agree to abide by its terms.
