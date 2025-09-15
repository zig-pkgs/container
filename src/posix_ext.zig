/// A wrapper around the raw `syscall5` to provide a typed error set for the mount(2) syscall.
pub const MountError = error{
    /// EACCES: A component of a path was not searchable, or mounting a read-only
    /// filesystem was attempted without the MS_RDONLY flag.
    Access,
    /// EBUSY: The source is already mounted, or it cannot be remounted read-only
    /// because it still holds files open for writing.
    Busy,
    /// EFAULT: A pointer argument points outside the user address space.
    Fault,
    /// EINVAL: Invalid superblock, invalid remount/move operation, or invalid flags.
    InvalidValue,
    /// ELOOP: Too many links encountered during pathname resolution or a move
    /// operation where the target is a descendant of the source.
    Loop,
    /// EMFILE: The table of dummy devices is full.
    FileTableOverflow,
    /// ENAMETOOLONG: A pathname was longer than MAXPATHLEN.
    NameTooLong,
    /// ENODEV: The filesystem type is not configured in the kernel.
    NoDevice,
    /// ENOENT: A pathname was empty or had a nonexistent component.
    NoEntry,
    /// ENOMEM: The kernel could not allocate memory.
    NoMemory,
    /// ENOTBLK: The source is not a block device when one was required.
    NotBlockDevice,
    /// ENOTDIR: The target, or a prefix of the source, is not a directory.
    NotDirectory,
    /// ENXIO: The major number of the block device source is out of range.
    NoDeviceOrAddress,
    /// EPERM: The caller does not have the required privileges.
    PermissionDenied,
    /// EROFS: An attempt was made to mount a read-only filesystem without the MS_RDONLY flag.
    ReadOnlyFileSystem,
} || posix.UnexpectedError;

/// A wrapper around the raw `syscall2` to provide a typed error set for the umount2(2) syscall.
pub const UmountError = error{
    /// EAGAIN: A call to umount2() with MNT_EXPIRE successfully marked an unbusy filesystem as expired.
    Again,
    /// EBUSY: The target could not be unmounted because it is busy.
    Busy,
    /// EFAULT: The target points outside the user address space.
    Fault,
    /// EINVAL: The target is not a mount point or is locked.
    InvalidValue,
    /// ENAMETOOLONG: A pathname was longer than MAXPATHLEN.
    NameTooLong,
    /// ENOENT: A pathname was empty or had a nonexistent component.
    NoEntry,
    /// ENOMEM: The kernel could not allocate memory.
    NoMemory,
    /// EPERM: The caller does not have the required privileges.
    PermissionDenied,
} || posix.UnexpectedError;

/// Mounts a filesystem.
/// This function wraps the raw `mount` syscall to return a typed `MountError`.
pub fn mountZ(
    special: [*:0]const u8,
    dir: [*:0]const u8,
    fstype: ?[*:0]const u8,
    flags: u32,
    data: usize,
) MountError!void {
    const rc = linux.mount(special, dir, fstype, flags, data);
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES => error.Access,
        .BUSY => error.Busy,
        .FAULT => error.Fault,
        .INVAL => error.InvalidValue,
        .LOOP => error.Loop,
        .MFILE => error.FileTableOverflow,
        .NAMETOOLONG => error.NameTooLong,
        .NODEV => error.NoDevice,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .NOTBLK => error.NotBlockDevice,
        .NOTDIR => error.NotDirectory,
        .NXIO => error.NoDeviceOrAddress,
        .PERM => error.PermissionDenied,
        .ROFS => error.ReadOnlyFileSystem,
        else => |e| posix.unexpectedErrno(e),
    };
}

/// Unmounts a filesystem with the specified flags.
/// This function wraps the raw `umount2` syscall to return a typed `UmountError`.
pub fn umount2Z(special: [*:0]const u8, flags: u32) UmountError!void {
    const rc = linux.umount2(special, flags);
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .AGAIN => error.Again,
        .BUSY => error.Busy,
        .FAULT => error.Fault,
        .INVAL => error.InvalidValue,
        .NAMETOOLONG => error.NameTooLong,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .PERM => error.PermissionDenied,
        else => |e| posix.unexpectedErrno(e),
    };
}

/// A typed error set for failures from the chroot(2) syscall.
pub const ChrootError = error{
    /// EACCES: Search permission is denied on a component of the path prefix.
    Access,
    /// EFAULT: The path points outside the process's accessible address space.
    Fault,
    /// EIO: An I/O error occurred.
    InputOutput,
    /// ELOOP: Too many symbolic links were encountered in resolving the path.
    Loop,
    /// ENAMETOOLONG: The path is too long.
    NameTooLong,
    /// ENOENT: The path does not exist.
    NoEntry,
    /// ENOMEM: Insufficient kernel memory was available.
    NoMemory,
    /// ENOTDIR: A component of the path is not a directory.
    NotDirectory,
    /// EPERM: The caller has insufficient privilege to perform the operation.
    PermissionDenied,
} || posix.UnexpectedError;

/// Changes the root directory of the calling process to the specified path.
/// This function wraps the raw `chroot` syscall to return a typed `ChrootError`.
pub fn chrootZ(path: [*:0]const u8) ChrootError!void {
    // The chroot syscall returns 0 on success and -1 on error.
    const rc = linux.chroot(path);

    return switch (posix.errno(rc)) {
        .SUCCESS => {}, // Success, return void.
        .ACCES => error.Access,
        .FAULT => error.Fault,
        .IO => error.InputOutput,
        .LOOP => error.Loop,
        .NAMETOOLONG => error.NameTooLong,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .NOTDIR => error.NotDirectory,
        .PERM => error.PermissionDenied,
        // Forward any other unexpected errno to the caller.
        else => |e| posix.unexpectedErrno(e),
    };
}

/// A comprehensive, typed error set for the unshare(2) syscall, based on the man page.
pub const UnshareError = error{
    /// EINVAL: Invalid flags were specified, thread-related flags were used in a
    /// multithreaded process, or a required kernel module for a namespace is not loaded.
    InvalidValue,
    /// ENOMEM: Cannot allocate sufficient memory for the operation.
    NoMemory,
    /// ENOSPC: The limit on the nesting depth or number of a resource
    /// (e.g., PID or user namespaces) would be exceeded.
    NoSpace,
    /// EPERM: The caller does not have the required privileges (CAP_SYS_ADMIN)
    /// for the requested namespace operation, or is in a chroot.
    PermissionDenied,
    /// EUSERS: (Linux 3.11-4.8) User namespace limit was exceeded. Now reported as ENOSPC.
    UserLimitExceeded,
} || posix.UnexpectedError;

/// Wraps the raw `unshare` syscall to return a typed `UnshareError`.
pub fn unshare(flags: u32) UnshareError!void {
    const rc = linux.unshare(@intCast(flags));
    if (rc != 0) {
        return switch (posix.errno(rc)) {
            .INVAL => error.InvalidValue,
            .NOMEM => error.NoMemory,
            .NOSPC => error.NoSpace,
            .PERM => error.PermissionDenied,
            .USERS => error.UserLimitExceeded,
            else => |e| posix.unexpectedErrno(e),
        };
    }
}

/// A comprehensive, typed error set for the clone(2) syscall, based on the man page.
pub const CloneError = error{
    /// EACCES: (clone3 only) Invalid cgroup permissions.
    Access,
    /// EAGAIN: Too many processes are already running.
    TooManyProcesses,
    /// EBUSY: (clone3 only) Target cgroup has a domain controller enabled.
    Busy,
    /// EEXIST: (clone3 only) A specified PID in set_tid already exists.
    PidExists,
    /// EINVAL: One of many invalid flag combinations or arguments was provided.
    /// Examples: CLONE_SIGHAND without CLONE_VM, CLONE_NEWPID with CLONE_THREAD,
    /// a kernel module for a namespace is not loaded, or stack is misaligned.
    InvalidValue,
    /// ENOMEM: Cannot allocate sufficient memory for the new process.
    NoMemory,
    /// ENOSPC: The limit on the nesting depth or number of a resource
    /// (e.g., PID or user namespaces) would be exceeded.
    NoSpace,
    /// EOPNOTSUPP: (clone3 only) Invalid cgroup state.
    OperationNotSupported,
    /// EPERM: The caller does not have the required privileges (CAP_SYS_ADMIN)
    /// for the requested namespace operation, or is in a chroot.
    PermissionDenied,
    /// ERESTARTNOINTR: System call was interrupted by a signal and will be restarted.
    Interrupted,
    /// EUSERS: (Linux 3.11-4.8) User namespace limit was exceeded. Now reported as ENOSPC.
    UserLimitExceeded,
} || posix.UnexpectedError;

pub fn clone(
    func: *const fn (arg: usize) callconv(.C) u8,
    stack: usize,
    flags: u32,
    arg: usize,
    ptid: ?*c_int,
    tp: usize, // aka tls
    ctid: ?*c_int,
) CloneError!posix.pid_t {
    // The older std lib wrapper returns a usize. We must cast to a signed type
    // to correctly check for negative error codes.
    const rc = linux.clone(func, stack, flags, arg, ptid, tp, ctid);

    return switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => error.Access,
        .AGAIN => error.TooManyProcesses,
        .BUSY => error.Busy,
        .EXIST => error.PidExists,
        .INVAL => error.InvalidValue,
        .NOMEM => error.NoMemory,
        .NOSPC => error.NoSpace,
        .OPNOTSUPP => error.OperationNotSupported,
        .PERM => error.PermissionDenied,
        .RESTART => error.Interrupted,
        .USERS => error.UserLimitExceeded,
        else => |e| posix.unexpectedErrno(e),
    };
}

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
