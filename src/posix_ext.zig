pub const MountError = error{
    Access,
    Busy,
    Fault,
    InvalidValue,
    Loop,
    FileTableOverflow,
    NameTooLong,
    NoDevice,
    NoEntry,
    NoMemory,
    NotBlockDevice,
    NotDirectory,
    NoDeviceOrAddress,
    PermissionDenied,
    ReadOnlyFileSystem,
} || posix.UnexpectedError;

pub fn mountZ(source: [*:0]const u8, target: [*:0]const u8, fstype: ?[*:0]const u8, flags: u32, data: ?[*:0]const u8) MountError!void {
    const rc = linux.mount(source, target, fstype, flags, data);
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

pub const UmountError = error{
    Again,
    Busy,
    Fault,
    InvalidValue,
    NameTooLong,
    NoEntry,
    NoMemory,
    PermissionDenied,
} || posix.UnexpectedError;

pub fn umount2Z(target: [*:0]const u8, flags: u32) UmountError!void {
    const rc = linux.umount2(target, flags);
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
