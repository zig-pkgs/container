pub fn run(gpa: mem.Allocator, comptime function: anytype, args: anytype) !void {
    var flags: u32 = 0;
    flags |= linux.CLONE.NEWUSER;
    flags |= linux.CLONE.NEWPID;
    flags |= linux.CLONE.NEWNS;

    var fd_idmap: posix.fd_t = 0;

    // clear any inherited settings
    var sa: posix.Sigaction = .{
        .flags = 0,
        .handler = .{
            .handler = posix.SIG.DFL,
        },
        .mask = posix.sigemptyset(),
    };
    posix.sigaction(posix.SIG.CHLD, &sa, null);

    const pid_idmap = try mapIdsFromChild(gpa, &fd_idmap);

    try posix_ext.unshare(flags);

    try syncWithChild(fd_idmap, pid_idmap);

    var sigset = posix.sigemptyset();
    var oldsigset = posix.sigemptyset();
    posix.sigaddset(&sigset, posix.SIG.INT);
    posix.sigaddset(&sigset, posix.SIG.TERM);
    posix.sigprocmask(posix.SIG.BLOCK, &sigset, &oldsigset);

    const pid = try posix.fork();
    if (pid == 0) {
        posix.sigprocmask(posix.SIG.SETMASK, &oldsigset, null);
    } else {
        const status = posix.waitpid(pid, 0);
        switch (statusToTerm(status.status)) {
            .Signal => |sig| {
                const term_sig: u8 = @intCast(sig);
                posix.sigaction(term_sig, &sa, null);
                sigset = posix.sigemptyset();
                posix.sigaddset(&sigset, term_sig);
                try posix.kill(linux.getpid(), term_sig);
                return;
            },
            else => return,
        }
    }

    try posix.setuid(0);
    try posix.setgid(0);

    const thread = try Thread.spawn(.{}, function, args);
    defer thread.join();
}

fn syncWithChild(fd: posix.fd_t, pid: posix.pid_t) !void {
    var buf: [8]u8 = undefined;
    var file: std.fs.File = .{ .handle = fd };
    var file_writer = file.writer(&buf);
    const w = &file_writer.interface;
    try w.writeInt(u64, PIPE_SYNC_BYTE, native_endian);
    try w.flush();
    posix.close(fd);
    const status = posix.waitpid(pid, 0);
    switch (statusToTerm(status.status)) {
        .Exited => |code| if (code != 0) return error.MapIdsFailed,
        else => {},
    }
}

fn statusToTerm(status: u32) std.process.Child.Term {
    return if (posix.W.IFEXITED(status))
        .{ .Exited = posix.W.EXITSTATUS(status) }
    else if (posix.W.IFSIGNALED(status))
        .{ .Signal = posix.W.TERMSIG(status) }
    else if (posix.W.IFSTOPPED(status))
        .{ .Stopped = posix.W.STOPSIG(status) }
    else
        .{ .Unknown = status };
}

fn mapIdsExternal(gpa: std.mem.Allocator, pid: posix.pid_t) !void {
    const pid_str = try std.fmt.allocPrint(gpa, "{d}", .{pid});
    defer gpa.free(pid_str);

    var uid_list = try RangeList.init(gpa, .uid, pid_str);
    defer uid_list.deinit(gpa);
    var gid_list = try RangeList.init(gpa, .gid, pid_str);
    defer gid_list.deinit(gpa);

    {
        const argv = try uid_list.toArgv(gpa);
        defer {
            for (argv) |arg| gpa.free(arg);
            gpa.free(argv);
        }

        const result = try std.process.Child.run(.{
            .allocator = gpa,
            .argv = argv,
        });
        defer {
            gpa.free(result.stdout);
            gpa.free(result.stderr);
        }
    }

    {
        const argv = try gid_list.toArgv(gpa);
        defer {
            for (argv) |arg| gpa.free(arg);
            gpa.free(argv);
        }

        const result = try std.process.Child.run(.{
            .allocator = gpa,
            .argv = argv,
        });
        defer {
            gpa.free(result.stdout);
            gpa.free(result.stderr);
        }
    }
}

fn mapIdsFromChild(gpa: std.mem.Allocator, fd: *posix.fd_t) !posix.fd_t {
    const ppid = linux.getpid();

    const child = try forkAndWait(fd);
    if (child > 0) return child;

    mapIdsExternal(gpa, ppid) catch |err| {
        log.err("Mapper process failed to write maps: {s}", .{@errorName(err)});
        posix.exit(1);
    };

    posix.exit(0);
}

//  This creates an eventfd and forks. The parent process returns immediately,
//  but the child waits for a `PIPE_SYNC_BYTE` on the eventfd before returning.
//  This allows the parent to perform some tasks before the child starts its
//  work. The parent should call syncWithChild() once it is ready for the
//  child to continue.
fn forkAndWait(fd: *posix.fd_t) !posix.fd_t {
    fd.* = try posix.eventfd(0, 0);
    const child_pid = try posix.fork();
    if (child_pid == 0) {
        var buf: [8]u8 = undefined;
        defer posix.close(fd.*);
        var file: std.fs.File = .{ .handle = fd.* };
        var file_reader = file.reader(&buf);
        const r = &file_reader.interface;
        const ch = try r.takeInt(u64, native_endian);
        if (ch != PIPE_SYNC_BYTE) return error.BadMessage;
    }
    return child_pid;
}

const std = @import("std");
const log = std.log;
const mem = std.mem;
const Thread = std.Thread;
const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();
const linux = std.os.linux;
const posix = std.posix;
const posix_ext = @import("posix_ext.zig");
const testing = std.testing;
const RangeList = @import("RangeList.zig");
const container = @This();

const PIPE_SYNC_BYTE = 0x06;

test {
    _ = RangeList;
    const message = "Hello from the outside world!";

    try container.run(testing.allocator, (struct {
        fn task(msg: []const u8) !void {
            try testing.expectEqualStrings(message, msg);
            try testing.expectEqual(0, linux.getuid());
            try testing.expectEqual(0, linux.getgid());
        }
    }).task, .{message});
}
