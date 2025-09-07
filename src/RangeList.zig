pub const Range = struct {
    range: u32,
    count: u32,

    const default_range: Range = .{
        .range = 100000,
        .count = 65536,
    };

    pub const Kind = enum {
        uid,
        gid,
    };

    pub fn fromConfig(comptime kind: Kind, gpa: mem.Allocator) !Range {
        const real_uid = posix.geteuid();
        const name = try getUsername(gpa, real_uid);
        defer gpa.free(name);

        const path = "/etc/sub" ++ @tagName(kind);

        var buf: [8 * 1024]u8 = undefined;
        var file = try std.fs.openFileAbsolute(path, .{});

        defer file.close();
        var file_reader = file.reader(&buf);
        const reader = &file_reader.interface;
        loop: while (true) {
            const line = reader.takeDelimiterExclusive('\n') catch |err| {
                switch (err) {
                    error.EndOfStream => break :loop,
                    else => |e| return e,
                }
            };
            var it = mem.tokenizeScalar(u8, line, ':');
            const user_name = it.next().?;
            if (mem.eql(u8, name, user_name)) {
                const range = try std.fmt.parseInt(u32, it.next().?, 10);
                const count = try std.fmt.parseInt(u32, it.next().?, 10);
                return .{
                    .range = range,
                    .count = count,
                };
            }
        }
        return default_range;
    }

    fn getUsername(gpa: mem.Allocator, real_uid: posix.uid_t) ![]u8 {
        var buf: [8 * 1024]u8 = undefined;
        var file = try std.fs.openFileAbsolute("/etc/passwd", .{});
        defer file.close();
        var file_reader = file.reader(&buf);
        const reader = &file_reader.interface;
        loop: while (true) {
            const line = reader.takeDelimiterExclusive('\n') catch |err| {
                switch (err) {
                    error.EndOfStream => break :loop,
                    else => |e| return e,
                }
            };
            var it = mem.tokenizeScalar(u8, line, ':');
            const name = it.next().?;
            _ = it.next().?;
            const uid = try std.fmt.parseInt(posix.uid_t, it.next().?, 10);
            if (uid == real_uid) {
                return try gpa.dupe(u8, name);
            }
        }
        return error.CorruptPasswordFile;
    }
};

kind: Range.Kind,
pid_str: []const u8,
range_list: std.ArrayList(Range),

pub fn init(gpa: mem.Allocator, comptime kind: Range.Kind, pid_str: []const u8) !@This() {
    var list: std.ArrayList(Range) = try .initCapacity(gpa, 2);
    errdefer list.deinit(gpa);
    switch (kind) {
        .uid => |t| {
            list.appendAssumeCapacity(.{
                .range = linux.geteuid(),
                .count = 1,
            });
            list.appendAssumeCapacity(try Range.fromConfig(t, gpa));
        },
        .gid => |t| {
            list.appendAssumeCapacity(.{
                .range = linux.getegid(),
                .count = 1,
            });
            list.appendAssumeCapacity(try Range.fromConfig(t, gpa));
        },
    }
    return .{
        .pid_str = pid_str,
        .kind = kind,
        .range_list = list,
    };
}

pub fn deinit(self: *@This(), gpa: mem.Allocator) void {
    self.range_list.deinit(gpa);
}

pub fn toArgv(self: *@This(), gpa: mem.Allocator) ![]const []const u8 {
    const capacity = self.range_list.items.len * 3 + 2;
    var list: std.ArrayList([]const u8) = try .initCapacity(gpa, capacity);
    defer list.deinit(gpa);

    switch (self.kind) {
        .uid => list.appendAssumeCapacity(try gpa.dupe(u8, "newuidmap")),
        .gid => list.appendAssumeCapacity(try gpa.dupe(u8, "newgidmap")),
    }

    list.appendAssumeCapacity(try gpa.dupe(u8, self.pid_str));

    for (self.range_list.items, 0..) |range, i| {
        {
            const arg = try std.fmt.allocPrint(gpa, "{d}", .{
                i,
            });
            list.appendAssumeCapacity(arg);
        }
        {
            const arg = try std.fmt.allocPrint(gpa, "{d}", .{
                range.range,
            });
            list.appendAssumeCapacity(arg);
        }
        {
            const arg = try std.fmt.allocPrint(gpa, "{d}", .{
                range.count,
            });
            list.appendAssumeCapacity(arg);
        }
    }

    return try list.toOwnedSlice(gpa);
}

const std = @import("std");
const mem = std.mem;
const posix = std.posix;
const linux = std.os.linux;
const testing = std.testing;
const RangeList = @This();

test {
    const pid_str = "1234";

    {
        var uid_list = try RangeList.init(testing.allocator, .uid, pid_str);
        defer uid_list.deinit(testing.allocator);
        const argv = try uid_list.toArgv(testing.allocator);
        defer {
            for (argv) |arg| testing.allocator.free(arg);
            testing.allocator.free(argv);
        }
    }

    {
        var gid_list = try RangeList.init(testing.allocator, .gid, pid_str);
        defer gid_list.deinit(testing.allocator);
        const argv = try gid_list.toArgv(testing.allocator);
        defer {
            for (argv) |arg| testing.allocator.free(arg);
            testing.allocator.free(argv);
        }
    }
}
