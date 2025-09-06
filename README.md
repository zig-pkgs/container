# Zig Container Module

A lightweight, self-contained Zig module for running functions within an isolated, root-privileged Linux container.

This project provides a powerful way to sandbox parts of a Zig application. It uses Linux namespaces to create an isolated environment and safely escalates privileges *only* within that environment, allowing you to run any Zig function as `root` without the main application needing or having root privileges.

## Core Features

-   **Run Zig Functions in a Sandbox**: Execute any `comptime`-known Zig function directly inside the container, not just external commands.
-   **Rootless Privilege Escalation**: Starts as an unprivileged user and gains root privileges only inside a new, isolated user namespace.
-   **Namespace Isolation**: Creates new User, PID, and Mount namespaces for process and filesystem isolation.
-   **Type-Safe and Compile-Time Checked**: Leverages Zig's `comptime` features to ensure the function to be run is known and valid at compile time.
-   **Zero External Dependencies**: Does not depend on `setuid` helpers like `newuidmap`. The UID/GID mapping is performed directly by the module.

## Motivation

This module is designed for scenarios where a part of a larger Zig application needs to perform privileged operations in an isolated way, such as:
-   Setting up network interfaces.
-   Manipulating filesystem mounts for tests.
-   Running code in a chroot-like environment.
-   Implementing privilege separation within a single application.

By running a Zig function instead of an external process, you avoid the overhead of `exec` and can maintain application state and communication more easily.

## API

The module exposes a single public function, `run`.

**File:** `src/container.zig`
```zig
pub fn run(
    allocator: std.mem.Allocator,
    comptime function: anytype,
    args: anytype,
) !void
```

**Parameters:**

-   `allocator`: A `std.mem.Allocator` used for temporary allocations during the container setup process.
-   `comptime function`: A compile-time known function pointer. This is the function that will be executed as `root` inside the new container. It must conform to the signature expected by `std.Thread.spawn`.
-   `args`: A `tuple` or anonymous struct containing the arguments that will be passed to the `function`.

## Usage Example

Here is a complete example of how to use the `container` module in your own project.

#### 1. Fetch the module

```
zig fetch --save git+https://github.com/zig-pkgs/container.git
```

#### 2. Add the module to your `build.zig`

Add the `container` module to your executable.

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const container_dep = b.dependency("container", .{
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "my-app",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{
                    .name = "container",
                    .module = container_dep.module("container"),
                },
            },
        }),
    });
    b.installArtifact(exe);
}
```

#### 3. `src/main.zig` (Example Application)

This example defines a function `myContainerizedTask` and runs it inside the container.

```zig
const std = @import("std");
const linux = std.os.linux;
const log = std.log;
const container = @import("container"); // Import the module

/// This function will be executed inside the container.
/// It takes one argument: a struct containing a message.
fn myContainerizedTask(args: struct { message: []const u8 }) void {
    log.info("--- Executing inside container ---", .{});
    log.info("Message from main: {s}", .{args.message});
    log.info("My UID is: {d}", .{linux.getuid()});
    log.info("My PID is: {d}", .{linux.getpid()});
    log.info("--- Finished container task ---", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() != .ok) @panic("mem leak");
    const allocator = gpa.allocator();

    log.info("--- Main application started (UID: {d}) ---", .{linux.getuid()});

    // Define the arguments to pass to our containerized function.
    const task_args = .{
        .message = "Hello from the outside world!",
    };

    // Call the container's run function.
    try container.run(allocator, myContainerizedTask, task_args);

    log.info("--- Main application finished ---", .{});
}
```

#### 4. Running the Example

```sh
$ zig build
$ ./zig-out/bin/my-app
info: --- Main application started (UID: 1000) ---
info: --- Executing inside container ---
info: Message from main: Hello from the outside world!
info: My UID is: 0
info: My PID is: 1
info: --- Finished container task ---
info: --- Main application finished ---
```

## How It Works

The module uses a precise sequence of system calls to create the environment securely:

1.  **Fork Mapper**: The initial process forks a short-lived child process (the "Mapper").
2.  **Unshare**: The initial process calls `unshare()` to move itself into new User, PID, and Mount namespaces.
3.  **Write Maps**: The Mapper process, which is still in the parent namespace, writes the UID/GID mappings to `/proc/<pid>/[ug]id_map` for the initial process. The kernel specifically allows this for an immediate child.
4.  **Sync & Wait**: The initial process waits for the Mapper to finish and exit.
5.  **Fork Worker**: The initial process (now a "Supervisor") forks a final "Worker" process.
6.  **Become Root & Run**: The Worker process, which inherits the fully configured namespaces, successfully calls `setuid(0)` and `setgid(0)`. It then calls `std.Thread.spawn` to execute the user-provided Zig function.
7.  **Supervise**: The Supervisor process waits for the Worker to terminate and then returns, allowing the main application to continue.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
