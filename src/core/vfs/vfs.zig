//! Vfs — the one interface over local filesystem, FTP/FTPS, and SFTP that
//! the pool, queue, and UI compose on. This file is the contract; backends
//! live in local.zig / ftp.zig / sftp.zig and a test double in
//! ../testutil/mock_vfs.zig.
//!
//! Conventions:
//! - Every operation takes `io: std.Io`, a `*CancelToken`, and a
//!   `*Diagnostics` out-param (see ../diag.zig) — errors are classified and
//!   carry server context; the UI never shows bare Zig error names.
//! - `list` STREAMS: the sink receives batches as they parse so the UI can
//!   render the first rows of a 100k-entry directory immediately.
//! - Paths are normalized UTF-8 (see path.zig); per-backend encoding shims
//!   handle legacy servers.

const std = @import("std");
const CancelToken = @import("../cancel.zig").CancelToken;
const diag_mod = @import("../diag.zig");

/// Capability set: drives UI affordances (grey out chmod where the
/// backend can't, hide resume when the server lacks REST, ...).
/// Not `packed`: the tri-state `case_sensitive` (?bool) has no bit-packed
/// representation, and nothing serializes this type.
pub const Caps = struct {
    resume_read: bool = false,
    resume_write: bool = false,
    atomic_rename: bool = false,
    chmod: bool = false,
    symlinks: bool = false,
    mtime_set: bool = false,
    server_search: bool = false,
    /// null = unknown (typical for FTP without TVFS hints)
    case_sensitive: ?bool = null,
};

pub const EntryKind = enum { file, dir, symlink, special, unknown };

/// One directory entry. All slices are arena-owned by the snapshot being
/// built (see snapshot.zig); consumers never free individual entries.
pub const Entry = struct {
    name: []const u8,
    kind: EntryKind = .unknown,
    size: ?u64 = null,
    /// POSIX permission bits where known (e.g. 0o644).
    mode: ?u16 = null,
    /// Seconds since epoch, where known.
    mtime: ?i64 = null,
    owner: ?[]const u8 = null,
    group: ?[]const u8 = null,
    link_target: ?[]const u8 = null,
};

/// Streaming sink for directory listings. `batch` is called repeatedly from
/// the listing worker as entries parse; `done` exactly once afterwards
/// (with the terminal status). Entries' slices are valid only when arena
/// ownership has been transferred via the surrounding DirSnapshot protocol.
pub const ListingSink = struct {
    context: *anyopaque,
    batchFn: *const fn (context: *anyopaque, entries: []const Entry) void,

    pub fn batch(self: ListingSink, entries: []const Entry) void {
        self.batchFn(self.context, entries);
    }
};

pub const OpenMode = enum { create_truncate, create_resume, append };

pub const Error = error{
    Canceled,
    ConnectionLost,
    NotFound,
    PermissionDenied,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    NotSupported,
    ProtocolViolation,
    AuthRequired,
    Timeout,
    OutOfMemory,
    Unexpected,
};

/// Streaming read/write handles. Concrete `std.Io.Reader`/`std.Io.Writer`
/// interfaces so transfers are plain stream pumps regardless of backend.
pub const ReadStream = struct {
    reader: *std.Io.Reader,
    context: *anyopaque,
    closeFn: *const fn (context: *anyopaque, io: std.Io) void,

    pub fn close(self: ReadStream, io: std.Io) void {
        self.closeFn(self.context, io);
    }
};

pub const WriteStream = struct {
    writer: *std.Io.Writer,
    context: *anyopaque,
    /// Close MUST flush; returns error if the final flush fails.
    closeFn: *const fn (context: *anyopaque, io: std.Io) Error!void,

    pub fn close(self: WriteStream, io: std.Io) Error!void {
        return self.closeFn(self.context, io);
    }
};

pub const VTable = struct {
    caps: *const fn (ctx: *anyopaque) Caps,
    /// The backend's default directory, copied into `buf`: the user's home
    /// (local, SFTP realpath ".") or the post-login working directory
    /// (FTP PWD). Used for sites with no configured remote path.
    defaultPath: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, buf: []u8) Error![]const u8,
    stat: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) Error!Entry,
    list: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, arena: std.mem.Allocator, sink: ListingSink) Error!void,
    openRead: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64) Error!ReadStream,
    openWrite: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64, mode: OpenMode) Error!WriteStream,
    mkdir: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) Error!void,
    remove: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, recursive: bool) Error!void,
    rename: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, from: []const u8, to: []const u8) Error!void,
    chmod: *const fn (ctx: *anyopaque, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, mode: u16) Error!void,
};

pub const Vfs = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    pub fn caps(self: Vfs) Caps {
        return self.vtable.caps(self.ctx);
    }
    pub fn defaultPath(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, buf: []u8) Error![]const u8 {
        return self.vtable.defaultPath(self.ctx, io, cancel, diag, buf);
    }
    pub fn stat(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) Error!Entry {
        return self.vtable.stat(self.ctx, io, cancel, diag, path);
    }
    pub fn list(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, arena: std.mem.Allocator, sink: ListingSink) Error!void {
        return self.vtable.list(self.ctx, io, cancel, diag, path, arena, sink);
    }
    pub fn openRead(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64) Error!ReadStream {
        return self.vtable.openRead(self.ctx, io, cancel, diag, path, offset);
    }
    pub fn openWrite(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, offset: u64, mode: OpenMode) Error!WriteStream {
        return self.vtable.openWrite(self.ctx, io, cancel, diag, path, offset, mode);
    }
    pub fn mkdir(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8) Error!void {
        return self.vtable.mkdir(self.ctx, io, cancel, diag, path);
    }
    pub fn remove(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, recursive: bool) Error!void {
        return self.vtable.remove(self.ctx, io, cancel, diag, path, recursive);
    }
    pub fn rename(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, from: []const u8, to: []const u8) Error!void {
        return self.vtable.rename(self.ctx, io, cancel, diag, from, to);
    }
    pub fn chmod(self: Vfs, io: std.Io, cancel: *CancelToken, diag: *diag_mod.Diagnostics, path: []const u8, mode: u16) Error!void {
        return self.vtable.chmod(self.ctx, io, cancel, diag, path, mode);
    }
};

test {
    std.testing.refAllDecls(@This());
}
