//! sftp — SftpClient: the SFTP protocol engine over an authenticated
//! SshSession (session.zig). Speaks vfs currency directly: readdir streams
//! `vfs.Entry` batches into a `vfs.ListingSink`, openRead/openWrite return
//! `vfs.ReadStream`/`vfs.WriteStream`-shaped handles.
//!
//! Every libssh2 call is pumped through poll.zig (non-blocking session,
//! ≤100 ms cancel latency). SSH_FX_* statuses map to classified
//! Diagnostics via `classifyFx` (the table is unit-tested).
//!
//! Read-ahead strategy: libssh2's sftp_read maintains its own pipeline of
//! outstanding SSH_FXP_READ requests sized at `buffer_size * 4`, split
//! into 30000-byte wire chunks (src/sftp.c, MAX_SFTP_READ_SIZE). Handing
//! it our 32 KiB stream buffer per refill therefore keeps ~4 × 32 KiB of
//! reads in flight — the requested depth — without a second pipelining
//! layer on our side. Writes use the mirrored trick: a 128 KiB buffered
//! writer drains in one sftp_write call, which libssh2 splits into
//! pipelined 30000-byte WRITE packets.

const std = @import("std");
const c = @import("c");
const poll = @import("poll.zig");
const session_mod = @import("session.zig");
const SshSession = session_mod.SshSession;
const diag_mod = @import("../../diag.zig");
const Diagnostics = diag_mod.Diagnostics;
const CancelToken = @import("../../cancel.zig").CancelToken;
const vfs = @import("../../vfs/vfs.zig");

const Allocator = std.mem.Allocator;

/// Stream buffer handed to libssh2_sftp_read per refill; libssh2 keeps
/// 4× this amount of READ requests outstanding (see module doc).
pub const read_buffer_len = 32 * 1024;
/// Buffered-writer capacity; drained in one pipelined sftp_write call.
pub const write_buffer_len = 128 * 1024;
/// Entries accumulated before each ListingSink.batch call.
pub const listing_batch_len = 64;
/// Longest single file name accepted from readdir.
pub const max_name_len = 1024;

pub const Caps: vfs.Caps = .{
    .resume_read = true,
    .resume_write = true,
    .atomic_rename = true,
    .chmod = true,
    .symlinks = true,
    .mtime_set = false, // engine support deferred; protocol allows it
    .server_search = false,
    .case_sensitive = null,
};

// ---------------------------------------------------------------------------
// SSH_FX_* -> vfs error + retry class (pure; unit-tested)
// ---------------------------------------------------------------------------

pub const FxMapping = struct {
    err: vfs.Error,
    class: diag_mod.ErrorClass,
};

pub fn classifyFx(fx: u64) FxMapping {
    return switch (fx) {
        c.LIBSSH2_FX_NO_SUCH_FILE,
        c.LIBSSH2_FX_NO_SUCH_PATH,
        c.LIBSSH2_FX_INVALID_FILENAME,
        => .{ .err = error.NotFound, .class = .permanent },
        c.LIBSSH2_FX_PERMISSION_DENIED,
        c.LIBSSH2_FX_WRITE_PROTECT,
        => .{ .err = error.PermissionDenied, .class = .permanent },
        c.LIBSSH2_FX_FILE_ALREADY_EXISTS => .{ .err = error.AlreadyExists, .class = .permanent },
        c.LIBSSH2_FX_NOT_A_DIRECTORY => .{ .err = error.NotADirectory, .class = .permanent },
        c.LIBSSH2_FX_OP_UNSUPPORTED => .{ .err = error.NotSupported, .class = .permanent },
        c.LIBSSH2_FX_BAD_MESSAGE => .{ .err = error.ProtocolViolation, .class = .permanent },
        c.LIBSSH2_FX_NO_CONNECTION,
        c.LIBSSH2_FX_CONNECTION_LOST,
        => .{ .err = error.ConnectionLost, .class = .transient },
        // Contended locks clear on retry; everything else server-side
        // (FAILURE, quota, no-media, loops, non-empty dirs) is permanent
        // until the user changes something.
        c.LIBSSH2_FX_LOCK_CONFLICT => .{ .err = error.Unexpected, .class = .transient },
        else => .{ .err = error.Unexpected, .class = .permanent },
    };
}

/// Human-readable SSH_FX name for diagnostics.
pub fn fxName(fx: u64) []const u8 {
    return switch (fx) {
        c.LIBSSH2_FX_OK => "OK",
        c.LIBSSH2_FX_EOF => "EOF",
        c.LIBSSH2_FX_NO_SUCH_FILE => "no such file",
        c.LIBSSH2_FX_PERMISSION_DENIED => "permission denied",
        c.LIBSSH2_FX_FAILURE => "server failure",
        c.LIBSSH2_FX_BAD_MESSAGE => "bad message",
        c.LIBSSH2_FX_NO_CONNECTION => "no connection",
        c.LIBSSH2_FX_CONNECTION_LOST => "connection lost",
        c.LIBSSH2_FX_OP_UNSUPPORTED => "operation unsupported",
        c.LIBSSH2_FX_INVALID_HANDLE => "invalid handle",
        c.LIBSSH2_FX_NO_SUCH_PATH => "no such path",
        c.LIBSSH2_FX_FILE_ALREADY_EXISTS => "file already exists",
        c.LIBSSH2_FX_WRITE_PROTECT => "write protected",
        c.LIBSSH2_FX_NO_MEDIA => "no media",
        c.LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM => "no space on filesystem",
        c.LIBSSH2_FX_QUOTA_EXCEEDED => "quota exceeded",
        c.LIBSSH2_FX_UNKNOWN_PRINCIPAL => "unknown principal",
        c.LIBSSH2_FX_LOCK_CONFLICT => "lock conflict",
        c.LIBSSH2_FX_DIR_NOT_EMPTY => "directory not empty",
        c.LIBSSH2_FX_NOT_A_DIRECTORY => "not a directory",
        c.LIBSSH2_FX_INVALID_FILENAME => "invalid filename",
        c.LIBSSH2_FX_LINK_LOOP => "link loop",
        else => "unknown status",
    };
}

// ---------------------------------------------------------------------------
// Attribute conversion (pure; unit-tested)
// ---------------------------------------------------------------------------

/// Numeric attributes as the protocol reports them; the vfs backend
/// formats names/owners as it builds snapshot entries.
pub const Attrs = struct {
    kind: vfs.EntryKind = .unknown,
    size: ?u64 = null,
    mode: ?u16 = null,
    mtime: ?i64 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
};

pub fn attrsFromC(a: *const c.LIBSSH2_SFTP_ATTRIBUTES) Attrs {
    var out: Attrs = .{};
    if (a.flags & c.LIBSSH2_SFTP_ATTR_SIZE != 0) out.size = a.filesize;
    if (a.flags & c.LIBSSH2_SFTP_ATTR_ACMODTIME != 0) out.mtime = @intCast(a.mtime);
    if (a.flags & c.LIBSSH2_SFTP_ATTR_UIDGID != 0) {
        out.uid = @truncate(a.uid);
        out.gid = @truncate(a.gid);
    }
    if (a.flags & c.LIBSSH2_SFTP_ATTR_PERMISSIONS != 0) {
        out.mode = @truncate(a.permissions & 0o7777);
        out.kind = switch (a.permissions & c.LIBSSH2_SFTP_S_IFMT) {
            c.LIBSSH2_SFTP_S_IFREG => .file,
            c.LIBSSH2_SFTP_S_IFDIR => .dir,
            c.LIBSSH2_SFTP_S_IFLNK => .symlink,
            c.LIBSSH2_SFTP_S_IFIFO,
            c.LIBSSH2_SFTP_S_IFCHR,
            c.LIBSSH2_SFTP_S_IFBLK,
            c.LIBSSH2_SFTP_S_IFSOCK,
            => .special,
            else => .unknown,
        };
    }
    return out;
}

/// Builds an arena-owned vfs.Entry: `name` is duped, uid/gid are formatted
/// as owner/group strings (SFTPv3 carries no names).
pub fn entryFromAttrs(
    arena: Allocator,
    name: []const u8,
    attrs: Attrs,
) error{OutOfMemory}!vfs.Entry {
    return .{
        .name = try arena.dupe(u8, name),
        .kind = attrs.kind,
        .size = attrs.size,
        .mode = attrs.mode,
        .mtime = attrs.mtime,
        .owner = if (attrs.uid) |uid| try std.fmt.allocPrint(arena, "{d}", .{uid}) else null,
        .group = if (attrs.gid) |gid| try std.fmt.allocPrint(arena, "{d}", .{gid}) else null,
    };
}

fn openFlagsForMode(mode: vfs.OpenMode) c_ulong {
    return switch (mode) {
        .create_truncate => c.LIBSSH2_FXF_WRITE | c.LIBSSH2_FXF_CREAT | c.LIBSSH2_FXF_TRUNC,
        .create_resume => c.LIBSSH2_FXF_WRITE | c.LIBSSH2_FXF_CREAT,
        .append => c.LIBSSH2_FXF_WRITE | c.LIBSSH2_FXF_CREAT | c.LIBSSH2_FXF_APPEND,
    };
}

// ---------------------------------------------------------------------------
// SftpClient
// ---------------------------------------------------------------------------

pub const SftpClient = struct {
    session: *SshSession,
    sftp: *c.LIBSSH2_SFTP,

    pub fn init(session: *SshSession, cancel: *CancelToken, diag: *Diagnostics) vfs.Error!SftpClient {
        const Op = struct {
            s: *SshSession,

            pub fn call(op: @This()) ?*c.LIBSSH2_SFTP {
                return c.libssh2_sftp_init(op.s.handle);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.s.handle);
            }
            pub fn lastErrno(op: @This()) c_int {
                return c.libssh2_session_last_errno(op.s.handle);
            }
        };
        const maybe = poll.pumpHandle(session.fd, cancel, Op{ .s = session }) catch |err|
            return pumpError(err, diag);
        const sftp = maybe orelse {
            var buf: [256]u8 = undefined;
            const rc = c.libssh2_session_last_errno(session.handle);
            diag.set(.permanent, 0, "SFTP subsystem init failed (rc {d}): {s}", .{
                rc, session_mod.LibSsh2.lastErrorMessage(session.handle, &buf),
            });
            return error.ProtocolViolation;
        };
        return .{ .session = session, .sftp = sftp };
    }

    /// Best-effort shutdown of the SFTP channel; the SSH session stays
    /// usable. Bounded — never blocks teardown.
    pub fn deinit(self: *SftpClient) void {
        var token: CancelToken = .{};
        const Op = struct {
            client: *const SftpClient,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_shutdown(op.client.sftp);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        _ = poll.pumpBounded(self.session.fd, &token, Op{ .client = self }, 5) catch {};
        self.* = undefined;
    }

    // -- directory listing --------------------------------------------------

    /// Streams the directory into `sink` in batches of up to
    /// `listing_batch_len` entries. "." and ".." are skipped. Entry slices
    /// are owned by `arena` (the caller's snapshot arena).
    pub fn readdir(
        self: *SftpClient,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        arena: Allocator,
        sink: vfs.ListingSink,
    ) vfs.Error!void {
        const handle = try self.openHandle(cancel, diag, path, 0, 0, c.LIBSSH2_SFTP_OPENDIR);
        defer self.closeHandleQuiet(handle);

        var batch: [listing_batch_len]vfs.Entry = undefined;
        var n: usize = 0;
        var name_buf: [max_name_len]u8 = undefined;
        while (true) {
            try checkCancel(cancel, diag);
            var attrs: c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
            const Op = struct {
                client: *const SftpClient,
                handle: *c.LIBSSH2_SFTP_HANDLE,
                buf: []u8,
                attrs: *c.LIBSSH2_SFTP_ATTRIBUTES,

                pub fn call(op: @This()) c_int {
                    return c.libssh2_sftp_readdir_ex(op.handle, op.buf.ptr, op.buf.len, null, 0, op.attrs);
                }
                pub fn directions(op: @This()) c_int {
                    return c.libssh2_session_block_directions(op.client.session.handle);
                }
            };
            const rc = poll.pump(self.session.fd, cancel, Op{
                .client = self,
                .handle = handle,
                .buf = &name_buf,
                .attrs = &attrs,
            }) catch |err| return pumpError(err, diag);
            if (rc == 0) break; // end of directory
            if (rc < 0) return self.mapRc(rc, diag, "readdir", path);

            const name = name_buf[0..@intCast(rc)];
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            batch[n] = try entryFromAttrs(arena, name, attrsFromC(&attrs));
            n += 1;
            if (n == batch.len) {
                sink.batch(batch[0..n]);
                n = 0;
            }
        }
        if (n > 0) sink.batch(batch[0..n]);
    }

    // -- file streams ---------------------------------------------------

    /// Opens `path` for reading at `offset`. `cancel` and `diag` must
    /// outlive the returned stream (they classify mid-transfer failures;
    /// the queue engine owns both for the transfer's duration).
    pub fn openRead(
        self: *SftpClient,
        gpa: Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        offset: u64,
    ) vfs.Error!vfs.ReadStream {
        const handle = try self.openHandle(cancel, diag, path, c.LIBSSH2_FXF_READ, 0, c.LIBSSH2_SFTP_OPENFILE);
        errdefer self.closeHandleQuiet(handle);
        if (offset > 0) c.libssh2_sftp_seek64(handle, offset);

        const ctx = gpa.create(ReadCtx) catch return error.OutOfMemory;
        ctx.* = .{
            .client = self,
            .handle = handle,
            .gpa = gpa,
            .cancel = cancel,
            .diag = diag,
            .interface = .{
                .vtable = &.{ .stream = ReadCtx.stream },
                .buffer = &ctx.buffer,
                .seek = 0,
                .end = 0,
            },
            .buffer = undefined,
        };
        return .{
            .reader = &ctx.interface,
            .context = ctx,
            .closeFn = ReadCtx.close,
        };
    }

    const ReadCtx = struct {
        client: *SftpClient,
        handle: *c.LIBSSH2_SFTP_HANDLE,
        gpa: Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        interface: std.Io.Reader,
        buffer: [read_buffer_len]u8,

        /// One pumped sftp_read directly into `w`'s writable space. On the
        /// buffered path that space IS the reader's 32 KiB buffer
        /// (defaultReadVec hands us a Writer over r.buffer), which is what
        /// sizes libssh2's internal 4× read-ahead — see module doc. The
        /// impl must never touch r.seek/r.end itself: the caller owns that
        /// bookkeeping.
        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const ctx: *ReadCtx = @alignCast(@fieldParentPtr("interface", r));
            const dest = limit.slice(try w.writableSliceGreedy(1));
            const Op = struct {
                ctx: *ReadCtx,
                dest: []u8,

                pub fn call(op: @This()) isize {
                    return c.libssh2_sftp_read(op.ctx.handle, op.dest.ptr, op.dest.len);
                }
                pub fn directions(op: @This()) c_int {
                    return c.libssh2_session_block_directions(op.ctx.client.session.handle);
                }
            };
            const rc = poll.pump(ctx.client.session.fd, ctx.cancel, Op{ .ctx = ctx, .dest = dest }) catch |err| {
                swallow(pumpError(err, ctx.diag));
                return error.ReadFailed;
            };
            if (rc == 0) return error.EndOfStream;
            if (rc < 0) {
                swallow(ctx.client.mapRc(@intCast(rc), ctx.diag, "read", ""));
                return error.ReadFailed;
            }
            const got: usize = @intCast(rc);
            w.advance(got);
            return got;
        }

        fn close(context: *anyopaque, io: std.Io) void {
            _ = io;
            const ctx: *ReadCtx = @ptrCast(@alignCast(context));
            ctx.client.closeHandleQuiet(ctx.handle);
            const gpa = ctx.gpa;
            gpa.destroy(ctx);
        }
    };

    /// Opens `path` for writing (0644 on create). For `.create_resume`
    /// and `.append` the stream position is set to `offset`. Same
    /// lifetime contract as openRead for `cancel`/`diag`.
    pub fn openWrite(
        self: *SftpClient,
        gpa: Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        offset: u64,
        mode: vfs.OpenMode,
    ) vfs.Error!vfs.WriteStream {
        const handle = try self.openHandle(
            cancel,
            diag,
            path,
            openFlagsForMode(mode),
            0o644,
            c.LIBSSH2_SFTP_OPENFILE,
        );
        errdefer self.closeHandleQuiet(handle);
        if (mode != .create_truncate and offset > 0) c.libssh2_sftp_seek64(handle, offset);

        const ctx = gpa.create(WriteCtx) catch return error.OutOfMemory;
        ctx.* = .{
            .client = self,
            .handle = handle,
            .gpa = gpa,
            .cancel = cancel,
            .diag = diag,
            .interface = .{
                .vtable = &.{ .drain = WriteCtx.drain },
                .buffer = &ctx.buffer,
            },
            .buffer = undefined,
        };
        return .{
            .writer = &ctx.interface,
            .context = ctx,
            .closeFn = WriteCtx.close,
        };
    }

    const WriteCtx = struct {
        client: *SftpClient,
        handle: *c.LIBSSH2_SFTP_HANDLE,
        gpa: Allocator,
        cancel: *CancelToken,
        diag: *Diagnostics,
        interface: std.Io.Writer,
        buffer: [write_buffer_len]u8,

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const ctx: *WriteCtx = @alignCast(@fieldParentPtr("interface", w));
            const buffered = w.buffered();
            if (buffered.len > 0) try ctx.writeAll(buffered);
            w.end = 0;

            var consumed: usize = 0;
            if (data.len > 0) {
                for (data[0 .. data.len - 1]) |slice| {
                    try ctx.writeAll(slice);
                    consumed += slice.len;
                }
                const last = data[data.len - 1];
                for (0..splat) |_| {
                    try ctx.writeAll(last);
                    consumed += last.len;
                }
            }
            return consumed;
        }

        /// libssh2_sftp_write may accept only part of the buffer (it
        /// pipelines 30000-byte WRITE packets internally); keep feeding
        /// the remainder of the SAME data until everything is taken.
        fn writeAll(ctx: *WriteCtx, bytes: []const u8) std.Io.Writer.Error!void {
            var rest = bytes;
            while (rest.len > 0) {
                const Op = struct {
                    ctx: *WriteCtx,
                    rest: []const u8,

                    pub fn call(op: @This()) isize {
                        return c.libssh2_sftp_write(op.ctx.handle, op.rest.ptr, op.rest.len);
                    }
                    pub fn directions(op: @This()) c_int {
                        return c.libssh2_session_block_directions(op.ctx.client.session.handle);
                    }
                };
                const rc = poll.pump(ctx.client.session.fd, ctx.cancel, Op{ .ctx = ctx, .rest = rest }) catch |err| {
                    swallow(pumpError(err, ctx.diag));
                    return error.WriteFailed;
                };
                if (rc < 0) {
                    swallow(ctx.client.mapRc(@intCast(rc), ctx.diag, "write", ""));
                    return error.WriteFailed;
                }
                rest = rest[@intCast(rc)..];
            }
        }

        fn close(context: *anyopaque, io: std.Io) vfs.Error!void {
            _ = io;
            const ctx: *WriteCtx = @ptrCast(@alignCast(context));
            const gpa = ctx.gpa;
            defer gpa.destroy(ctx);

            const flush_failed = blk: {
                ctx.interface.flush() catch break :blk true;
                break :blk false;
            };
            // Close the handle even when the flush failed; a pumped close
            // surfaces server-side errors for the success path.
            const Op = struct {
                ctx: *WriteCtx,

                pub fn call(op: @This()) c_int {
                    return c.libssh2_sftp_close_handle(op.ctx.handle);
                }
                pub fn directions(op: @This()) c_int {
                    return c.libssh2_session_block_directions(op.ctx.client.session.handle);
                }
            };
            const rc = poll.pump(ctx.client.session.fd, ctx.cancel, Op{ .ctx = ctx }) catch |err| {
                if (flush_failed) return diagToError(ctx.diag);
                return pumpError(err, ctx.diag);
            };
            if (flush_failed) return diagToError(ctx.diag);
            if (rc < 0) return ctx.client.mapRc(rc, ctx.diag, "close", "");
        }
    };

    // -- metadata operations ----------------------------------------------

    pub fn stat(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) vfs.Error!Attrs {
        var attrs: c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
        const rc = try self.statRc(cancel, diag, path, c.LIBSSH2_SFTP_STAT, &attrs);
        if (rc < 0) return self.mapRc(rc, diag, "stat", path);
        return attrsFromC(&attrs);
    }

    /// lstat: attributes of the link itself.
    pub fn lstat(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) vfs.Error!Attrs {
        var attrs: c.LIBSSH2_SFTP_ATTRIBUTES = undefined;
        const rc = try self.statRc(cancel, diag, path, c.LIBSSH2_SFTP_LSTAT, &attrs);
        if (rc < 0) return self.mapRc(rc, diag, "lstat", path);
        return attrsFromC(&attrs);
    }

    pub fn chmod(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8, mode: u16) vfs.Error!void {
        var attrs: c.LIBSSH2_SFTP_ATTRIBUTES = std.mem.zeroes(c.LIBSSH2_SFTP_ATTRIBUTES);
        attrs.flags = c.LIBSSH2_SFTP_ATTR_PERMISSIONS;
        attrs.permissions = mode;
        const rc = try self.statRc(cancel, diag, path, c.LIBSSH2_SFTP_SETSTAT, &attrs);
        if (rc < 0) return self.mapRc(rc, diag, "chmod", path);
    }

    fn statRc(
        self: *SftpClient,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        stat_type: c_int,
        attrs: *c.LIBSSH2_SFTP_ATTRIBUTES,
    ) vfs.Error!c_int {
        const Op = struct {
            client: *const SftpClient,
            path: []const u8,
            stat_type: c_int,
            attrs: *c.LIBSSH2_SFTP_ATTRIBUTES,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_stat_ex(op.client.sftp, op.path.ptr, @intCast(op.path.len), op.stat_type, op.attrs);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        return poll.pump(self.session.fd, cancel, Op{
            .client = self,
            .path = path,
            .stat_type = stat_type,
            .attrs = attrs,
        }) catch |err| pumpError(err, diag);
    }

    pub fn mkdir(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) vfs.Error!void {
        const Op = struct {
            client: *const SftpClient,
            path: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_mkdir_ex(op.client.sftp, op.path.ptr, @intCast(op.path.len), 0o755);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const rc = poll.pump(self.session.fd, cancel, Op{ .client = self, .path = path }) catch |err|
            return pumpError(err, diag);
        if (rc < 0) return self.mapRc(rc, diag, "mkdir", path);
    }

    pub fn rmdir(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) vfs.Error!void {
        const Op = struct {
            client: *const SftpClient,
            path: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_rmdir_ex(op.client.sftp, op.path.ptr, @intCast(op.path.len));
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const rc = poll.pump(self.session.fd, cancel, Op{ .client = self, .path = path }) catch |err|
            return pumpError(err, diag);
        if (rc < 0) return self.mapRc(rc, diag, "rmdir", path);
    }

    pub fn unlink(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8) vfs.Error!void {
        const Op = struct {
            client: *const SftpClient,
            path: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_unlink_ex(op.client.sftp, op.path.ptr, @intCast(op.path.len));
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const rc = poll.pump(self.session.fd, cancel, Op{ .client = self, .path = path }) catch |err|
            return pumpError(err, diag);
        if (rc < 0) return self.mapRc(rc, diag, "unlink", path);
    }

    /// posix-rename@openssh.com (atomic overwrite) when the server
    /// supports it, otherwise SSH_FXP_RENAME with overwrite/atomic/native
    /// flags.
    pub fn rename(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, from: []const u8, to: []const u8) vfs.Error!void {
        const PosixOp = struct {
            client: *const SftpClient,
            from: []const u8,
            to: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_posix_rename_ex(op.client.sftp, op.from.ptr, op.from.len, op.to.ptr, op.to.len);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const prc = poll.pump(self.session.fd, cancel, PosixOp{ .client = self, .from = from, .to = to }) catch |err|
            return pumpError(err, diag);
        if (prc == 0) return;
        // Server without the extension: libssh2 fails locally with the
        // (positive) LIBSSH2_FX_OP_UNSUPPORTED code — fall back.
        if (prc != c.LIBSSH2_FX_OP_UNSUPPORTED) return self.mapRc(prc, diag, "rename", from);

        const Op = struct {
            client: *const SftpClient,
            from: []const u8,
            to: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_rename_ex(
                    op.client.sftp,
                    op.from.ptr,
                    @intCast(op.from.len),
                    op.to.ptr,
                    @intCast(op.to.len),
                    c.LIBSSH2_SFTP_RENAME_OVERWRITE | c.LIBSSH2_SFTP_RENAME_ATOMIC | c.LIBSSH2_SFTP_RENAME_NATIVE,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const rc = poll.pump(self.session.fd, cancel, Op{ .client = self, .from = from, .to = to }) catch |err|
            return pumpError(err, diag);
        if (rc < 0) return self.mapRc(rc, diag, "rename", from);
    }

    /// Creates `link_path` pointing at `target`. Argument order on the
    /// wire follows OpenSSH's (reversed-from-draft) SSH_FXP_SYMLINK
    /// convention, which is what libssh2 emits and every mainstream
    /// server expects.
    pub fn symlink(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, target: []const u8, link_path: []const u8) vfs.Error!void {
        const Op = struct {
            client: *const SftpClient,
            target: []const u8,
            link_path: []const u8,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_symlink_ex(
                    op.client.sftp,
                    op.target.ptr,
                    @intCast(op.target.len),
                    // not written through for SYMLINK; non-const in the C
                    // prototype only because READLINK/REALPATH share it
                    @constCast(op.link_path.ptr),
                    @intCast(op.link_path.len),
                    c.LIBSSH2_SFTP_SYMLINK,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const rc = poll.pump(self.session.fd, cancel, Op{ .client = self, .target = target, .link_path = link_path }) catch |err|
            return pumpError(err, diag);
        if (rc < 0) return self.mapRc(rc, diag, "symlink", link_path);
    }

    pub fn readlink(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8, buf: []u8) vfs.Error![]const u8 {
        return self.linkQuery(cancel, diag, path, buf, c.LIBSSH2_SFTP_READLINK, "readlink");
    }

    pub fn realpath(self: *SftpClient, cancel: *CancelToken, diag: *Diagnostics, path: []const u8, buf: []u8) vfs.Error![]const u8 {
        return self.linkQuery(cancel, diag, path, buf, c.LIBSSH2_SFTP_REALPATH, "realpath");
    }

    fn linkQuery(
        self: *SftpClient,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        buf: []u8,
        link_type: c_int,
        what: []const u8,
    ) vfs.Error![]const u8 {
        const Op = struct {
            client: *const SftpClient,
            path: []const u8,
            buf: []u8,
            link_type: c_int,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_symlink_ex(
                    op.client.sftp,
                    op.path.ptr,
                    @intCast(op.path.len),
                    op.buf.ptr,
                    @intCast(op.buf.len),
                    op.link_type,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        const rc = poll.pump(self.session.fd, cancel, Op{
            .client = self,
            .path = path,
            .buf = buf,
            .link_type = link_type,
        }) catch |err| return pumpError(err, diag);
        if (rc < 0) return self.mapRc(rc, diag, what, path);
        return buf[0..@intCast(rc)];
    }

    // -- shared plumbing ----------------------------------------------------

    fn openHandle(
        self: *SftpClient,
        cancel: *CancelToken,
        diag: *Diagnostics,
        path: []const u8,
        flags: c_ulong,
        mode: c_long,
        open_type: c_int,
    ) vfs.Error!*c.LIBSSH2_SFTP_HANDLE {
        const Op = struct {
            client: *const SftpClient,
            path: []const u8,
            flags: c_ulong,
            mode: c_long,
            open_type: c_int,

            pub fn call(op: @This()) ?*c.LIBSSH2_SFTP_HANDLE {
                return c.libssh2_sftp_open_ex(
                    op.client.sftp,
                    op.path.ptr,
                    @intCast(op.path.len),
                    op.flags,
                    op.mode,
                    op.open_type,
                );
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
            pub fn lastErrno(op: @This()) c_int {
                return c.libssh2_session_last_errno(op.client.session.handle);
            }
        };
        const maybe = poll.pumpHandle(self.session.fd, cancel, Op{
            .client = self,
            .path = path,
            .flags = flags,
            .mode = mode,
            .open_type = open_type,
        }) catch |err| return pumpError(err, diag);
        return maybe orelse self.mapRc(c.libssh2_session_last_errno(self.session.handle), diag, "open", path);
    }

    /// Cleanup-path close: bounded, errors swallowed (the operation's
    /// real error has already been reported).
    fn closeHandleQuiet(self: *SftpClient, handle: *c.LIBSSH2_SFTP_HANDLE) void {
        var token: CancelToken = .{};
        const Op = struct {
            client: *const SftpClient,
            handle: *c.LIBSSH2_SFTP_HANDLE,

            pub fn call(op: @This()) c_int {
                return c.libssh2_sftp_close_handle(op.handle);
            }
            pub fn directions(op: @This()) c_int {
                return c.libssh2_session_block_directions(op.client.session.handle);
            }
        };
        _ = poll.pumpBounded(self.session.fd, &token, Op{ .client = self, .handle = handle }, 5) catch {};
    }

    /// Maps a non-zero libssh2 rc to a classified vfs error. SFTP-status
    /// failures consult libssh2_sftp_last_error; transport failures reuse
    /// the session-level classification.
    fn mapRc(self: *const SftpClient, rc: c_int, diag: *Diagnostics, what: []const u8, path: []const u8) vfs.Error {
        if (rc == c.LIBSSH2_ERROR_SFTP_PROTOCOL) {
            const fx: u64 = @intCast(c.libssh2_sftp_last_error(self.sftp));
            const m = classifyFx(fx);
            diag.set(m.class, @truncate(fx), "{s} {s}: {s} (SSH_FX {d})", .{ what, path, fxName(fx), fx });
            return m.err;
        }
        // posix_rename's "extension unsupported" local error arrives as a
        // positive SSH_FX code.
        if (rc > 0) {
            const m = classifyFx(@intCast(rc));
            diag.set(m.class, @intCast(rc), "{s} {s}: {s}", .{ what, path, fxName(@intCast(rc)) });
            return m.err;
        }
        var buf: [256]u8 = undefined;
        const msg = session_mod.LibSsh2.lastErrorMessage(self.session.handle, &buf);
        const cls = session_mod.classifyLibRc(rc);
        diag.set(cls.class, 0, "{s} {s} failed (rc {d}): {s}", .{ what, path, rc, msg });
        return switch (cls.fatal orelse error.Unexpected) {
            error.ConnectionLost => error.ConnectionLost,
            error.Timeout => error.Timeout,
            error.OutOfMemory => error.OutOfMemory,
            error.ProtocolViolation => error.ProtocolViolation,
            else => error.Unexpected,
        };
    }
};

fn checkCancel(cancel: *const CancelToken, diag: *Diagnostics) vfs.Error!void {
    cancel.check() catch {
        diag.set(.cancel, 0, "canceled", .{});
        return error.Canceled;
    };
}

/// The stream vtables must report Read/WriteFailed; the classified vfs
/// error's only job there is filling diag, so its value is swallowed.
fn swallow(_: vfs.Error) void {}

fn pumpError(err: poll.Error, diag: *Diagnostics) vfs.Error {
    switch (err) {
        error.Canceled => {
            diag.set(.cancel, 0, "canceled", .{});
            return error.Canceled;
        },
        error.ConnectionLost => {
            diag.set(.transient, 0, "connection lost while waiting on socket", .{});
            return error.ConnectionLost;
        },
    }
}

/// Recovers the vfs error class for a WriteStream close after the flush
/// already filled `diag`.
fn diagToError(diag: *const Diagnostics) vfs.Error {
    return switch (diag.class) {
        .cancel => error.Canceled,
        .transient => error.ConnectionLost,
        else => error.Unexpected,
    };
}

// ---------------------------------------------------------------------------
// Unit tests (pure mapping/conversion logic)
// ---------------------------------------------------------------------------

const t = std.testing;

test "SSH_FX_* -> vfs error mapping table" {
    const cases = [_]struct { fx: u64, err: vfs.Error, class: diag_mod.ErrorClass }{
        .{ .fx = c.LIBSSH2_FX_NO_SUCH_FILE, .err = error.NotFound, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_NO_SUCH_PATH, .err = error.NotFound, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_INVALID_FILENAME, .err = error.NotFound, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_PERMISSION_DENIED, .err = error.PermissionDenied, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_WRITE_PROTECT, .err = error.PermissionDenied, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_FILE_ALREADY_EXISTS, .err = error.AlreadyExists, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_NOT_A_DIRECTORY, .err = error.NotADirectory, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_OP_UNSUPPORTED, .err = error.NotSupported, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_BAD_MESSAGE, .err = error.ProtocolViolation, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_NO_CONNECTION, .err = error.ConnectionLost, .class = .transient },
        .{ .fx = c.LIBSSH2_FX_CONNECTION_LOST, .err = error.ConnectionLost, .class = .transient },
        .{ .fx = c.LIBSSH2_FX_LOCK_CONFLICT, .err = error.Unexpected, .class = .transient },
        .{ .fx = c.LIBSSH2_FX_FAILURE, .err = error.Unexpected, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM, .err = error.Unexpected, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_QUOTA_EXCEEDED, .err = error.Unexpected, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_DIR_NOT_EMPTY, .err = error.Unexpected, .class = .permanent },
        .{ .fx = c.LIBSSH2_FX_LINK_LOOP, .err = error.Unexpected, .class = .permanent },
        .{ .fx = 999, .err = error.Unexpected, .class = .permanent },
    };
    for (cases) |case| {
        const m = classifyFx(case.fx);
        try t.expectEqual(case.err, m.err);
        try t.expectEqual(case.class, m.class);
    }
}

test "attrsFromC honors validity flags and IFMT bits" {
    var a: c.LIBSSH2_SFTP_ATTRIBUTES = std.mem.zeroes(c.LIBSSH2_SFTP_ATTRIBUTES);

    // nothing valid -> all unknown
    try t.expectEqual(Attrs{}, attrsFromC(&a));

    a.flags = c.LIBSSH2_SFTP_ATTR_SIZE | c.LIBSSH2_SFTP_ATTR_PERMISSIONS |
        c.LIBSSH2_SFTP_ATTR_ACMODTIME | c.LIBSSH2_SFTP_ATTR_UIDGID;
    a.filesize = 10 * 1024 * 1024;
    a.permissions = c.LIBSSH2_SFTP_S_IFREG | 0o644;
    a.mtime = 1_700_000_000;
    a.uid = 1001;
    a.gid = 100;
    const file = attrsFromC(&a);
    try t.expectEqual(vfs.EntryKind.file, file.kind);
    try t.expectEqual(@as(?u64, 10 * 1024 * 1024), file.size);
    try t.expectEqual(@as(?u16, 0o644), file.mode);
    try t.expectEqual(@as(?i64, 1_700_000_000), file.mtime);
    try t.expectEqual(@as(?u32, 1001), file.uid);
    try t.expectEqual(@as(?u32, 100), file.gid);

    a.permissions = c.LIBSSH2_SFTP_S_IFDIR | 0o755;
    try t.expectEqual(vfs.EntryKind.dir, attrsFromC(&a).kind);
    a.permissions = c.LIBSSH2_SFTP_S_IFLNK | 0o777;
    try t.expectEqual(vfs.EntryKind.symlink, attrsFromC(&a).kind);
    a.permissions = c.LIBSSH2_SFTP_S_IFSOCK;
    try t.expectEqual(vfs.EntryKind.special, attrsFromC(&a).kind);
    a.permissions = c.LIBSSH2_SFTP_S_IFCHR;
    try t.expectEqual(vfs.EntryKind.special, attrsFromC(&a).kind);
}

test "entryFromAttrs arena ownership and uid/gid formatting" {
    var arena: std.heap.ArenaAllocator = .init(t.allocator);
    defer arena.deinit();

    const e = try entryFromAttrs(arena.allocator(), "hello.txt", .{
        .kind = .file,
        .size = 5,
        .mode = 0o600,
        .mtime = 42,
        .uid = 501,
        .gid = 20,
    });
    try t.expectEqualStrings("hello.txt", e.name);
    try t.expectEqualStrings("501", e.owner.?);
    try t.expectEqualStrings("20", e.group.?);
    try t.expectEqual(@as(?u64, 5), e.size);

    const bare = try entryFromAttrs(arena.allocator(), "x", .{});
    try t.expectEqual(@as(?[]const u8, null), bare.owner);
    try t.expectEqual(vfs.EntryKind.unknown, bare.kind);
}

test "entryFromAttrs survives allocation failure" {
    const Check = struct {
        fn run(gpa: Allocator) !void {
            var arena: std.heap.ArenaAllocator = .init(gpa);
            defer arena.deinit();
            _ = try entryFromAttrs(arena.allocator(), "name", .{ .uid = 1, .gid = 2 });
        }
    };
    try t.checkAllAllocationFailures(t.allocator, Check.run, .{});
}

test "open flags per vfs mode" {
    try t.expectEqual(
        @as(c_ulong, c.LIBSSH2_FXF_WRITE | c.LIBSSH2_FXF_CREAT | c.LIBSSH2_FXF_TRUNC),
        openFlagsForMode(.create_truncate),
    );
    try t.expectEqual(
        @as(c_ulong, c.LIBSSH2_FXF_WRITE | c.LIBSSH2_FXF_CREAT),
        openFlagsForMode(.create_resume),
    );
    try t.expectEqual(
        @as(c_ulong, c.LIBSSH2_FXF_WRITE | c.LIBSSH2_FXF_CREAT | c.LIBSSH2_FXF_APPEND),
        openFlagsForMode(.append),
    );
}

test {
    std.testing.refAllDecls(@This());
    // Live Docker matrix — opt-in via RELAY_SFTP_LIVE=1 so plain
    // `zig build test` never touches docker or the network.
    _ = @import("live_test.zig");
}
