//! store — the CredStore interface: the only place secrets live. Sites
//! (settings/sites.zig) reference credentials purely by key
//! (protocol, host, port, account); the backing store is the macOS
//! Keychain (keychain.zig) in the macOS app, Secret Service/libsecret in the
//! Linux app, and an in-memory fake (fake.zig) in tests.
//!
//! No io/CancelToken: the backend contract is synchronous and not cancelable,
//! so callers run it on a worker, never the main thread (libsecret may wait
//! for the session service or unlock UI). Diagnostics is still threaded
//! through so native-store context reaches the UI classified; auth failures
//! pause the site.

const std = @import("std");
const Diagnostics = @import("../diag.zig").Diagnostics;

pub const Protocol = enum(u8) { ftp, ftps, sftp };

/// Identity of one stored secret. Slices are borrowed for the duration of
/// the call.
pub const Key = struct {
    protocol: Protocol,
    host: []const u8,
    port: u16,
    account: []const u8,
};

pub const Error = error{
    /// No secret stored under this key (typically prompts the user).
    NotFound,
    /// The store refused access (locked keychain, denied ACL, user hit
    /// "Deny"). Classified .auth in Diagnostics.
    AccessDenied,
    OutOfMemory,
    Unexpected,
};

pub const VTable = struct {
    get: *const fn (ctx: *anyopaque, gpa: std.mem.Allocator, diag: *Diagnostics, key: Key) Error![]u8,
    set: *const fn (ctx: *anyopaque, diag: *Diagnostics, key: Key, secret: []const u8) Error!void,
    delete: *const fn (ctx: *anyopaque, diag: *Diagnostics, key: Key) Error!void,
};

pub const CredStore = struct {
    vtable: *const VTable,
    ctx: *anyopaque,

    /// Returns the secret bytes, owned by the caller. Free with
    /// `freeSecret` so the plaintext is zeroed before release.
    pub fn get(self: CredStore, gpa: std.mem.Allocator, diag: *Diagnostics, key: Key) Error![]u8 {
        return self.vtable.get(self.ctx, gpa, diag, key);
    }

    /// Creates or replaces the secret under `key`.
    pub fn set(self: CredStore, diag: *Diagnostics, key: Key, secret: []const u8) Error!void {
        return self.vtable.set(self.ctx, diag, key, secret);
    }

    pub fn delete(self: CredStore, diag: *Diagnostics, key: Key) Error!void {
        return self.vtable.delete(self.ctx, diag, key);
    }
};

/// Zeroes the plaintext before freeing — secrets must not linger in freed
/// heap pages.
pub fn freeSecret(gpa: std.mem.Allocator, secret: []u8) void {
    std.crypto.secureZero(u8, secret);
    gpa.free(secret);
}

test "freeSecret zeroes before freeing" {
    // testing.allocator would flag a leak if free were skipped; the zeroing
    // itself can't be observed post-free without UB, so this is a smoke
    // check that the call composes.
    const secret = try std.testing.allocator.dupe(u8, "hunter2");
    freeSecret(std.testing.allocator, secret);
}

test {
    std.testing.refAllDecls(@This());
}
