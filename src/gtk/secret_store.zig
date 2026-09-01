//! Secret Service/libsecret implementation of relay_core's CredStore.

const std = @import("std");
const relay = @import("relay_core");

const store = relay.cred.store;
const Diagnostics = relay.diag.Diagnostics;

pub const SecretStore = struct {
    pub fn credStore(self: *SecretStore) store.CredStore {
        return .{ .ctx = @ptrCast(self), .vtable = &vtable };
    }

    fn get(
        _: *anyopaque,
        gpa: std.mem.Allocator,
        diag: *Diagnostics,
        key: store.Key,
    ) store.Error![]u8 {
        var secret: ?[*:0]u8 = null;
        var secret_len: usize = 0;
        var message: ?[*:0]u8 = null;
        const result = relay_secret_lookup(
            protocolName(key.protocol).ptr,
            protocolName(key.protocol).len,
            key.host.ptr,
            key.host.len,
            key.port,
            key.account.ptr,
            key.account.len,
            &secret,
            &secret_len,
            &message,
        );
        defer freeMessage(message);
        switch (result) {
            .ok => {},
            .not_found => return error.NotFound,
            .access_denied => {
                setDiag(diag, .auth, message, "Secret Service denied credential access");
                return error.AccessDenied;
            },
            .unexpected => {
                setDiag(diag, .permanent, message, "Secret Service credential lookup failed");
                return error.Unexpected;
            },
        }
        const value = secret orelse return error.Unexpected;
        defer relay_secret_password_free(value);
        return gpa.dupe(u8, value[0..secret_len]);
    }

    fn set(
        _: *anyopaque,
        diag: *Diagnostics,
        key: store.Key,
        secret: []const u8,
    ) store.Error!void {
        var message: ?[*:0]u8 = null;
        const result = relay_secret_store(
            protocolName(key.protocol).ptr,
            protocolName(key.protocol).len,
            key.host.ptr,
            key.host.len,
            key.port,
            key.account.ptr,
            key.account.len,
            secret.ptr,
            secret.len,
            &message,
        );
        defer freeMessage(message);
        return resultError(result, diag, message, "Secret Service credential write failed");
    }

    fn delete(_: *anyopaque, diag: *Diagnostics, key: store.Key) store.Error!void {
        var message: ?[*:0]u8 = null;
        const result = relay_secret_clear(
            protocolName(key.protocol).ptr,
            protocolName(key.protocol).len,
            key.host.ptr,
            key.host.len,
            key.port,
            key.account.ptr,
            key.account.len,
            &message,
        );
        defer freeMessage(message);
        return resultError(result, diag, message, "Secret Service credential deletion failed");
    }

    const vtable: store.VTable = .{
        .get = get,
        .set = set,
        .delete = delete,
    };
};

const Result = enum(c_int) {
    ok = 0,
    not_found = 1,
    access_denied = 2,
    unexpected = 3,
};

fn protocolName(protocol: store.Protocol) []const u8 {
    return @tagName(protocol);
}

fn resultError(result: Result, diag: *Diagnostics, message: ?[*:0]u8, fallback: []const u8) store.Error!void {
    switch (result) {
        .ok, .not_found => return,
        .access_denied => {
            setDiag(diag, .auth, message, fallback);
            return error.AccessDenied;
        },
        .unexpected => {
            setDiag(diag, .permanent, message, fallback);
            return error.Unexpected;
        },
    }
}

fn setDiag(
    diag: *Diagnostics,
    class: relay.diag.ErrorClass,
    message: ?[*:0]u8,
    fallback: []const u8,
) void {
    const text = if (message) |value| std.mem.span(value) else fallback;
    diag.set(class, 0, "{s}", .{text});
}

fn freeMessage(message: ?[*:0]u8) void {
    if (message) |value| relay_secret_message_free(value);
}

extern fn relay_secret_lookup(
    protocol: [*]const u8,
    protocol_len: usize,
    host: [*]const u8,
    host_len: usize,
    port: u16,
    account: [*]const u8,
    account_len: usize,
    secret_out: *?[*:0]u8,
    secret_len_out: *usize,
    message_out: *?[*:0]u8,
) Result;

extern fn relay_secret_store(
    protocol: [*]const u8,
    protocol_len: usize,
    host: [*]const u8,
    host_len: usize,
    port: u16,
    account: [*]const u8,
    account_len: usize,
    secret: [*]const u8,
    secret_len: usize,
    message_out: *?[*:0]u8,
) Result;

extern fn relay_secret_clear(
    protocol: [*]const u8,
    protocol_len: usize,
    host: [*]const u8,
    host_len: usize,
    port: u16,
    account: [*]const u8,
    account_len: usize,
    message_out: *?[*:0]u8,
) Result;

extern fn relay_secret_password_free(secret: [*:0]u8) void;
extern fn relay_secret_message_free(message: [*:0]u8) void;

test "CredStore vtable is available without touching the user's keyring" {
    var backend: SecretStore = .{};
    const cred_store = backend.credStore();
    try std.testing.expect(cred_store.ctx == @as(*anyopaque, @ptrCast(&backend)));
}

test {
    std.testing.refAllDecls(SecretStore);
}
