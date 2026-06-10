//! keychain — CredStore backed by the macOS Keychain, as
//! kSecClassInternetPassword items via the SecItem* C API. The needed
//! CoreFoundation/Security symbols are extern'd directly (core links both
//! frameworks on macOS; no ObjC, per the architecture laws).
//!
//! TESTING POLICY: unit tests must NEVER touch the real Keychain — they
//! would pollute the developer/CI login keychain and can block on UI
//! consent prompts. This file gets compile coverage only, plus a smoke
//! test that is skipped unless RELAY_KEYCHAIN_SMOKE=1 is set (run it
//! manually: `RELAY_KEYCHAIN_SMOKE=1 zig build test`). All CredStore logic
//! tests live against cred/fake.zig.

const std = @import("std");
const builtin = @import("builtin");
const store = @import("store.zig");
const Diagnostics = @import("../diag.zig").Diagnostics;

pub const KeychainStore = if (builtin.os.tag == .macos) MacKeychainStore else UnsupportedStore;

/// Referencing this on non-macOS is a compile error by design: callers
/// must select cred/fake.zig there.
const UnsupportedStore = struct {
    pub fn credStore(self: *UnsupportedStore) store.CredStore {
        _ = self;
        @compileError("KeychainStore is macOS-only; use cred/fake.zig elsewhere");
    }
};

const MacKeychainStore = struct {
    pub fn credStore(self: *MacKeychainStore) store.CredStore {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: store.VTable = .{
        .get = vtGet,
        .set = vtSet,
        .delete = vtDelete,
    };

    fn vtGet(ctx: *anyopaque, gpa: std.mem.Allocator, diag: *Diagnostics, key: store.Key) store.Error![]u8 {
        const self: *MacKeychainStore = @ptrCast(@alignCast(ctx));
        return self.get(gpa, diag, key);
    }
    fn vtSet(ctx: *anyopaque, diag: *Diagnostics, key: store.Key, secret: []const u8) store.Error!void {
        const self: *MacKeychainStore = @ptrCast(@alignCast(ctx));
        return self.set(diag, key, secret);
    }
    fn vtDelete(ctx: *anyopaque, diag: *Diagnostics, key: store.Key) store.Error!void {
        const self: *MacKeychainStore = @ptrCast(@alignCast(ctx));
        return self.delete(diag, key);
    }

    pub fn get(self: *MacKeychainStore, gpa: std.mem.Allocator, diag: *Diagnostics, key: store.Key) store.Error![]u8 {
        _ = self;
        const attrs: ItemAttrs = try .init(key);
        defer attrs.deinit();

        const keys = [_]?*const anyopaque{
            c.kSecClass,      c.kSecAttrServer,   c.kSecAttrAccount,
            c.kSecAttrPort,   c.kSecAttrProtocol, c.kSecReturnData,
            c.kSecMatchLimit,
        };
        const values = [_]?*const anyopaque{
            c.kSecClassInternetPassword, attrs.server,   attrs.account,
            attrs.port,                  attrs.protocol, c.kCFBooleanTrue,
            c.kSecMatchLimitOne,
        };
        const query = try makeDict(&keys, &values);
        defer c.CFRelease(query);

        var result: ?*const anyopaque = null;
        const status = c.SecItemCopyMatching(query, &result);
        if (status != c.errSecSuccess) return statusToError(status, diag, "SecItemCopyMatching");
        const obj = result orelse return error.Unexpected;
        defer c.CFRelease(obj);
        if (c.CFGetTypeID(obj) != c.CFDataGetTypeID()) {
            diag.set(.permanent, 0, "Keychain returned a non-CFData item", .{});
            return error.Unexpected;
        }
        const data: *const c.CFData = @ptrCast(obj);
        const len: usize = @intCast(c.CFDataGetLength(data));
        const secret = try gpa.alloc(u8, len);
        @memcpy(secret, c.CFDataGetBytePtr(data)[0..len]);
        return secret;
    }

    pub fn set(self: *MacKeychainStore, diag: *Diagnostics, key: store.Key, secret: []const u8) store.Error!void {
        _ = self;
        const attrs: ItemAttrs = try .init(key);
        defer attrs.deinit();
        const data = c.CFDataCreate(null, secret.ptr, @intCast(secret.len)) orelse return error.OutOfMemory;
        defer c.CFRelease(data);

        const add_keys = [_]?*const anyopaque{
            c.kSecClass,    c.kSecAttrServer,   c.kSecAttrAccount,
            c.kSecAttrPort, c.kSecAttrProtocol, c.kSecValueData,
        };
        const add_values = [_]?*const anyopaque{
            c.kSecClassInternetPassword, attrs.server,   attrs.account,
            attrs.port,                  attrs.protocol, data,
        };
        const add_attrs = try makeDict(&add_keys, &add_values);
        defer c.CFRelease(add_attrs);

        const status = c.SecItemAdd(add_attrs, null);
        if (status == c.errSecSuccess) return;
        if (status != c.errSecDuplicateItem) return statusToError(status, diag, "SecItemAdd");

        // Item exists: update its secret in place (keeps ACL/metadata).
        const query_keys = [_]?*const anyopaque{
            c.kSecClass,    c.kSecAttrServer,   c.kSecAttrAccount,
            c.kSecAttrPort, c.kSecAttrProtocol,
        };
        const query_values = [_]?*const anyopaque{
            c.kSecClassInternetPassword, attrs.server,   attrs.account,
            attrs.port,                  attrs.protocol,
        };
        const query = try makeDict(&query_keys, &query_values);
        defer c.CFRelease(query);

        const update_keys = [_]?*const anyopaque{c.kSecValueData};
        const update_values = [_]?*const anyopaque{data};
        const update = try makeDict(&update_keys, &update_values);
        defer c.CFRelease(update);

        const update_status = c.SecItemUpdate(query, update);
        if (update_status != c.errSecSuccess) return statusToError(update_status, diag, "SecItemUpdate");
    }

    pub fn delete(self: *MacKeychainStore, diag: *Diagnostics, key: store.Key) store.Error!void {
        _ = self;
        const attrs: ItemAttrs = try .init(key);
        defer attrs.deinit();

        const keys = [_]?*const anyopaque{
            c.kSecClass,    c.kSecAttrServer,   c.kSecAttrAccount,
            c.kSecAttrPort, c.kSecAttrProtocol,
        };
        const values = [_]?*const anyopaque{
            c.kSecClassInternetPassword, attrs.server,   attrs.account,
            attrs.port,                  attrs.protocol,
        };
        const query = try makeDict(&keys, &values);
        defer c.CFRelease(query);

        const status = c.SecItemDelete(query);
        if (status != c.errSecSuccess) return statusToError(status, diag, "SecItemDelete");
    }
};

/// The CF objects identifying one item; shared by every query.
const ItemAttrs = struct {
    server: *const c.CFString,
    account: *const c.CFString,
    port: *const c.CFNumber,
    /// Borrowed constant (kSecAttrProtocol*), not released.
    protocol: *const c.CFString,

    fn init(key: store.Key) store.Error!ItemAttrs {
        const server = c.CFStringCreateWithBytes(null, key.host.ptr, @intCast(key.host.len), c.kCFStringEncodingUTF8, 0) orelse
            return error.OutOfMemory;
        errdefer c.CFRelease(server);
        const account = c.CFStringCreateWithBytes(null, key.account.ptr, @intCast(key.account.len), c.kCFStringEncodingUTF8, 0) orelse
            return error.OutOfMemory;
        errdefer c.CFRelease(account);
        var port_value: i32 = key.port;
        const port = c.CFNumberCreate(null, c.kCFNumberSInt32Type, &port_value) orelse
            return error.OutOfMemory;
        return .{
            .server = server,
            .account = account,
            .port = port,
            .protocol = switch (key.protocol) {
                .ftp => c.kSecAttrProtocolFTP,
                .ftps => c.kSecAttrProtocolFTPS,
                .sftp => c.kSecAttrProtocolSSH,
            },
        };
    }

    fn deinit(self: ItemAttrs) void {
        c.CFRelease(self.server);
        c.CFRelease(self.account);
        c.CFRelease(self.port);
    }
};

fn makeDict(keys: []const ?*const anyopaque, values: []const ?*const anyopaque) store.Error!*const c.CFDictionary {
    std.debug.assert(keys.len == values.len);
    return c.CFDictionaryCreate(
        null,
        keys.ptr,
        values.ptr,
        @intCast(keys.len),
        &c.kCFTypeDictionaryKeyCallBacks,
        &c.kCFTypeDictionaryValueCallBacks,
    ) orelse error.OutOfMemory;
}

fn statusToError(status: c.OSStatus, diag: *Diagnostics, op: []const u8) store.Error {
    switch (status) {
        c.errSecItemNotFound => {
            diag.set(.auth, 0, "{s}: no matching Keychain item (OSStatus {d})", .{ op, status });
            return error.NotFound;
        },
        c.errSecAuthFailed, c.errSecUserCanceled, c.errSecInteractionNotAllowed => {
            diag.set(.auth, 0, "{s}: Keychain access denied (OSStatus {d})", .{ op, status });
            return error.AccessDenied;
        },
        else => {
            diag.set(.permanent, 0, "{s}: Keychain error (OSStatus {d})", .{ op, status });
            return error.Unexpected;
        },
    }
}

/// Hand-declared CF/Security ABI (see Security/SecItem.h,
/// CoreFoundation/CFDictionary.h). Kept minimal on purpose; translate-c is
/// reserved for the vendored C libraries.
const c = struct {
    const CFString = opaque {};
    const CFData = opaque {};
    const CFNumber = opaque {};
    const CFDictionary = opaque {};
    const CFBoolean = opaque {};
    const CFIndex = isize;
    const CFTypeID = usize;
    const OSStatus = i32;
    const CFStringEncoding = u32;
    const kCFStringEncodingUTF8: CFStringEncoding = 0x0800_0100;
    const CFNumberType = CFIndex;
    const kCFNumberSInt32Type: CFNumberType = 3;

    const CFDictionaryKeyCallBacks = extern struct {
        version: CFIndex,
        retain: ?*const anyopaque,
        release: ?*const anyopaque,
        copyDescription: ?*const anyopaque,
        equal: ?*const anyopaque,
        hash: ?*const anyopaque,
    };
    const CFDictionaryValueCallBacks = extern struct {
        version: CFIndex,
        retain: ?*const anyopaque,
        release: ?*const anyopaque,
        copyDescription: ?*const anyopaque,
        equal: ?*const anyopaque,
    };

    extern const kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
    extern const kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
    extern const kCFBooleanTrue: *const CFBoolean;

    extern fn CFStringCreateWithBytes(
        alloc: ?*const anyopaque,
        bytes: [*]const u8,
        num_bytes: CFIndex,
        encoding: CFStringEncoding,
        is_external_representation: u8,
    ) ?*const CFString;
    extern fn CFDataCreate(alloc: ?*const anyopaque, bytes: [*]const u8, length: CFIndex) ?*const CFData;
    extern fn CFDataGetLength(data: *const CFData) CFIndex;
    extern fn CFDataGetBytePtr(data: *const CFData) [*]const u8;
    extern fn CFNumberCreate(alloc: ?*const anyopaque, number_type: CFNumberType, value_ptr: *const anyopaque) ?*const CFNumber;
    extern fn CFDictionaryCreate(
        alloc: ?*const anyopaque,
        keys: [*]const ?*const anyopaque,
        values: [*]const ?*const anyopaque,
        num_values: CFIndex,
        key_callbacks: *const CFDictionaryKeyCallBacks,
        value_callbacks: *const CFDictionaryValueCallBacks,
    ) ?*const CFDictionary;
    extern fn CFRelease(cf: *const anyopaque) void;
    extern fn CFGetTypeID(cf: *const anyopaque) CFTypeID;
    extern fn CFDataGetTypeID() CFTypeID;

    extern const kSecClass: ?*const anyopaque;
    extern const kSecClassInternetPassword: ?*const anyopaque;
    extern const kSecAttrServer: ?*const anyopaque;
    extern const kSecAttrAccount: ?*const anyopaque;
    extern const kSecAttrPort: ?*const anyopaque;
    extern const kSecAttrProtocol: ?*const anyopaque;
    extern const kSecAttrProtocolFTP: *const CFString;
    extern const kSecAttrProtocolFTPS: *const CFString;
    extern const kSecAttrProtocolSSH: *const CFString;
    extern const kSecReturnData: ?*const anyopaque;
    extern const kSecMatchLimit: ?*const anyopaque;
    extern const kSecMatchLimitOne: ?*const anyopaque;
    extern const kSecValueData: ?*const anyopaque;

    extern fn SecItemCopyMatching(query: *const CFDictionary, result: *?*const anyopaque) OSStatus;
    extern fn SecItemAdd(attributes: *const CFDictionary, result: ?*?*const anyopaque) OSStatus;
    extern fn SecItemUpdate(query: *const CFDictionary, attrs_to_update: *const CFDictionary) OSStatus;
    extern fn SecItemDelete(query: *const CFDictionary) OSStatus;

    const errSecSuccess: OSStatus = 0;
    const errSecItemNotFound: OSStatus = -25300;
    const errSecDuplicateItem: OSStatus = -25299;
    const errSecAuthFailed: OSStatus = -25293;
    const errSecInteractionNotAllowed: OSStatus = -25308;
    const errSecUserCanceled: OSStatus = -128;
};

test "keychain: compile coverage only — never touches the real Keychain" {
    if (builtin.os.tag == .macos) {
        // Analyze (not call) the implementation so the externs, casts, and
        // vtable shapes are compile-checked and linked on every test run.
        std.testing.refAllDecls(MacKeychainStore);
        std.testing.refAllDecls(ItemAttrs);
        _ = &makeDict;
        _ = &statusToError;
    } else {
        return error.SkipZigTest;
    }
}

test "keychain: manual smoke test (set RELAY_KEYCHAIN_SMOKE=1 to run)" {
    if (builtin.os.tag == .macos) {
        const gate = std.c.getenv("RELAY_KEYCHAIN_SMOKE") orelse return error.SkipZigTest;
        if (!std.mem.eql(u8, std.mem.span(gate), "1")) return error.SkipZigTest;

        var keychain: KeychainStore = .{};
        const cs = keychain.credStore();
        var diag: Diagnostics = .{};
        const key: store.Key = .{
            .protocol = .sftp,
            .host = "relay-smoke-test.invalid",
            .port = 2222,
            .account = "relay-smoke",
        };

        cs.delete(&diag, key) catch {}; // clean slate from previous runs

        try cs.set(&diag, key, "s3cret");
        const got = try cs.get(std.testing.allocator, &diag, key);
        defer store.freeSecret(std.testing.allocator, got);
        try std.testing.expectEqualStrings("s3cret", got);

        try cs.set(&diag, key, "rotated!"); // exercises the SecItemUpdate path
        const got2 = try cs.get(std.testing.allocator, &diag, key);
        defer store.freeSecret(std.testing.allocator, got2);
        try std.testing.expectEqualStrings("rotated!", got2);

        try cs.delete(&diag, key);
        try std.testing.expectError(error.NotFound, cs.get(std.testing.allocator, &diag, key));
    } else {
        return error.SkipZigTest;
    }
}
