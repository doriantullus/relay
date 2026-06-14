//! fake — in-memory CredStore for unit tests and Linux CI. All CredStore
//! logic tests live against this; keychain.zig only gets compile coverage
//! plus a manual smoke test (unit tests must never touch the real
//! Keychain).

const std = @import("std");
const store = @import("store.zig");
const Diagnostics = @import("../diag.zig").Diagnostics;

pub const FakeStore = struct {
    gpa: std.mem.Allocator,
    /// Composite key string → secret copy. NUL separators: none of the key
    /// parts can contain NUL, so composition is unambiguous.
    map: std.StringHashMapUnmanaged([]u8) = .empty,
    /// Worker threads share one CredStore in the real app; mirror that.
    /// See events.zig for the 0.16 lock rationale.
    mutex: std.atomic.Mutex = .unlocked,
    /// Test hook: the next operation fails with this error (then clears).
    fail_next: ?store.Error = null,

    pub fn init(gpa: std.mem.Allocator) FakeStore {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *FakeStore) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.gpa.free(entry.key_ptr.*);
            store.freeSecret(self.gpa, entry.value_ptr.*);
        }
        self.map.deinit(self.gpa);
        self.* = undefined;
    }

    pub fn credStore(self: *FakeStore) store.CredStore {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: store.VTable = .{
        .get = vtGet,
        .set = vtSet,
        .delete = vtDelete,
    };

    fn vtGet(ctx: *anyopaque, gpa: std.mem.Allocator, diag: *Diagnostics, key: store.Key) store.Error![]u8 {
        const self: *FakeStore = @ptrCast(@alignCast(ctx));
        return self.get(gpa, diag, key);
    }
    fn vtSet(ctx: *anyopaque, diag: *Diagnostics, key: store.Key, secret: []const u8) store.Error!void {
        const self: *FakeStore = @ptrCast(@alignCast(ctx));
        return self.set(diag, key, secret);
    }
    fn vtDelete(ctx: *anyopaque, diag: *Diagnostics, key: store.Key) store.Error!void {
        const self: *FakeStore = @ptrCast(@alignCast(ctx));
        return self.delete(diag, key);
    }

    pub fn get(self: *FakeStore, gpa: std.mem.Allocator, diag: *Diagnostics, key: store.Key) store.Error![]u8 {
        const composite = try composeKey(self.gpa, key);
        defer self.gpa.free(composite);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.takeInjectedFailure(diag);
        const secret = self.map.get(composite) orelse {
            diag.set(.auth, 0, "no stored credential for {s}@{s}:{d}", .{ key.account, key.host, key.port });
            return error.NotFound;
        };
        return gpa.dupe(u8, secret);
    }

    pub fn set(self: *FakeStore, diag: *Diagnostics, key: store.Key, secret: []const u8) store.Error!void {
        const composite = try composeKey(self.gpa, key);
        errdefer self.gpa.free(composite);
        const copy = try self.gpa.dupe(u8, secret);
        errdefer store.freeSecret(self.gpa, copy);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.takeInjectedFailure(diag);
        const slot = try self.map.getOrPut(self.gpa, composite);
        if (slot.found_existing) {
            self.gpa.free(composite);
            store.freeSecret(self.gpa, slot.value_ptr.*);
        }
        slot.value_ptr.* = copy;
    }

    pub fn delete(self: *FakeStore, diag: *Diagnostics, key: store.Key) store.Error!void {
        const composite = try composeKey(self.gpa, key);
        defer self.gpa.free(composite);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        try self.takeInjectedFailure(diag);
        const removed = self.map.fetchRemove(composite) orelse {
            diag.set(.permanent, 0, "no stored credential for {s}@{s}:{d}", .{ key.account, key.host, key.port });
            return error.NotFound;
        };
        self.gpa.free(removed.key);
        store.freeSecret(self.gpa, removed.value);
    }

    /// Stored credentials (for asserting in tests).
    pub fn count(self: *FakeStore) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.map.count();
    }

    fn takeInjectedFailure(self: *FakeStore, diag: *Diagnostics) store.Error!void {
        if (self.fail_next) |err| {
            self.fail_next = null;
            diag.set(if (err == error.AccessDenied) .auth else .permanent, 0, "injected failure: {t}", .{err});
            return err;
        }
    }
};

fn composeKey(gpa: std.mem.Allocator, key: store.Key) error{OutOfMemory}![]u8 {
    return std.fmt.allocPrint(gpa, "{t}\x00{s}\x00{d}\x00{s}", .{
        key.protocol, key.host, key.port, key.account,
    });
}

const lockSpin = @import("../sync.zig").lockSpin;

const test_key: store.Key = .{
    .protocol = .sftp,
    .host = "web1.example.com",
    .port = 2222,
    .account = "deploy",
};

test "fake store: set/get/delete round trip through the interface" {
    var fake: FakeStore = .init(std.testing.allocator);
    defer fake.deinit();
    const cs = fake.credStore();
    var diag: Diagnostics = .{};

    try std.testing.expectError(error.NotFound, cs.get(std.testing.allocator, &diag, test_key));
    try std.testing.expect(diag.message.len > 0);

    try cs.set(&diag, test_key, "hunter2");
    const got = try cs.get(std.testing.allocator, &diag, test_key);
    defer store.freeSecret(std.testing.allocator, got);
    try std.testing.expectEqualStrings("hunter2", got);

    // Overwrite replaces, not duplicates.
    try cs.set(&diag, test_key, "rotated!");
    try std.testing.expectEqual(@as(usize, 1), fake.count());
    const got2 = try cs.get(std.testing.allocator, &diag, test_key);
    defer store.freeSecret(std.testing.allocator, got2);
    try std.testing.expectEqualStrings("rotated!", got2);

    try cs.delete(&diag, test_key);
    try std.testing.expectError(error.NotFound, cs.get(std.testing.allocator, &diag, test_key));
    try std.testing.expectError(error.NotFound, cs.delete(&diag, test_key));
}

test "fake store: keys differing in any component are distinct" {
    var fake: FakeStore = .init(std.testing.allocator);
    defer fake.deinit();
    const cs = fake.credStore();
    var diag: Diagnostics = .{};

    var other_port = test_key;
    other_port.port = 22;
    var other_proto = test_key;
    other_proto.protocol = .ftps;
    var other_account = test_key;
    other_account.account = "root";

    try cs.set(&diag, test_key, "a");
    try cs.set(&diag, other_port, "b");
    try cs.set(&diag, other_proto, "c");
    try cs.set(&diag, other_account, "d");
    try std.testing.expectEqual(@as(usize, 4), fake.count());

    const got = try cs.get(std.testing.allocator, &diag, other_port);
    defer store.freeSecret(std.testing.allocator, got);
    try std.testing.expectEqualStrings("b", got);
}

test "fake store: injected failure surfaces once, with diagnostics" {
    var fake: FakeStore = .init(std.testing.allocator);
    defer fake.deinit();
    const cs = fake.credStore();
    var diag: Diagnostics = .{};

    try cs.set(&diag, test_key, "hunter2");
    fake.fail_next = error.AccessDenied;
    try std.testing.expectError(error.AccessDenied, cs.get(std.testing.allocator, &diag, test_key));
    try std.testing.expectEqual(.auth, diag.class);

    const got = try cs.get(std.testing.allocator, &diag, test_key);
    defer store.freeSecret(std.testing.allocator, got);
    try std.testing.expectEqualStrings("hunter2", got);
}

fn credCycle(gpa: std.mem.Allocator) !void {
    var fake: FakeStore = .init(gpa);
    defer fake.deinit();
    const cs = fake.credStore();
    var diag: Diagnostics = .{};

    try cs.set(&diag, test_key, "hunter2");
    try cs.set(&diag, test_key, "rotated!");
    const got = try cs.get(gpa, &diag, test_key);
    defer store.freeSecret(gpa, got);
    if (!std.mem.eql(u8, got, "rotated!")) return error.TestUnexpectedResult;
    try cs.delete(&diag, test_key);
}

test "fake store: allocation failures neither leak nor corrupt" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, credCycle, .{});
}

test {
    std.testing.refAllDecls(@This());
}
