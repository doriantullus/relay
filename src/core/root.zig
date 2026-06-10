//! relay_core — protocol engines (FTP/FTPS/SFTP), transfer queue, VFS,
//! credentials, settings. Architectural law: this module never imports
//! ObjC and stays portable (it builds and unit-tests on Linux CI).
//!
//! All I/O is coded against `*std.Io.Reader` / `*std.Io.Writer`, never raw
//! sockets, so every protocol layer unit-tests against in-memory streams.

const std = @import("std");

pub const version: std.SemanticVersion = .{ .major = 0, .minor = 1, .patch = 0 };

pub const diag = @import("diag.zig");
pub const cancel = @import("cancel.zig");
pub const events = @import("events.zig");

pub const transcript = @import("log/transcript.zig");
pub const settings = @import("settings/settings.zig");
pub const sites = @import("settings/sites.zig");

pub const cred = struct {
    pub const store = @import("cred/store.zig");
    pub const keychain = @import("cred/keychain.zig");
    pub const fake = @import("cred/fake.zig");
};

pub const ssh = struct {
    pub const agent = @import("proto/ssh/agent.zig");
    pub const keys = @import("proto/ssh/keys.zig");
    pub const known_hosts = @import("proto/ssh/known_hosts.zig");
    pub const ssh_config = @import("proto/ssh/ssh_config.zig");
};

pub const ftp = struct {
    pub const reply = @import("proto/ftp/reply.zig");
    pub const listing_mlsd = @import("proto/ftp/listing_mlsd.zig");
    pub const listing_list = @import("proto/ftp/listing_list.zig");
    pub const client = @import("proto/ftp/client.zig");
    pub const data_conn = @import("proto/ftp/data_conn.zig");
};

pub const tls = struct {
    pub const provider = @import("tls/provider.zig");
    pub const libressl = @import("tls/libressl.zig");
    pub const verify_sectrust = @import("tls/verify_sectrust.zig");
};

pub const sftp = struct {
    pub const session = @import("proto/sftp/session.zig");
    pub const client = @import("proto/sftp/sftp.zig");
    pub const poll = @import("proto/sftp/poll.zig");
};

pub const vfs = struct {
    pub const iface = @import("vfs/vfs.zig");
    pub const local = @import("vfs/local.zig");
    pub const ftp_backend = @import("vfs/ftp.zig");
    pub const sftp_backend = @import("vfs/sftp.zig");
    pub const path = @import("vfs/path.zig");
    pub const snapshot = @import("vfs/snapshot.zig");
};

pub const pool = struct {
    pub const site_pool = @import("pool/site_pool.zig");
    pub const lease = @import("pool/lease.zig");
    pub const keepalive = @import("pool/keepalive.zig");
};

pub const queue = struct {
    pub const engine = @import("queue/engine.zig");
    pub const item = @import("queue/item.zig");
    pub const scheduler = @import("queue/scheduler.zig");
    pub const rate_limit = @import("queue/rate_limit.zig");
    pub const persist = @import("queue/persist.zig");
};

pub const testutil = struct {
    pub const duplex = @import("testutil/duplex.zig");
    pub const ftp_script = @import("testutil/ftp_script.zig");
    pub const mock_vfs = @import("testutil/mock_vfs.zig");
};

test "module sanity" {
    try std.testing.expectEqual(@as(usize, 0), version.major);
    try std.testing.expectEqual(@as(usize, 1), version.minor);
}

// Reference every leaf module so its tests are included in `zig build test`.
test {
    _ = diag;
    _ = cancel;
    _ = events;
    _ = transcript;
    _ = settings;
    _ = sites;
    _ = cred.store;
    _ = cred.keychain;
    _ = cred.fake;
    _ = ssh.agent;
    _ = ssh.keys;
    _ = ssh.known_hosts;
    _ = ssh.ssh_config;
    _ = ftp.reply;
    _ = ftp.listing_mlsd;
    _ = ftp.listing_list;
    _ = ftp.client;
    _ = ftp.data_conn;
    _ = tls.provider;
    _ = tls.libressl;
    _ = tls.verify_sectrust;
    _ = sftp.session;
    _ = sftp.client;
    _ = sftp.poll;
    _ = vfs.iface;
    _ = vfs.local;
    _ = vfs.ftp_backend;
    _ = vfs.sftp_backend;
    _ = vfs.path;
    _ = vfs.snapshot;
    _ = pool.site_pool;
    _ = pool.lease;
    _ = pool.keepalive;
    _ = queue.engine;
    _ = queue.item;
    _ = queue.scheduler;
    _ = queue.rate_limit;
    _ = queue.persist;
    _ = testutil.duplex;
    _ = testutil.ftp_script;
    _ = testutil.mock_vfs;
}
