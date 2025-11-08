//! Gossip type defintions.
//!
//! Follows: https://github.com/eigerco/solana-spec/blob/ad72d520820c7666aa1798e79acc02564190c6f4/gossip-protocol-spec.md

const std = @import("std");
const Bloom = @import("Bloom.zig");

const Address = std.net.Address;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Ed25519 = std.crypto.sign.Ed25519;
const KeyPair = Ed25519.KeyPair;
const Signature = Ed25519.Signature;
const Pubkey = Ed25519.PublicKey;

pub const Messages = enum(u32) {
    pull_request,
    pull_response,
    push_message,
    prune_message,
    ping_message,
    pong_message,
};

const any_address: Address = .initIp4(.{ 0, 0, 0, 0 }, 0);

/// Represents an IPv4 address.
pub const IpAddress = struct {
    octets: [4]u8,

    pub const localhost: IpAddress = .{ .octets = .{ 127, 0, 0, 1 } };
};

pub const PullRequest = struct {
    filter: Filter,
    gossip_data: SignedGossipData,

    pub const Filter = struct {
        filter: Bloom,
        mask: u64,
        mask_bits: u32,
    };
};

pub const PushMessage = struct {
    sender_pubkey: Pubkey,
    gossip_data: []const SignedGossipData,

    pub fn serialize(pm: *const PushMessage, writer: *std.Io.Writer) !void {
        try writer.writeAll(&pm.sender_pubkey.bytes);
        for (pm.crds) |data| try data.serialize(writer);
    }
};

pub const PingMessage = struct {
    from: Pubkey,
    token: [32]u8,
    signature: Signature,

    pub const SIZE = 32 + 32 + 64;

    pub fn fromBytes(bytes: []const u8) !PingMessage {
        if (bytes.len != SIZE) return error.WrongSize;
        return .{
            .from = .{ .bytes = bytes[0..32].* },
            .token = bytes[32..64].*,
            .signature = .fromBytes(bytes[64..128].*),
        };
    }

    const PING_PONG_HASH_PREFIX = "SOLANA_PING_PONG";

    pub fn response(pm: *const PingMessage, kp: *const KeyPair, writer: *std.Io.Writer) !void {
        std.debug.assert(writer.buffer.len >= SIZE + 4); // ping and pong messages are the same size

        try writer.writeInt(u32, @intFromEnum(Messages.pong_message), .little);
        try writer.writeAll(&kp.public_key.bytes);

        const hash_bytes = try writer.writableArray(32);
        Sha256.hash(PING_PONG_HASH_PREFIX ++ pm.token, hash_bytes, .{});

        const signature = try kp.sign(hash_bytes, null);
        try writer.writeAll(&signature.toBytes());
    }
};

const PongMessage = struct {
    from: Pubkey,
    hash: [32]u8,
    signature: [64]u64,
};

const SignedGossipData = struct {
    signature: Signature,
    data: GossipData,

    pub fn serialize(cd: *const SignedGossipData, writer: *std.Io.Writer) !void {
        try writer.writeAll(&cd.signature.toBytes());
        try cd.data.serialize(writer);
    }
};

pub const GossipData = union(enum) {
    legacy_contact_info: noreturn,
    vote: noreturn,
    lowest_slot: noreturn,
    legacy_snapshot_hashes: noreturn,
    accounts_hashes: noreturn,
    epoch_slots: noreturn,
    legacy_version: noreturn,
    version: Version,
    node_instance: NodeInstance,
    duplicate_shred: noreturn,
    snapshot_hashes: noreturn,
    contact_info: ContactInfo,
    restart_last_voted_fork_slots: noreturn,
    restart_heaviest_fork: noreturn,

    const Version = struct {
        from: Pubkey,
        wallclock: u64,
        version: LegacyVersion2,
    };

    const NodeInstance = struct {
        from: Pubkey,
        wallclock: u64,
        timestamp: u64,
        token: u64,
    };

    pub fn serialize(cd: *const GossipData, writer: *std.Io.Writer) !void {
        try writer.writeInt(u32, @intFromEnum(cd.*), .little);
        switch (cd.*) {
            .version => |v| {
                try writer.writeAll(&v.from.bytes);
                try writer.writeInt(u64, v.wallclock, .little);
                try v.version.serialize(writer);
            },
            .node_instance => |ni| {
                try writer.writeAll(&ni.from.bytes);
                try writer.writeInt(u64, ni.wallclock, .little);
                try writer.writeInt(u64, ni.timestamp, .little);
                try writer.writeInt(u64, ni.token, .little);
            },
            .contact_info => |ci| {
                try writer.writeAll(&ci.pubkey.bytes);
                try writer.writeUleb128(ci.wallclock);
                try writer.writeInt(u64, ci.startup, .little); // outset
                try writer.writeInt(u16, ci.shred_version, .little);
                try ci.version.serialize(writer);

                var addrs: [SocketTag.NUM]Address = undefined;
                var addrs_len: u8 = 0;
                var sockets: [SocketTag.NUM]ContactInfo.SocketEntry = undefined;
                var sockets_len: u8 = 0;

                const Scratch = struct {
                    addr: Address,
                    tag: u8,
                    fn lessThan(_: void, lhs: @This(), rhs: @This()) bool {
                        return lhs.addr.getPort() < rhs.addr.getPort();
                    }
                };
                var scratch: [SocketTag.NUM]Scratch = undefined;
                var scratch_len: u8 = 0;
                for (ci.sockets.values, 0..) |entry, i| {
                    if (!entry.eql(any_address)) { // if it's initialized
                        defer scratch_len += 1;
                        scratch[scratch_len].addr = entry;
                        scratch[scratch_len].addr.setPort(@byteSwap(entry.getPort()));
                        scratch[scratch_len].tag = @intCast(i); // less than 2^7 sockets, so always 1 byte tag in shortvec
                    }
                }
                const sorted = scratch[0..scratch_len];
                std.sort.block(Scratch, sorted, {}, Scratch.lessThan);

                addrs[0] = sorted[0].addr;
                addrs_len += 1;
                sockets[0] = .{
                    .port_offset = sorted[0].addr.getPort(),
                    .addr_index = 0,
                    .tag = sorted[0].tag,
                };
                sockets_len += 1;

                // perform a bit of compression by re-using existing addresses
                for (sorted[1..], 0..) |*socket, i| {
                    var found: bool = false;
                    for (addrs[0..addrs_len], 0..) |addr, j| {
                        if (addr.eql(socket.addr)) {
                            defer sockets_len += 1;
                            sockets[sockets_len].addr_index = @intCast(j);
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        defer addrs_len += 1;
                        addrs[addrs_len] = socket.addr;
                        sockets[addrs_len].addr_index = addrs_len;
                    }
                    sockets[sockets_len].port_offset = socket.addr.getPort() - sorted[i - 1].addr.getPort();
                    sockets[sockets_len].tag = socket.tag;
                    sockets_len += 1;
                }

                try writer.writeByte(addrs_len);
                for (addrs[0..addrs_len]) |addr| {
                    try writer.writeInt(u32, 0, .little);
                    try writer.writeInt(u32, addr.in.sa.addr, .little);
                }

                try writer.writeByte(sockets_len);
                for (sockets[0..sockets_len]) |socket| {
                    try writer.writeByte(socket.tag);
                    try writer.writeByte(socket.addr_index);
                    try writer.writeUleb128(socket.port_offset);
                }

                try writer.writeByte(0); // extensions, always empty for now
            },
            else => @panic("TODO"),
        }
    }
};

pub const LegacyVersion2 = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32,
    feature_set: u32,

    pub fn serialize(lv2: *const LegacyVersion2, writer: *std.Io.Writer) !void {
        try writer.writeInt(u16, lv2.major, .little);
        try writer.writeInt(u16, lv2.minor, .little);
        try writer.writeInt(u16, lv2.patch, .little);

        try writer.writeInt(u8, @intFromBool(lv2.commit != null), .little);
        if (lv2.commit) |c| try writer.writeInt(u32, c, .little);

        try writer.writeInt(u32, lv2.feature_set, .little);
    }
};

pub const ContactInfo = struct {
    pubkey: Pubkey,
    wallclock: u64,
    startup: u64,
    shred_version: u16,
    version: Version,
    sockets: std.EnumArray(SocketTag, Address),

    const Version = struct {
        major: u16,
        minor: u16,
        patch: u16,
        commit: u32,
        feature_set: u32,
        client: u16,

        fn serialize(v: *const Version, writer: *std.Io.Writer) !void {
            try writer.writeUleb128(v.major);
            try writer.writeUleb128(v.minor);
            try writer.writeUleb128(v.patch);
            try writer.writeInt(u32, v.commit, .little);
            try writer.writeInt(u32, v.feature_set, .little);
            try writer.writeUleb128(v.client);
        }
    };

    const SocketEntry = struct {
        port_offset: u16,
        tag: u8,
        addr_index: u8,
    };

    pub const SIZE = 32 + (SocketTag.NUM * 10) + 8 + 2;
};

pub const SocketTag = enum(u8) {
    gossip = 0,
    serve_repair_quic = 1,
    rpc = 2,
    rpc_pubsub = 3,
    serve_repair = 4,
    tpu = 5,
    tpu_forwards = 6,
    tpu_forwards_quic = 7,
    tpu_quic = 8,
    tpu_vote = 9,
    tvu = 10,
    tvu_quic = 11,
    tpu_vote_quic = 12,
    alpenglow = 13,

    const NUM = @typeInfo(SocketTag).@"enum".fields.len;
    comptime {
        std.debug.assert(NUM < (1 << 7));
    }
};
