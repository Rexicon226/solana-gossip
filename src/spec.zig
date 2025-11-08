//! Gossip type defintions.
//!
//! Follows: https://github.com/eigerco/solana-spec/blob/ad72d520820c7666aa1798e79acc02564190c6f4/gossip-protocol-spec.md

const std = @import("std");
const Bloom = @import("Bloom.zig");

const Address = std.net.Address;

const Ed25519 = std.crypto.sign.Ed25519;
const Signature = Ed25519.Signature;
const Pubkey = Ed25519.PublicKey;

pub const PullRequest = struct {
    filter: Filter,
    gossip_data: []const SignedGossipData,
};

pub const Filter = struct {
    filter: Bloom,
    mask: u64,
    mask_bits: u32,
};

pub const PushMessage = struct {
    sender_pubkey: Pubkey,
    gossip_data: []const SignedGossipData,

    pub fn serialize(pm: *const PushMessage, writer: *std.Io.Writer) !void {
        try writer.writeAll(&pm.sender_pubkey.bytes);
        for (pm.crds) |data| try data.serialize(writer);
    }
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
    legacy_contact_info: ContactInfo,
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
    contact_info: noreturn,
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
            .legacy_contact_info => |ci| {
                try writer.writeAll(&ci.pubkey.bytes);
                for (ci.sockets.values) |socket| switch (socket.any.family) {
                    std.posix.AF.INET => {
                        try writer.writeInt(u32, 0, .little); // ipv4 address
                        try writer.writeInt(u32, socket.in.sa.addr, .little);
                        try writer.writeInt(u16, socket.in.sa.port, .little);
                    },
                    else => @panic("TODO: support ipv6"),
                };
            },
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

pub const SocketTag = enum(u8) {
    gossip = 0,
    repair = 1,
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

    comptime {
        std.debug.assert(@typeInfo(SocketTag).@"enum".fields.len == 14);
    }
};

pub const ContactInfo = struct {
    /// Identity public key of the peer node.
    pubkey: Pubkey,
    /// Shred version of the peer node.
    shred_version: u16,
    /// Wallclock of when the contact info is signed.
    wallclock: u64,
    sockets: std.EnumArray(SocketTag, Address),
};
