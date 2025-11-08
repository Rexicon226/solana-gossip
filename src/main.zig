const std = @import("std");
const xev = @import("xev");
const base58 = @import("base58");

const spec = @import("spec.zig");
const Gossip = @import("Gossip.zig");

const Address = std.net.Address;

const Ed25519 = std.crypto.sign.Ed25519;
const KeyPair = Ed25519.KeyPair;
const Pubkey = Ed25519.PublicKey;

/// Represents an IPv4 address.
const IpAddress = struct {
    octets: [4]u8,

    pub const localhost: IpAddress = .{ .octets = .{ 127, 0, 0, 1 } };
};

fn resolveAddresses(allocator: std.mem.Allocator, addresses: []const []const u8) ![]const Address {
    var result = try allocator.alloc(Address, addresses.len);
    errdefer allocator.free(result);

    for (addresses, 0..) |address, i| {
        const resolved = try resolveAddress(allocator, address);
        for (result[0..i]) |other| if (resolved.eql(other)) continue; // already have it
        result[i] = resolved;
    }

    return result;
}

/// Resolves the domain and port provided, returning the IP indicated by the first A record.
fn resolveAddress(allocator: std.mem.Allocator, host_and_port: []const u8) !Address {
    const domain_index = std.mem.indexOfScalar(u8, host_and_port, ':') orelse
        return error.PortMissing;
    const domain = host_and_port[0..domain_index];

    const port = std.fmt.parseInt(u16, host_and_port[domain_index + 1 ..], 10) catch
        return error.InvalidPort;

    const address_list = try std.net.getAddressList(allocator, domain, port);
    defer address_list.deinit();
    if (address_list.addrs.len == 0) return error.DnsResolutionFailed;

    return address_list.addrs[0]; // return first A record address
}

const MAX_PORT_COUNT_PER_MESSAGE = 4;
const HEADER_LENGTH = 4;

const IpEchoRequest = extern struct {
    tcp_ports: [MAX_PORT_COUNT_PER_MESSAGE]u16 = @splat(0),
    udp_ports: [MAX_PORT_COUNT_PER_MESSAGE]u16 = @splat(0),
};

/// Pings the address and expects a IpEchoResponse back. Returns
/// the ipv4 octets of the IP in the request, as well as a potential shred
/// version indicated by the echo.
fn ipEcho(address: Address) !struct { IpAddress, ?u16 } {
    const stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();

    // send ip echo request
    {
        var buffer: [@sizeOf(IpEchoRequest)]u8 = undefined;
        var stream_writer = stream.writer(&buffer);
        const writer = &stream_writer.interface;

        try writer.splatByteAll(0, HEADER_LENGTH);
        try writer.splatByteAll(0, @sizeOf(IpEchoRequest));
        try writer.writeByte('\n');
        try writer.flush();
    }

    // get the echo response
    {
        var buffer: [32]u8 = undefined;
        var stream_reader = stream.reader(&buffer);
        const reader: *std.Io.Reader = stream_reader.interface();
        try reader.discardAll(HEADER_LENGTH);

        if (try reader.takeInt(u32, .little) != 0) return error.Ipv6Unsupported;
        const ip_address: IpAddress = .{ .octets = (try reader.takeArray(4)).* };
        const shred_version: ?u16 = switch (try reader.takeByte()) {
            0 => null,
            1 => try reader.takeInt(u16, .little),
            else => return error.InvalidData,
        };

        return .{ ip_address, shred_version };
    }
}

const Extraspect = struct {
    ip: IpAddress,
    shred_version: u16,
};

/// Pings the echo servers provided to gain information about ourselves.
fn extraspect(entrypoints: []const Address) !Extraspect {
    var ip: ?IpAddress = null;
    var shred_version: ?u16 = null;

    // loop over the entrypoints until we get all of the info we need, or run out of entrypoints
    for (entrypoints) |entrypoint| {
        const new_ip_addr, const new_shred_version = try ipEcho(entrypoint);
        if (ip == null) ip = new_ip_addr;
        if (shred_version == null) shred_version = new_shred_version;
        if (ip != null and shred_version != null) break;
    }

    return .{
        .shred_version = shred_version orelse 0,
        .ip = ip orelse .localhost,
    };
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    const gossip_port: u16 = 8001;

    const entrypoints: []const []const u8 = &.{
        "entrypoint.testnet.solana.com:8001",
        "entrypoint2.testnet.solana.com:8001",
        // "entrypoint3.testnet.solana.com:8001",
        // "127.0.0.1:8000",
    };

    const addresses = try resolveAddresses(allocator, entrypoints);
    defer allocator.free(addresses);

    const info = try extraspect(addresses);
    std.log.info(
        "echo server response ip: {any}, shred_version: {d}",
        .{ info.ip.octets, info.shred_version },
    );

    const my_keypair: KeyPair = .generate();

    std.log.info("public key: {f}", .{formatPubkey(my_keypair.public_key)});

    var contact_info: spec.ContactInfo = .{
        .pubkey = my_keypair.public_key,
        .shred_version = info.shred_version,
        .sockets = .initFill(try .parseIp("0.0.0.0", 0)),
        .wallclock = 0, // changed when we sign
    };
    contact_info.sockets.set(.gossip, .initIp4(info.ip.octets, gossip_port));

    var gossip: Gossip = undefined;
    try gossip.init(&my_keypair, contact_info);
    try gossip.run(addresses);
}

fn formatPubkey(pubkey: Pubkey) std.fmt.Alt(Pubkey, fmtPubkey) {
    return .{ .data = pubkey };
}
fn fmtPubkey(pubkey: Pubkey, writer: *std.Io.Writer) !void {
    var buffer: [1234]u8 = undefined;
    const len = base58.Table.BITCOIN.encode(&buffer, &pubkey.bytes);
    try writer.writeAll(buffer[0..len]);
}
