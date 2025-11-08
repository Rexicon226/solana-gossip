const std = @import("std");
const xev = @import("xev");
const Gossip = @This();

const posix = std.posix;

const spec = @import("spec.zig");
const Bloom = @import("Bloom.zig");

const ContactInfo = spec.ContactInfo;
const PushMessage = spec.PushMessage;
const GossipData = spec.GossipData;
const PingMessage = spec.PingMessage;
const LegacyVersion2 = spec.LegacyVersion2;
const Messages = spec.Messages;

const Address = std.net.Address;

const Ed25519 = std.crypto.sign.Ed25519;
const KeyPair = Ed25519.KeyPair;
const Pubkey = Ed25519.PublicKey;

// events
pull_request: xev.Timer,
gossip_reply: xev.UDP,

// gossip table
crds: Crds,

// our information
contact_info: ContactInfo,

keypair: KeyPair,
startup_timestamp: u64,
gossip_socket: std.posix.fd_t,
prng: std.Random.DefaultPrng,

entrypoints: []const Address,

// all the rates are in milliseconds
const PULL_REQUEST_RATE = 2_000;
const MTU = 1232;

const NUM_KEYS = 8;
const FALSE_POSITIVE_RATE = 0.1;

const our_version: LegacyVersion2 = .{
    .major = 0,
    .minor = 1,
    .patch = 0,
    .commit = null,
    .feature_set = 4,
};

const Crds = struct {
    failed_inserts: std.DoublyLinkedList,

    fn advance(c: *Crds) void {
        _ = c;
    }
};

pub fn init(
    g: *Gossip,
    kp: *const KeyPair,
    entrypoints: []const Address,
    contact_info: ContactInfo,
) !void {
    // open up our gossip socket
    // const gossip_address = contact_info.sockets.get(.gossip);
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    errdefer posix.close(sockfd);

    _ = try std.posix.fcntl(sockfd, std.posix.F.SETFL, @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true })));

    // try posix.bind(sockfd, &gossip_address.any, gossip_address.getOsSockLen());
    const any: Address = .initIp4(@splat(0), 8001);
    try posix.bind(sockfd, &any.any, any.getOsSockLen());

    g.* = .{
        .pull_request = try .init(),
        .gossip_reply = .initFd(sockfd),
        .keypair = kp.*,
        .contact_info = contact_info,
        .crds = .{},
        .startup_timestamp = wallclock(),
        .gossip_socket = sockfd,
        .entrypoints = entrypoints,
        .prng = .init(wallclock()), // TODO: i'd prefer not to intialize with wall clock
    };
}

const DEPTH = 20;

pub fn run(g: *Gossip) !void {
    var loop: xev.Loop = try .init(.{});
    defer loop.deinit();

    var buffers: [DEPTH][MTU]u8 = undefined;
    var states: [DEPTH]xev.UDP.State = undefined;
    var reply_completions: [DEPTH]xev.Completion = undefined;
    // setup the callback for when we recveive data from the network.
    for (&buffers, &states, &reply_completions) |*read_buffer, *state, *completion| {
        g.gossip_reply.read(
            &loop,
            completion,
            state,
            .{ .slice = read_buffer },
            Gossip,
            g,
            onGossipReply,
        );
    }

    // setup our pull request timer to trigger every 5 seconds.
    var pull_request_completion: xev.Completion = undefined;
    g.pull_request.run(
        &loop,
        &pull_request_completion,
        PULL_REQUEST_RATE,
        Gossip,
        g,
        onPullRequest,
    );

    // The node starts the Gossip service and then advertises itself to the cluster
    // by sending messages to the peer identified by the entrypoint. The node sends:
    // - two push messages containing its own Version and NodeInstance
    // - a pull request that contains the node's own LegacyContactInfo
    // try g.sendPushMessage(
    //     g.entrypoints,
    //     &.{
    //         .{ .version = .{
    //             .from = g.keypair.public_key,
    //             .wallclock = wallclock(),
    //             .version = our_version,
    //         } },
    //         .{ .node_instance = .{
    //             .from = g.keypair.public_key,
    //             .wallclock = wallclock(),
    //             .timestamp = g.startup_timestamp,
    //             .token = g.prng.random().int(u64),
    //         } },
    //     },
    // );
    // we send the pull request in our timer callback

    try loop.run(.until_done);
}

/// Sends the provided push message to each target.
fn sendPushMessage(
    g: *Gossip,
    targets: []const Address,
    datas: []const GossipData,
) !void {
    var payload: [MTU]u8 = @splat(0);
    var writer: std.Io.Writer = .fixed(&payload);

    try writer.writeInt(u32, @intFromEnum(Messages.push_message), .little);
    try writer.writeAll(&g.keypair.public_key.bytes);
    try writer.writeInt(u64, datas.len, .little);
    for (datas) |data| try serializeData(&writer, &g.keypair, data);

    for (targets) |target| {
        const bytes_sent = try std.posix.sendto(
            g.gossip_socket,
            writer.buffered(),
            std.posix.MSG.NOSIGNAL,
            &target.any,
            target.getOsSockLen(),
        );
        std.debug.assert(bytes_sent == writer.end);
    }
}

/// Sends the provided push message to each target.
fn sendPullRequest(g: *Gossip, data: GossipData) !void {
    const random = g.prng.random();

    // TODO: get from crds table
    const num_items = 0;
    // const max_bits: f64 = @floatFromInt(8 * (MTU - 4 - 8 - (8 * NUM_KEYS) - 1 - 8 - 8 - 8 - 8 - 4 - LegacyContactInfo.SIZE));
    const max_bits: f64 = 123;

    const max_items = Bloom.maxItems(max_bits, NUM_KEYS, FALSE_POSITIVE_RATE);
    const num_bits = Bloom.numBits(max_items, FALSE_POSITIVE_RATE, max_bits);

    const mask_bits = @ceil(@log2(num_items / max_items));
    const offset: u32 = if (mask_bits >= 0) @intFromFloat(mask_bits) else 0;
    const mask = random.int(u64) | (~@as(u64, 0) >> @intCast(offset));

    const bloom_vec_len = try std.math.divCeil(u64, num_bits, 64);

    var payload: [MTU]u8 = @splat(0);
    var writer: std.Io.Writer = .fixed(&payload);

    // filter
    {
        // bloom filter
        {
            try writer.writeInt(u32, @intFromEnum(Messages.pull_request), .little);

            try writer.writeInt(u64, NUM_KEYS, .little);
            const keys: []align(1) u64 = @ptrCast(try writer.writableSlice(NUM_KEYS * 8));

            try writer.writeByte(@intFromBool(num_bits != 0)); // has bits
            const bits: []align(1) u64 = switch (num_bits) {
                0 => &.{},
                else => bits: {
                    try writer.writeInt(u64, bloom_vec_len, .little);
                    break :bits @ptrCast(try writer.writableSlice(bloom_vec_len * 8));
                },
            };

            try writer.writeInt(u64, num_bits, .little);
            const bits_set: *align(1) u64 = @ptrCast(try writer.writableArray(8));

            const bloom: Bloom = .{
                .keys = keys,
                .bits = bits,
                .max_bits = num_bits,
            };
            for (bloom.keys) |*key| key.* = random.int(u64);

            // TODO: populate bloom filter

            var num_bits_set: u32 = 0;
            for (bloom.bits) |bit| num_bits_set += @popCount(bit);
            bits_set.* = num_bits_set;
        }

        try writer.writeInt(u64, mask, .little);
        try writer.writeInt(u32, offset, .little); // mask bits
    }

    var copy = data;
    switch (copy) {
        .contact_info => |*ci| ci.wallclock = wallclock(),
        else => unreachable, // pull request only valid with ContactInfo
    }
    try serializeData(&writer, &g.keypair, copy);

    // TODO: get peer from table

    for (g.entrypoints) |target| {
        std.debug.print("sending pull request to: {f}\n", .{target});
        const bytes_sent = try std.posix.sendto(
            g.gossip_socket,
            writer.buffered(),
            std.posix.MSG.NOSIGNAL,
            &target.any,
            target.getOsSockLen(),
        );
        std.debug.assert(bytes_sent == writer.end);
    }
}

fn serializeData(writer: *std.Io.Writer, kp: *const KeyPair, data: GossipData) !void {
    // reserve 64 bytes for the signature
    const sig_bytes = try writer.writableArray(Ed25519.Signature.encoded_length);

    const start = writer.end;
    try data.serialize(writer);

    // sign the data we just wrote and write it back to the signature slice
    const signature = try kp.sign(writer.buffered()[start..], null);
    @memcpy(sig_bytes, &signature.toBytes());
}

fn onGossipReply(
    maybe_gossip: ?*Gossip,
    _: *xev.Loop,
    _: *xev.Completion,
    _: *xev.UDP.State,
    peer_address: Address,
    _: xev.UDP,
    read_buffer: xev.ReadBuffer,
    read_error: xev.ReadError!usize,
) xev.CallbackAction {
    const log = std.log.scoped(.gossip_reply);

    const bytes_read = read_error catch |err| {
        log.err("onGossipReply failed to read: {t}", .{err});
        return .disarm;
    };
    if (bytes_read < 4) return .rearm;
    const bytes = read_buffer.slice[0..bytes_read];
    return onGossipReplyInner(maybe_gossip.?, bytes, peer_address) catch |err| {
        log.err("onGossipReply failed with: {t}", .{err});
        return .rearm;
    };
}

fn onGossipReplyInner(
    gossip: *const Gossip,
    bytes: []const u8,
    peer_address: Address,
) !xev.CallbackAction {
    const log = std.log.scoped(.gossip_reply);

    const tag: u32 = @bitCast(bytes[0..4].*);
    const ty: Messages = std.enums.fromInt(Messages, tag) orelse {
        log.warn("got unknwon message tag: {d}", .{tag});
        return .rearm;
    };
    log.info("received {t} from {f}", .{ ty, peer_address });

    switch (ty) {
        .ping_message => {
            const message_bytes = bytes[4..];
            const message: PingMessage = try .fromBytes(message_bytes);

            // verify the signature
            try message.signature.verify(&message.token, message.from);

            // create a pong message to send back
            var response: [PingMessage.SIZE + 4]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&response);
            try message.response(&gossip.keypair, &writer);

            log.info("sending pong message to {f}", .{peer_address});

            const bytes_sent = try std.posix.sendto(
                gossip.gossip_socket,
                writer.buffered(),
                0,
                &peer_address.any,
                peer_address.getOsSockLen(),
            );
            std.debug.assert(bytes_sent == writer.end);
        },
        else => log.err("TODO: handle {t} message", .{ty}),
    }

    return .rearm;
}

fn onPullRequest(
    maybe_gossip: ?*Gossip,
    loop: *xev.Loop,
    completion: *xev.Completion,
    timer_error: xev.Timer.RunError!void,
) xev.CallbackAction {
    errdefer |err| std.debug.panic("onPullRequest failed with: '{s}'", .{@errorName(err)});
    const log = std.log.scoped(.pull_request);

    try timer_error;

    log.info("creating pull request", .{});

    const gossip = maybe_gossip.?;

    try gossip.sendPullRequest(.{ .contact_info = gossip.contact_info });

    gossip.pull_request.run(loop, completion, PULL_REQUEST_RATE, Gossip, gossip, onPullRequest);
    return .disarm;
}

pub fn wallclock() u64 {
    return @intCast(std.time.milliTimestamp());
}
