const std = @import("std");
const Bloom = @This();
const Fnv = std.hash.Fnv1a_64;

keys: []align(1) u64,
bits: []align(1) u64,
max_bits: u64,

pub fn insert(b: *Bloom, new_key: []const u8) void {
    for (b.keys) |key| {
        var hasher: Fnv = .{ .value = key };
        hasher.update(new_key);
        const bit = hasher.final() % b.bits.len;
        b.bits[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
    }
}

pub fn contains(b: *Bloom, needle: []const u8) bool {
    for (b.keys) |key| {
        var hasher: Fnv = .{ .value = key };
        hasher.update(needle);
        const bit = hasher.final() % b.bits.len;
        if (b.bits[bit / 64] & @as(u64, 1) << @intCast(bit % 64) == 0) {
            return false;
        }
    }
    return true;
}

pub fn maxItems(max_bits: f64, num_keys: f64, false_positive_rate: f64) f64 {
    // TODO: document each step
    return @ceil(max_bits / (-num_keys / @log(1.0 - @exp(@log(false_positive_rate) / num_keys))));
}

pub fn numBits(num_items: f64, false_positive_rate: f64, max_bits: f64) u64 {
    const d: f64 = @log(1.0 / std.math.pow(f64, 2.0, @log(2.0)));
    const num_bits: f64 = @ceil((num_items * @log(false_positive_rate)) / d);
    return @intFromFloat(@max(1.0, @min(max_bits, num_bits)));
}
