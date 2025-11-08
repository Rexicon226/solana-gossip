const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const xev_mod = b.dependency("xev", .{
        .target = target,
        .optimize = optimize,
    }).module("xev");
    const base58_mod = b.dependency("base58", .{
        .target = target,
        .optimize = optimize,
    }).module("base58");

    const exe = b.addExecutable(.{
        .name = "gossip",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "xev", .module = xev_mod },
                .{ .name = "base58", .module = base58_mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "");
    run_step.dependOn(&b.addRunArtifact(exe).step);
}
