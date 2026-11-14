//! TR-100 machine report — a fork-free port of machine_report.sh.
//!
//! Every value the bash script spawned a process for is read in-process:
//! /proc, /sys, /etc, utmp, lastlog and TZif through std.Io, plus one raw
//! netlink socket (std.Io has no NETLINK_ROUTE path) and a few syscalls
//! with no Io equivalent (statfs, uname, readlinkat, getuid). The report
//! renders into the stdout writer's buffer and flushes once.
//!
//! The frame, column widths and bar quirks are the script's, including
//! the unclamped over-100% load bar. Five rows report what the script
//! meant to print instead of what its field picks produced:
//!
//!   - OS drops a codename that VERSION already carries.
//!   - CPU FREQ falls back to the last-level cache when the host exposes
//!     no clock (most arm64 servers), instead of " GHz".
//!   - MACHINE IP prefers the default-route interface and lists the
//!     other interfaces' addresses on continuation rows.
//!   - VOLUME is one row per filesystem, not just /, so a btrfs volume
//!     with several subvolumes shows once.
//!   - LAST LOGIN keeps the month, weekday and year fields the awk cut
//!     dropped.

const std = @import("std");
const Io = std.Io;
const process = std.process;
const heap = std.heap;
const assert = std.debug.assert;
const mem = std.mem;
const posix = std.posix;
const testing = std.testing;
const linux = std.os.linux;
const builtin = @import("builtin");

const use_safe_allocator = switch (builtin.mode) {
    .debug, .safe => true,
    .fast, .small => false,
};
var safe_allocator: heap.SafeAllocator = .init(heap.page_allocator, .{});

// Basic configuration, mirrors the script's globals. Edit as needed.
const report_title = "UNITED STATES GRAPHICS COMPANY";
const max_name_len = 13;
const max_data_len = 32;
const borders_and_padding = 7;

// Hard upper bounds on every input read. All real-world inputs sit far
// below these; a bound miss degrades to the same "empty value" the bash
// script rendered from a failed grep.
const etc_read_max = 64 * 1024;
const cpuinfo_read_max = 128 * 1024;
const mounts_read_max = 256 * 1024;
const utmp_read_max = 256 * 1024;
const tz_read_max = 256 * 1024;
const read_max = 16 * 1024;
const sysfs_read_max = 4096;
const max_dns_entries = 8;
const max_present_cpus = 1024;
const max_netlink_rounds = 64;
const recv_buf_len = 4096;

const stdout_buffer_len = 16 * 1024;

/// Whitespace-run tokenizer with awk field semantics: fields are 1-based,
/// runs of blanks collapse, out-of-range fields read as empty.
const Fields = struct {
    const max_fields = 16;

    items: [max_fields][]const u8 = @splat(&.{}),
    count: u8 = 0,

    fn parse(row: []const u8) Fields {
        var self: Fields = .{};
        var i: usize = 0;
        while (i < row.len and self.count < max_fields) {
            while (i < row.len and (row[i] == ' ' or row[i] == '\t')) i += 1;
            const start = i;
            while (i < row.len and row[i] != ' ' and row[i] != '\t') i += 1;
            if (i > start) {
                self.items[self.count] = row[start..i];
                self.count += 1;
            }
        }
        return self;
    }

    /// awk's $N.
    fn at(self: Fields, awk_index: u8) []const u8 {
        return if (awk_index == 0 or awk_index > self.count) &.{} else self.items[awk_index - 1];
    }
};

test "Fields awk semantics" {
    const f: Fields = .parse("matt pts/1 45.26.44.184 Sat Sep 26 12:06:18 -0700 2026");
    try testing.expectEqualStrings("matt", f.at(1));
    try testing.expectEqualStrings("45.26.44.184", f.at(3));
    try testing.expectEqualStrings("", f.at(10));
    try testing.expectEqualStrings("", f.at(99));
}

fn codepointCount(s: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const seq_len = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        i += @min(seq_len, s.len - i);
        n += 1;
    }
    return n;
}

/// cut(1) -c semantics: keep the first n codepoints (not bytes, not cells).
fn cutCodepoints(s: []const u8, n: usize) []const u8 {
    var i: usize = 0;
    var count: usize = 0;
    while (i < s.len and count < n) {
        const seq_len = std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        i += @min(seq_len, s.len - i);
        count += 1;
    }
    return s[0..i];
}

test cutCodepoints {
    try testing.expectEqualStrings("abc", cutCodepoints("abcdef", 3));
    try testing.expectEqualStrings("█", cutCodepoints("██░░", 1));
    try testing.expectEqualStrings("", cutCodepoints("abc", 0));
}

/// printf %Ns padding: right-pad to width bytes (every data string on the
/// verified hosts is ASCII; bash pads bytes here too).
fn padRight(w: *Io.Writer, s: []const u8, width: usize) !void {
    try w.writeAll(s);
    var i: usize = s.len;
    while (i < width) : (i += 1) try w.writeAll(" ");
}

fn parseUint(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var v: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

test parseUint {
    try testing.expectEqual(@as(?u64, 16000836), parseUint("16000836"));
    try testing.expectEqual(@as(?u64, null), parseUint("1.5"));
    try testing.expectEqual(@as(?u64, null), parseUint(""));
}

/// Parse "2400.000" as 2,400,000 milli-units (cpuinfo's MHz precision).
fn parseDecimalMilli(s: []const u8) ?u64 {
    const dot = mem.findScalar(u8, s, '.') orelse return parseUint(s) orelse null;
    const int_part = parseUint(s[0..dot]) orelse return null;
    var frac: u64 = 0;
    var scale: u64 = 1000;
    for (s[dot + 1 ..]) |c| {
        if (c < '0' or c > '9') return null;
        frac = frac * 10 + (c - '0');
        if (scale > 1) scale /= 10;
    }
    return int_part * 1000 + frac * scale;
}

test parseDecimalMilli {
    try testing.expectEqual(@as(?u64, 2400000), parseDecimalMilli("2400.000"));
    try testing.expectEqual(@as(?u64, 1899), parseDecimalMilli("1.899"));
    try testing.expectEqual(@as(?u64, 18370), parseDecimalMilli("18.37"));
}

fn parseHexU64(s: []const u8) ?u64 {
    const body = if (mem.startsWith(u8, s, "0x") or mem.startsWith(u8, s, "0X")) s[2..] else s;
    if (body.len == 0 or body.len > 16) return null;
    var v: u64 = 0;
    for (body) |c| {
        const digit: u8 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => return null,
        };
        v = v * 16 + digit;
    }
    return v;
}

test parseHexU64 {
    try testing.expectEqual(@as(?u64, 0x410fd841), parseHexU64("0x00000000410fd841"));
    try testing.expectEqual(@as(?u64, null), parseHexU64("0x"));
}

/// The script's IPv4 test, replicated: ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$.
fn isDottedQuad(s: []const u8) bool {
    var octets: usize = 0;
    var digits: usize = 0;
    for (s) |c| {
        if (c >= '0' and c <= '9') {
            digits += 1;
        } else if (c == '.') {
            if (digits == 0) return false;
            octets += 1;
            digits = 0;
        } else {
            return false;
        }
    }
    return octets == 3 and digits > 0;
}

test isDottedQuad {
    try testing.expect(isDottedQuad("45.26.44.184"));
    try testing.expect(isDottedQuad("127.0.0.1"));
    try testing.expect(!isDottedQuad("::1"));
    try testing.expect(!isDottedQuad("myhost.example"));
    try testing.expect(!isDottedQuad("1.2.3."));
    try testing.expect(!isDottedQuad(""));
}

/// Round a/b to nearest, ties to even — glibc printf under the default
/// FE_TONEAREST mode, which is what the script's awk does. Callers keep
/// products under 2^63 (meminfo KiB and statfs block counts are far below).
fn roundDiv(a: u64, b: u64) u64 {
    assert(b != 0);
    const q = a / b;
    const r = a % b;
    const twice_r = r * 2;
    return q + @intFromBool(twice_r > b or (twice_r == b and q % 2 == 1));
}

/// ceil((a * b) / denom) for products that can exceed u64 (block counts).
fn divCeilProduct(a: u64, b: u64, denom: u64) u64 {
    assert(denom != 0);
    const product: u128 = @as(u128, a) * @as(u128, b);
    return @intCast((product + denom - 1) / denom);
}

test "roundDiv and divCeilProduct" {
    try testing.expectEqual(@as(u64, 2), roundDiv(5, 2)); // tie: 2 is even
    try testing.expectEqual(@as(u64, 4), roundDiv(7, 2)); // tie: 3 is odd
    try testing.expectEqual(@as(u64, 3), roundDiv(6, 2));
    try testing.expectEqual(@as(u64, 0), roundDiv(1, 2)); // tie: 0 is even
    try testing.expectEqual(@as(u64, 2), roundDiv(4, 2));
    // df(1) rounds up: 64419632 blocks * 4096 / 2^20 = 251639.19 -> 251640.
    try testing.expectEqual(@as(u64, 251640), divCeilProduct(64419632, 4096, 1 << 20));
    try testing.expectEqual(@as(u64, 204061), divCeilProduct(52239575, 4096, 1 << 20));
}

/// percent with two decimals, in hundredths: round(used/total * 10000).
/// The two-step rounding matters: upstream's awk rounds the percent
/// before deriving bar width, so the rounding is load-bearing.
fn percentHundredths(used: u64, total: u64) u64 {
    if (total == 0) return 0;
    return roundDiv(used * 10000, total);
}

fn writeHundredths(w: *Io.Writer, hundredths: u64) !void {
    try w.print("{d}.{d:0>2}", .{ hundredths / 100, hundredths % 100 });
}

/// Fixed-writer overflow handler: keep the truncated prefix. The display
/// layer cuts every string to column width anyway, so the prefix renders
/// exactly like upstream's PRINT_DATA would have cut it.
fn keepTruncated(err: anyerror) void {
    // Only NoSpaceLeft reaches here; the truncation is the intended result.
    assert(err == error.NoSpaceLeft);
}

test writeHundredths {
    var buf: [32]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeHundredths(&w, 1087);
    try testing.expectEqualStrings("10.87", w.buffered());
}

/// A bounded, owned string — the bash script's global variables, with a
/// capacity and no allocator.
fn Str(comptime capacity: comptime_int) type {
    return struct {
        const Self = @This();
        const Int = std.math.IntFittingRange(0, capacity);

        bytes: [capacity]u8 = undefined,
        len: Int = 0,

        fn view(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }

        /// Caller guarantees the value fits (fixed-size kernel inputs).
        fn set(self: *Self, s: []const u8) void {
            assert(s.len <= capacity);
            @memcpy(self.bytes[0..s.len], s);
            self.len = @intCast(s.len);
        }

        /// File-derived values can be arbitrarily long; truncate, the
        /// same way upstream's PRINT_DATA cut them for display anyway.
        fn setTrunc(self: *Self, s: []const u8) void {
            const n = @min(s.len, capacity);
            @memcpy(self.bytes[0..n], s[0..n]);
            self.len = @intCast(n);
        }

        fn print(self: *Self, comptime format: []const u8, args: anytype) void {
            const written = mem.print(self.bytes[self.len..], format, args) catch {
                self.len = capacity;
                return;
            };
            self.len += @intCast(written.len);
        }
    };
}

// ------------------------------------------------------------ std.Io input

/// Read a whole file into a caller-provided buffer; errors read as empty,
/// which is the bash script's grep-fails-anything semantics.
fn readFileOrEmpty(io: Io, path: []const u8, buffer: []u8) []const u8 {
    return Io.Dir.cwd().readFile(io, path, buffer) catch buffer[0..0];
}

/// The lastlog access pattern: one fixed-size record at uid * 296.
fn readRecordOrEmpty(io: Io, path: []const u8, buffer: []u8, offset: u64) []const u8 {
    const file = Io.Dir.cwd().openFile(io, path, .{}) catch return buffer[0..0];
    defer file.close(io);
    const n = file.readPositionalAll(io, buffer, offset) catch return buffer[0..0];
    return buffer[0..n];
}

// ------------------------------------------------------ kernel ABI (hand-set)

// struct statfs, LP64 layout (x86_64 and aarch64 agree). No std.Io path.
const StatFs = extern struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_namelen: u64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

comptime {
    assert(@sizeOf(StatFs) == 120);
}

// struct utmp, LP64 layout: 400 bytes. The padding must sit where glibc
// puts it, because login(1)/sshd initialize these records field by field.
const UtmpRecord = extern struct {
    ut_type: i16,
    _pad0: u16 = 0,
    ut_pid: i32,
    ut_line: [32]u8,
    ut_id: [4]u8,
    ut_user: [32]u8,
    ut_host: [256]u8,
    e_termination: i16,
    e_exit: i16,
    ut_session: i64,
    ut_tv_sec: i64,
    ut_tv_usec: i64,
    ut_addr_v6: [4]u32,
    reserved: [20]u8,
};

comptime {
    assert(@sizeOf(UtmpRecord) == 400);
}

const ut_user_process: i16 = 7;

// struct lastlog, LP64 layout: 296 bytes, one record per uid.
const LastlogRecord = extern struct {
    ll_time: i64,
    ll_line: [32]u8,
    ll_host: [256]u8,
};

comptime {
    assert(@sizeOf(LastlogRecord) == 296);
}

// ------------------------------------------------------------------- netlink

// No std.Io path exists for NETLINK_ROUTE dumps, so this section is the
// one place raw linux calls are earned: socket, bind, sendto, recvfrom.

const SockaddrNl = extern struct {
    family: u16,
    _pad: u16 = 0,
    pid: u32 = 0,
    groups: u32 = 0,
};

const NlMsgHdr = extern struct {
    len: u32,
    type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
};

const RtGenMsg = extern struct { family: u8 };

const IfInfoMsg = extern struct {
    family: u8,
    _pad: u8 = 0,
    type: u16 = 0,
    index: i32,
    flags: u32 = 0,
    change: u32 = 0,
};

const IfAddrMsg = extern struct {
    family: u8,
    prefixlen: u8 = 0,
    flags: u8 = 0,
    scope: u8 = 0,
    index: u32,
};

const RtAttr = extern struct {
    len: u16,
    type: u16,
};

// linux/if_link.h, linux/if_addr.h, linux/netlink.h constants.
const rtm_getlink: u16 = 18;
const rtm_newlink: u16 = 16;
const rtm_getaddr: u16 = 22;
const rtm_newaddr: u16 = 20;
const nlmsg_done: u16 = 3;
const nlm_f_dump: u16 = 0x301; // NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH
const ifla_ifname: u16 = 3;
const ifa_local: u16 = 2;
const ifa_address: u16 = 1;
const af_inet: u8 = 2;
const af_inet6: u8 = 10;
const nlmsg_align_to: usize = 4;

/// Interface names by ifindex, straight off an RTM_GETLINK dump.
const IfaceNames = struct {
    names: [1024]Str(16) = @splat(.{}),

    fn byIndex(self: *const IfaceNames, index: u32) []const u8 {
        if (index == 0 or index >= self.names.len) return &.{};
        return self.names[index].view();
    }

    fn byName(self: *const IfaceNames, iface: []const u8) u32 {
        if (iface.len == 0) return 0;
        for (self.names, 0..) |slot, i| {
            if (mem.eql(u8, slot.view(), iface)) return @intCast(i);
        }
        return 0;
    }
};

/// Virtual interfaces (bridge, veth, container, tunnel) that can carry
/// an address they only inherited from a real one. The default route
/// bypasses this list: it names the interface the host actually uses.
const virtual_iface_prefixes = [_][]const u8{
    "docker", "br-", "veth", "virbr", "podman", "cni", "flannel",
    "cali",   "lxc", "tap",  "tunl",  "dummy",
};

fn isReportedIface(name: []const u8) bool {
    if (name.len == 0 or mem.eql(u8, name, "lo")) return false;
    for (virtual_iface_prefixes) |prefix| {
        if (mem.startsWith(u8, name, prefix)) return false;
    }
    return true;
}

test isReportedIface {
    try testing.expect(isReportedIface("ens34"));
    try testing.expect(isReportedIface("tailscale0"));
    try testing.expect(isReportedIface("wlp0s20f3"));
    try testing.expect(!isReportedIface("lo"));
    try testing.expect(!isReportedIface("docker0"));
    try testing.expect(!isReportedIface("br-dcdc88f09349"));
    try testing.expect(!isReportedIface("virbr0"));
    try testing.expect(!isReportedIface("veth1a2b3c"));
}

fn netlinkSocket() ?i32 {
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return null;
    return @intCast(rc);
}

fn netlinkBind(fd: i32) bool {
    const sa: SockaddrNl = .{ .family = linux.AF.NETLINK };
    const rc = linux.bind(fd, @ptrCast(&sa), @sizeOf(SockaddrNl));
    return linux.errno(rc) == .SUCCESS;
}

fn netlinkSendDump(fd: i32, msg_type: u16, seq: u32) bool {
    // Zero-filled to 20 bytes: NLMSG_ALIGN(17) with the pad covered, the
    // same shape ip(8) sends for a family-0 dump request.
    var req = mem.zeroes(extern struct {
        hdr: NlMsgHdr,
        gen: RtGenMsg,
        pad: [3]u8,
    });
    req.hdr = .{ .len = 20, .type = msg_type, .flags = nlm_f_dump, .seq = seq, .pid = 0 };
    const rc = linux.sendto(fd, @ptrCast(&req), req.hdr.len, 0, null, 0);
    return linux.errno(rc) == .SUCCESS;
}

const WalkResult = enum { done, more, malformed };

/// Walk one netlink datagram. Whole messages only: bad framing is
/// malformed (stop the dump) rather than garbage to parse.
fn netlinkWalk(
    buf: []const u8,
    ctx: anytype,
    onMsg: fn (ctx: @TypeOf(ctx), msg: *const NlMsgHdr) void,
) WalkResult {
    var off: usize = 0;
    while (off + @sizeOf(NlMsgHdr) <= buf.len) {
        // off is NLMSG_ALIGN'd by the loop itself, so the alignCast below
        // is a runtime assert of the kernel's framing, not a hope.
        const msg: *const NlMsgHdr = @ptrCast(@alignCast(buf[off..].ptr));
        if (msg.len < @sizeOf(NlMsgHdr) or off + msg.len > buf.len) return .malformed;
        onMsg(ctx, msg);
        if (msg.type == nlmsg_done) return .done;
        off += mem.alignForward(usize, msg.len, nlmsg_align_to);
    }
    return .more;
}

/// One dump request's full response: recv until DONE, bounded rounds.
fn netlinkRecvDump(
    fd: i32,
    msg_type: u16,
    seq: u32,
    ctx: anytype,
    onMsg: fn (ctx: @TypeOf(ctx), msg: *const NlMsgHdr) void,
) bool {
    if (!netlinkSendDump(fd, msg_type, seq)) return false;
    var recv_buf: [recv_buf_len]u8 = undefined;
    while (true) {
        const rc = linux.recvfrom(fd, &recv_buf, recv_buf.len, 0, null, null);
        if (linux.errno(rc) != .SUCCESS) return false;
        const n: usize = @intCast(rc);
        switch (netlinkWalk(recv_buf[0..n], ctx, onMsg)) {
            .done => return true,
            .more => continue,
            .malformed => return false,
        }
    }
}

fn dumpLinkNames(fd: i32, out: *IfaceNames) bool {
    const LinkCtx = struct {
        const Self = @This();

        names: *IfaceNames,

        fn on(self: Self, msg: *const NlMsgHdr) void {
            if (msg.type != rtm_newlink) return;
            if (msg.len < @sizeOf(NlMsgHdr) + @sizeOf(IfInfoMsg)) return;
            const raw: [*]align(4) const u8 = @ptrCast(msg);
            const info: *const IfInfoMsg = @ptrCast(raw + @sizeOf(NlMsgHdr));
            var attr_off: usize = @sizeOf(NlMsgHdr) + @sizeOf(IfInfoMsg);
            while (attr_off + @sizeOf(RtAttr) <= msg.len) {
                const attr: *const RtAttr = @ptrCast(@alignCast(raw + attr_off));
                if (attr.len < @sizeOf(RtAttr)) return;
                if (attr.type == ifla_ifname) {
                    const start = attr_off + @sizeOf(RtAttr);
                    const name_len = @min(@as(usize, attr.len) - @sizeOf(RtAttr), msg.len - start);
                    const ifindex: u32 = @intCast(info.index);
                    if (ifindex > 0 and ifindex < self.names.names.len) {
                        // IFLA_IFNAME is NUL-terminated with padding; a
                        // stored "lo\0" would sail past the lo filter.
                        const name_value = raw[start .. start + name_len];
                        const name_end = mem.findScalar(u8, name_value, 0) orelse name_value.len;
                        self.names.names[ifindex].setTrunc(name_value[0..name_end]);
                    }
                }
                attr_off += mem.alignForward(usize, attr.len, nlmsg_align_to);
            }
        }
    };
    const seq: u32 = 1;
    return netlinkRecvDump(fd, rtm_getlink, seq, LinkCtx{ .names = out }, LinkCtx.on);
}

/// RFC 5952: lowercase groups, longest zero-run (>= 2 groups) as "::".
fn writeIpv6Compressed(w: *Io.Writer, raw: []const u8) !void {
    if (raw.len < 16) return;
    var groups: [8]u16 = undefined;
    for (0..8) |i| groups[i] = (@as(u16, raw[i * 2]) << 8) | raw[i * 2 + 1];
    var best_start: usize = 0;
    var best_len: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (groups[i] != 0) {
            i += 1;
            continue;
        }
        var run: usize = 0;
        while (i + run < 8 and groups[i + run] == 0) run += 1;
        if (run > best_len) {
            best_len = run;
            best_start = i;
        }
        i += run;
    }
    var need_colon = false;
    var g: usize = 0;
    while (g < 8) {
        if (best_len >= 2 and g == best_start) {
            try w.writeAll("::");
            g += best_len;
            need_colon = false;
            continue;
        }
        if (need_colon) try w.writeAll(":");
        try w.print("{x}", .{groups[g]});
        need_colon = true;
        g += 1;
    }
}

test "writeIpv6Compressed" {
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var raw: [16]u8 = @splat(0);
    raw[0] = 0xfe;
    raw[1] = 0x80;
    raw[15] = 0x01; // fe80::1
    try writeIpv6Compressed(&w, &raw);
    try testing.expectEqualStrings("fe80::1", w.buffered());

    var w2: Io.Writer = .fixed(&buf);
    raw = @splat(0);
    raw[15] = 1; // ::1
    try writeIpv6Compressed(&w2, &raw);
    try testing.expectEqualStrings("::1", w2.buffered());

    var w3: Io.Writer = .fixed(&buf);
    try writeIpv6Compressed(&w3, "short");
    try testing.expectEqualStrings("", w3.buffered());
}

const max_machine_addrs = 4;

const MachineAddr = struct {
    addr: Str(64) = .{},
    ifindex: u32 = 0,
};

/// Every global address on a real interface, in dump order. The
/// default-route interface is moved to the front: it is the address a
/// client reaches this box on, not whichever ifindex the kernel
/// happened to number first (docker bridges used to win that race).
const AddrList = struct {
    items: [max_machine_addrs]MachineAddr = @splat(.{}),
    count: u8 = 0,

    fn add(self: *AddrList, index: u32, text: []const u8) void {
        if (self.count == max_machine_addrs) return;
        self.items[self.count] = .{ .ifindex = index };
        self.items[self.count].addr.setTrunc(text);
        self.count += 1;
    }

    fn putPreferredFirst(self: *AddrList, preferred: u32) void {
        if (preferred == 0) return;
        for (self.items[0..self.count], 0..) |item, i| {
            if (item.ifindex != preferred) continue;
            const first = self.items[0];
            self.items[0] = item;
            self.items[i] = first;
            return;
        }
    }
};

fn formatIpv4(raw: []const u8, out: *Str(64)) void {
    if (raw.len < 4) return;
    var w: Io.Writer = .fixed(out.bytes[0..]);
    w.print("{d}.{d}.{d}.{d}", .{ raw[0], raw[1], raw[2], raw[3] }) catch return;
    out.len = @intCast(w.buffered().len);
}

fn formatIpv6(raw: []const u8, out: *Str(64)) void {
    var w: Io.Writer = .fixed(out.bytes[0..]);
    writeIpv6Compressed(&w, raw) catch return;
    out.len = @intCast(w.buffered().len);
}

/// fe80::/10, ::1, and the all-zeros address: link-local and loopback
/// say nothing about how to reach the machine.
fn isUsableIpv6(raw: []const u8) bool {
    if (raw.len < 16) return false;
    if (raw[0] == 0xfe and (raw[1] & 0xc0) == 0x80) return false;
    for (raw[0..15]) |byte| {
        if (byte != 0) return true;
    }
    // Only :: and ::1 are left in the 0:...:n space.
    return raw[15] > 1;
}

test isUsableIpv6 {
    var global: [16]u8 = @splat(0);
    global[0] = 0x26;
    global[1] = 0x20;
    try testing.expect(isUsableIpv6(&global));
    var link_local: [16]u8 = @splat(0);
    link_local[0] = 0xfe;
    link_local[1] = 0x80;
    link_local[15] = 1;
    try testing.expect(!isUsableIpv6(&link_local));
    var loopback: [16]u8 = @splat(0);
    loopback[15] = 1;
    try testing.expect(!isUsableIpv6(&loopback));
}

fn dumpAddrs(fd: i32, names: *const IfaceNames, preferred: u32, out: *AddrList) bool {
    const AddrCtx = struct {
        const Self = @This();

        names: *const IfaceNames,
        list: *AddrList,
        preferred: u32,
        v6: Str(64) = .{},
        have_v6: bool = false,

        fn on(self: *Self, msg: *const NlMsgHdr) void {
            if (msg.type != rtm_newaddr) return;
            if (msg.len < @sizeOf(NlMsgHdr) + @sizeOf(IfAddrMsg)) return;
            const raw: [*]align(4) const u8 = @ptrCast(msg);
            const addr: *const IfAddrMsg = @ptrCast(raw + @sizeOf(NlMsgHdr));
            const is_v4 = addr.family == af_inet;
            const is_v6 = addr.family == af_inet6;
            if (!is_v4 and !is_v6) return;
            // The default route wins over the virtual-interface filter.
            const is_preferred = self.preferred != 0 and addr.index == self.preferred;
            if (!is_preferred and !isReportedIface(self.names.byIndex(addr.index))) return;
            if (is_v4 and self.list.count == max_machine_addrs) return;
            if (is_v6 and self.have_v6) return;

            var attr_off: usize = @sizeOf(NlMsgHdr) + @sizeOf(IfAddrMsg);
            while (attr_off + @sizeOf(RtAttr) <= msg.len) {
                const attr: *const RtAttr = @ptrCast(@alignCast(raw + attr_off));
                if (attr.len < @sizeOf(RtAttr)) return;
                // ip(8) reports IFA_LOCAL for IPv4 and IFA_ADDRESS for
                // IPv6; ifconfig's inet/inet6 lines carry the same bytes.
                const relevant = if (is_v4)
                    (attr.type == ifa_local or attr.type == ifa_address)
                else
                    attr.type == ifa_address;
                if (relevant) {
                    const start = attr_off + @sizeOf(RtAttr);
                    const raw_len = @min(@as(usize, attr.len) - @sizeOf(RtAttr), msg.len - start);
                    const value = raw[start .. start + raw_len];
                    if (is_v4) {
                        var text: Str(64) = .{};
                        formatIpv4(value, &text);
                        if (text.len > 0) self.list.add(addr.index, text.view());
                    } else if (isUsableIpv6(value)) {
                        formatIpv6(value, &self.v6);
                        self.have_v6 = self.v6.len > 0;
                    }
                    return;
                }
                attr_off += mem.alignForward(usize, attr.len, nlmsg_align_to);
            }
        }
    };
    const seq: u32 = 101;
    var ctx: AddrCtx = .{ .names = names, .list = out, .preferred = preferred };
    if (!netlinkRecvDump(fd, rtm_getaddr, seq, &ctx, AddrCtx.on)) return false;
    // IPv6 is the fallback address family, and only the first one: a
    // tailnet assigns a v4 and a v6 to the same interface, and printing
    // both says nothing extra.
    if (ctx.list.count == 0 and ctx.have_v6) ctx.list.add(0, ctx.v6.view());
    return true;
}

/// The interface carrying the IPv4 default route, by lowest metric.
fn defaultRouteIface(route: []const u8, out: *Str(16)) void {
    out.setTrunc("");
    var best_metric: u64 = std.math.maxInt(u64);
    var rest = route;
    var header = true;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        if (header) {
            header = false;
            continue;
        }
        // iface destination gateway flags refcnt use metric mask ...
        const fields: Fields = .parse(line);
        if (!mem.eql(u8, fields.at(2), "00000000")) continue;
        if (!mem.eql(u8, fields.at(8), "00000000")) continue;
        const metric = parseUint(fields.at(7)) orelse 0;
        if (metric > best_metric) continue;
        best_metric = metric;
        out.setTrunc(fields.at(1));
    }
}

test defaultRouteIface {
    const route = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask" ++
        "\t\tMTU\tWindow\tIRTT\n" ++
        "docker0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" ++
        "ens34\t00000000\t01012A0A\t0003\t0\t0\t1002\t00000000\t0\t0\t0\n" ++
        "ens34\t00012A0A\t00000000\t0001\t0\t0\t1002\t00FFFFFF\t0\t0\t0\n";
    var out: Str(16) = .{};
    defaultRouteIface(route, &out);
    try testing.expectEqualStrings("ens34", out.view());
}

/// MACHINE IP row plus one continuation row per extra interface, so a
/// host with a LAN address and a tailnet address shows both.
fn gatherMachineIps(
    io: Io,
    primary: *Str(64),
    extra: *[max_machine_addrs]Str(64),
    extra_count: *u8,
) void {
    extra_count.* = 0;
    var route_buf: [read_max]u8 = undefined;
    const route = readFileOrEmpty(io, "/proc/net/route", &route_buf);
    var preferred_name: Str(16) = .{};
    defaultRouteIface(route, &preferred_name);

    var list: AddrList = .{};
    const fd = netlinkSocket() orelse {
        primary.set("No IP found");
        return;
    };
    defer _ = linux.close(fd);
    if (!netlinkBind(fd)) {
        primary.set("No IP found");
        return;
    }
    var names: IfaceNames = .{};
    if (!dumpLinkNames(fd, &names)) {
        primary.set("No IP found");
        return;
    }
    const preferred = names.byName(preferred_name.view());
    if (!dumpAddrs(fd, &names, preferred, &list) or list.count == 0) {
        primary.set("No IP found");
        return;
    }
    list.putPreferredFirst(preferred);

    primary.setTrunc(list.items[0].addr.view());
    for (list.items[1..list.count]) |item| {
        var row = &extra[extra_count.*];
        row.print("{s} {s}", .{ names.byIndex(item.ifindex), item.addr.view() });
        extra_count.* += 1;
    }
}

// ------------------------------------------------------------ calendar math

/// Days since 1970-01-01 to civil date (Howard Hinnant's algorithm).
fn civilFromDays(days: i64) struct { year: i64, month: u32, day: u32 } {
    const z: i64 = days + 719468;
    const era: i64 = @divFloor(z, 146097);
    const doe: i64 = z - era * 146097; // [0, 146096]
    // [0, 399]: year of era, leap corrections applied per Hinnant.
    const yoe: i64 = @divFloor(
        doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096),
        365,
    );
    const y: i64 = yoe + era * 400;
    const doy: i64 = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100)); // [0, 365]
    const mp: i64 = @divFloor(5 * doy + 2, 153); // [0, 11]
    const d: i64 = doy - @divFloor(153 * mp + 2, 5) + 1; // [1, 31]
    const m: i64 = if (mp < 10) mp + 3 else mp - 9; // [1, 12]
    return .{ .year = if (m <= 2) y + 1 else y, .month = @intCast(m), .day = @intCast(d) };
}

/// 0 = Sunday ... 6 = Saturday. 1970-01-01 was a Thursday.
fn weekdayFromDays(days: i64) u3 {
    return @intCast(@mod(days + 4, 7));
}

const weekday_names = [7][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const month_names = [12][]const u8{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
};

test civilFromDays {
    const epoch = civilFromDays(0);
    try testing.expectEqual(@as(i64, 1970), epoch.year);
    try testing.expectEqual(@as(u32, 1), epoch.month);
    try testing.expectEqual(@as(u32, 1), epoch.day);
    try testing.expectEqual(@as(u3, 4), weekdayFromDays(0));

    // The fixture row from /var/log/lastlog: 2026-09-26, a Saturday.
    // (1790449578 - 25200) / 86400 = 20722 — the fixture epoch, local.
    const fixture_days: i64 = 20722;
    const fixture = civilFromDays(fixture_days);
    try testing.expectEqual(@as(i64, 2026), fixture.year);
    try testing.expectEqual(@as(u32, 9), fixture.month);
    try testing.expectEqual(@as(u32, 26), fixture.day);
    try testing.expectEqual(@as(u3, 6), weekdayFromDays(fixture_days));
}

// --------------------------------------------------------------- TZif (v2+)

/// The 64-bit data block of a TZif v2+ file: enough to answer "what was
/// the UTC offset at instant t", DST transitions included.
const Tz = struct {
    const max_transitions = 1024;
    const max_types = 128;

    transitions: [max_transitions]i64 = undefined,
    type_indices: [max_transitions]u8 = undefined,
    utoffs: [max_types]i32 = undefined,
    is_dst: std.bit_set.Static(max_types) = .empty,
    n_transitions: u16 = 0,
    n_types: u16 = 0,

    inline fn readInt(comptime T: type, buffer: *const [@divExact(@typeInfo(T).int.bits, 8)]u8) T {
        return mem.readInt(T, buffer, .big);
    }

    fn headerCounts(buf: []const u8) ?[6]u32 {
        if (buf.len < 44) return null;
        var counts: [6]u32 = undefined;
        for (0..6) |i| {
            counts[i] = readInt(u32, buf[20 + i * 4 ..][0..4]);
        }
        return counts;
    }

    fn parse(buf: []const u8) ?Tz {
        if (buf.len < 44) return null;
        if (!mem.eql(u8, buf[0..4], "TZif")) return null;
        const version = buf[4];
        if (version != '2' and version != '3' and version != '4') return null;

        const v1_counts = headerCounts(buf).?;
        // v1 data: per transition a 4-byte time and a 1-byte type index,
        // then typecnt*6 ttinfo, charcnt designations, leapcnt*8 leap
        // records, isstdcnt and isutcnt indicator bytes.
        const v1_data_len: usize =
            v1_counts[3] * 5 + v1_counts[4] * 6 + v1_counts[5] +
            v1_counts[2] * 8 + v1_counts[1] + v1_counts[0];
        const v2_start = 44 + v1_data_len;
        if (v2_start + 44 > buf.len) return null;
        if (!mem.eql(u8, buf[v2_start .. v2_start + 4], "TZif")) return null;

        const counts = headerCounts(buf[v2_start..]).?;
        // [0] isutcnt [1] isstdcnt [2] leapcnt [3] timecnt [4] typecnt
        // [5] charcnt; leap seconds are not parsed (not read, just sized).
        if (counts[3] > max_transitions) return null;
        if (counts[4] == 0 or counts[4] > max_types) return null;
        if (counts[5] > 8192 or counts[2] > 256) return null;

        var self: Tz = .{};
        self.n_transitions = @intCast(counts[3]);
        self.n_types = @intCast(counts[4]);
        var off: usize = v2_start + 44;
        for (0..counts[3]) |i| {
            if (off + 8 > buf.len) return null;
            self.transitions[i] = readInt(i64, buf[off..][0..8]);
            off += 8;
        }
        for (0..counts[3]) |i| {
            if (off >= buf.len) return null;
            self.type_indices[i] = buf[off];
            off += 1;
        }
        for (0..counts[4]) |i| {
            if (off + 6 > buf.len) return null;
            self.utoffs[i] = readInt(i32, buf[off..][0..4]);
            self.is_dst.setValue(i, buf[off + 4] != 0);
            off += 6;
        }
        return self;
    }

    /// Last transition at or before t. Before the first transition, the
    /// first non-DST type applies (the POSIX tzset rule).
    fn offsetAt(self: *const Tz, t: i64) i32 {
        var lo: usize = 0;
        var hi: usize = self.n_transitions;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (self.transitions[mid] <= t) lo = mid + 1 else hi = mid;
        }
        if (lo == 0) {
            var i: usize = 0;
            while (i < self.n_types) : (i += 1) {
                if (!self.is_dst.isSet(i)) return self.utoffs[i];
            }
            return if (self.n_types > 0) self.utoffs[0] else 0;
        }
        const index = self.type_indices[lo - 1];
        return if (index < self.n_types) self.utoffs[index] else 0;
    }
};

test "Tz parse and offsetAt" {
    // Synthetic TZif v2: type 0 is PST (-8:00, standard), type 1 is PDT
    // (-7:00, DST), one transition at 2026-03-08T10:00Z into type 1.
    var buf: [512]u8 = @splat(0);
    @memcpy(buf[0..4], "TZif");
    buf[4] = '2';
    // v1 header: two transitions (a 4-byte time plus a 1-byte type
    // index each) and one designation byte. A wrong v1 block size would
    // skip past the v2 magic and fail the parse — the regression the
    // real /etc/localtime caught (v1 timecnt was under-counted).
    mem.writeInt(u32, buf[32..][0..4], 2, .big); // timecnt
    mem.writeInt(u32, buf[40..][0..4], 1, .big); // charcnt
    var off: usize = 44 + 2 * 5 + 1; // v1 data
    @memcpy(buf[off..][0..4], "TZif");
    buf[off + 4] = '2';
    const v2 = off;
    mem.writeInt(u32, buf[v2 + 32 ..][0..4], 1, .big); // timecnt
    mem.writeInt(u32, buf[v2 + 36 ..][0..4], 2, .big); // typecnt
    mem.writeInt(u32, buf[v2 + 40 ..][0..4], 4, .big); // charcnt
    off = v2 + 44;
    const spring_2026: i64 = 1772784000;
    mem.writeInt(i64, buf[off..][0..8], spring_2026, .big);
    off += 8;
    buf[off] = 1; // transition into type 1
    off += 1;
    mem.writeInt(i32, buf[off..][0..4], -8 * 3600, .big); // type 0: PST
    buf[off + 4] = 0;
    mem.writeInt(i32, buf[off + 6 ..][0..4], -7 * 3600, .big); // type 1: PDT
    buf[off + 10] = 1;

    const tz = Tz.parse(&buf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(i32, -8 * 3600), tz.offsetAt(spring_2026 - 1));
    try testing.expectEqual(@as(i32, -7 * 3600), tz.offsetAt(spring_2026));
    try testing.expectEqual(@as(i32, -8 * 3600), tz.offsetAt(0)); // pre-table
}

fn writeTzOffset(w: *Io.Writer, offset_seconds: i32) !void {
    const sign: u8 = if (offset_seconds < 0) '-' else '+';
    const magnitude: u32 = @intCast(@abs(offset_seconds));
    try w.print("{c}{d:0>2}{d:0>2}", .{ sign, magnitude / 3600, (magnitude % 3600) / 60 });
}

test writeTzOffset {
    var buf: [8]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeTzOffset(&w, -25200);
    try testing.expectEqualStrings("-0700", w.buffered());
}

// ------------------------------------------------------------- data sources

/// ${ID^} ${VERSION} ${VERSION_CODENAME^} — capitalized first character,
/// literal spaces between, exactly like the script's string.
fn gatherOsName(io: Io, out: *Str(64)) void {
    var os_release_buf: [read_max]u8 = undefined;
    const os_release = readFileOrEmpty(io, "/etc/os-release", &os_release_buf);
    formatOsName(os_release, out);
}

fn formatOsName(os_release: []const u8, out: *Str(64)) void {
    out.setTrunc("");
    var id: Str(32) = .{};
    var version: []const u8 = "";
    var codename: Str(32) = .{};
    var rest = os_release;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        const eq = mem.findScalar(u8, line, '=') orelse continue;
        const key = line[0..eq];
        var value = line[eq + 1 ..];
        const quoted = value.len >= 2 and
            (value[0] == '"' or value[0] == '\'') and
            value[value.len - 1] == value[0];
        if (quoted) {
            value = value[1 .. value.len - 1];
        }
        if (mem.eql(u8, key, "ID")) upperFirst(value, &id);
        if (mem.eql(u8, key, "VERSION")) version = value;
        if (mem.eql(u8, key, "VERSION_CODENAME")) upperFirst(value, &codename);
    }
    out.print("{s} {s}", .{ id.view(), version });
    // NixOS bakes the codename into VERSION ("26.11 (Zokor)"), so the
    // script's third field printed "Nixos 26.11 (Zokor) Zokor".
    if (codename.view().len > 0 and std.ascii.findIgnoreCase(version, codename.view()) == null) {
        out.print(" {s}", .{codename.view()});
    }
}

test formatOsName {
    var out: Str(64) = .{};
    formatOsName(
        "ID=nixos\nVERSION=\"26.11 (Zokor)\"\nVERSION_CODENAME=zokor\n",
        &out,
    );
    try testing.expectEqualStrings("Nixos 26.11 (Zokor)", out.view());
    formatOsName(
        "ID=debian\nVERSION=\"12 (bookworm)\"\nVERSION_CODENAME=bookworm\n",
        &out,
    );
    try testing.expectEqualStrings("Debian 12 (bookworm)", out.view());
    formatOsName(
        "ID=arch\nVERSION=\"rolling\"\nVERSION_CODENAME=\"\"\n",
        &out,
    );
    try testing.expectEqualStrings("Arch rolling", out.view());
}

fn upperFirst(s: []const u8, out: *Str(32)) void {
    out.setTrunc(s);
    if (out.len > 0 and out.bytes[0] >= 'a' and out.bytes[0] <= 'z') {
        out.bytes[0] -= 'a' - 'A';
    }
}

test upperFirst {
    var out: Str(32) = .{};
    upperFirst("nixos", &out);
    try testing.expectEqualStrings("Nixos", out.view());
    upperFirst("Zokor", &out);
    try testing.expectEqualStrings("Zokor", out.view());
}

/// "Linux 7.2.6 " — the trailing space is { uname; uname -r; } | tr '\n' ' '.
fn gatherKernel(uts: *const posix.utsname, out: *Str(64)) void {
    out.setTrunc("");
    out.print("{s} {s} ", .{ mem.sliceTo(&uts.sysname, 0), mem.sliceTo(&uts.release, 0) });
}

/// hostname -f, in-process: resolve our own hostname against /etc/hosts
/// (the files source glibc consults first). The canonical name is the
/// first name on the matching line; no match leaves "Not Defined".
fn resolveHostname(uts: *const posix.utsname, hosts: []const u8, out: *Str(128)) void {
    out.set("Not Defined");
    const hostname = mem.sliceTo(&uts.nodename, 0);
    var rest = hosts;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        if (line.len == 0 or line[0] == '#') continue;
        const fields: Fields = .parse(line);
        if (fields.count < 2) continue;
        // $1 is the address; match against names ($2 canonical, $3+ aliases).
        var i: u8 = 2;
        while (i <= fields.count) : (i += 1) {
            if (mem.eql(u8, fields.at(i), hostname)) {
                out.setTrunc(fields.at(2));
                return;
            }
        }
    }
}

test resolveHostname {
    const hosts = "127.0.0.1 localhost\n\n127.0.0.2 launchpad\n10.0.0.5 box.example.com box\n";
    var uts: posix.utsname = undefined;
    @memset(&uts.nodename, 0);
    @memcpy(uts.nodename[0.."launchpad".len], "launchpad");
    var out: Str(128) = .{};
    resolveHostname(&uts, hosts, &out);
    try testing.expectEqualStrings("launchpad", out.view());

    @memset(&uts.nodename, 0);
    @memcpy(uts.nodename[0.."box".len], "box");
    resolveHostname(&uts, hosts, &out);
    try testing.expectEqualStrings("box.example.com", out.view());

    @memset(&uts.nodename, 0);
    @memcpy(uts.nodename[0.."nope".len], "nope");
    resolveHostname(&uts, hosts, &out);
    try testing.expectEqualStrings("Not Defined", out.view());
}

/// nameserver lines whose value is digits-and-dots only — the script's
/// `^nameserver [0-9.]` regex never matched an IPv6 server either.
fn gatherDnsServers(io: Io, out: *[max_dns_entries]Str(64), count: *u8) void {
    var resolv_buf: [read_max]u8 = undefined;
    const resolv = readFileOrEmpty(io, "/etc/resolv.conf", &resolv_buf);
    gatherDnsServersScan(resolv, out, count);
}

fn gatherDnsServersScan(resolv: []const u8, out: *[max_dns_entries]Str(64), count: *u8) void {
    count.* = 0;
    var rest = resolv;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        const fields: Fields = .parse(line);
        if (!mem.eql(u8, fields.at(1), "nameserver")) continue;
        const server = fields.at(2);
        var digits_and_dots = server.len > 0;
        for (server) |c| {
            if ((c < '0' or c > '9') and c != '.') digits_and_dots = false;
        }
        if (digits_and_dots and count.* < max_dns_entries) {
            out[count.*].setTrunc(server);
            count.* += 1;
        }
    }
}

test gatherDnsServersScan {
    const resolv = "# Generated by resolvconf\n" ++
        "search tail45c3.ts.net\n" ++
        "nameserver 127.0.0.1\n" ++
        "nameserver fd00::1\n" ++
        "options edns0\n";
    var servers: [max_dns_entries]Str(64) = @splat(.{});
    var count: u8 = 0;
    gatherDnsServersScan(resolv, &servers, &count);
    try testing.expectEqual(@as(u8, 1), count);
    try testing.expectEqualStrings("127.0.0.1", servers[0].view());
}

fn passwdUserName(passwd: []const u8, uid: u32) ?[]const u8 {
    var rest = passwd;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        // name:x:uid:gid:gecos:home:shell
        const first = mem.findScalar(u8, line, ':') orelse continue;
        const second = mem.findScalar(u8, line[first + 1 ..], ':') orelse continue;
        const uid_start = first + 1 + second + 1;
        const third = mem.findScalar(u8, line[uid_start..], ':') orelse continue;
        const uid_field = line[uid_start .. uid_start + third];
        if (parseUint(uid_field)) |u| {
            if (u == uid) return line[0..first];
        }
    }
    return null;
}

test passwdUserName {
    const passwd = "root:x:0:0:System administrator:/root:/run/current-system/sw/bin/bash\n" ++
        "matt:x:1001:100::/home/matt:/run/current-system/sw/bin/zsh\n";
    try testing.expectEqualStrings("matt", passwdUserName(passwd, 1001).?);
    try testing.expectEqualStrings("root", passwdUserName(passwd, 0).?);
    try testing.expectEqual(@as(?[]const u8, null), passwdUserName(passwd, 42));
}

/// The client address of this session. $SSH_CONNECTION answers when the
/// session has no tty (ssh command, agent tooling); otherwise read the
/// USER_PROCESS record for our controlling terminal, where ut_host is the
/// address sshd recorded at login. readlinkat is raw because std.Io has
/// no readlink path. A local login records an empty host, which renders
/// the script's "Not connected".
fn gatherClientIp(io: Io, environ: process.Environ, out: *Str(256)) void {
    out.set("Not connected");
    if (sshConnectionPeer(environ)) |peer| {
        out.setTrunc(peer);
        return;
    }
    var tty_line: Str(32) = .{};
    if (!controllingTtyLine(&tty_line)) return;

    var utmp_buf: [utmp_read_max]u8 = undefined;
    const utmp = readFileOrEmpty(io, "/var/run/utmp", &utmp_buf);
    var off: usize = 0;
    while (off + @sizeOf(UtmpRecord) <= utmp.len) : (off += @sizeOf(UtmpRecord)) {
        // off advances by whole 400-byte records, so alignment holds.
        const record: *const UtmpRecord = @ptrCast(@alignCast(utmp[off..].ptr));
        if (record.ut_type != ut_user_process) continue;
        if (!mem.eql(u8, mem.sliceTo(&record.ut_line, 0), tty_line.view())) continue;
        const host = mem.sliceTo(&record.ut_host, 0);
        if (host.len == 0) return;
        out.setTrunc(host);
        return;
    }
}

/// "client_addr client_port server_addr server_port" -> client_addr.
fn sshConnectionPeer(environ: process.Environ) ?[]const u8 {
    const value = environ.getPosix("SSH_CONNECTION") orelse return null;
    const fields: Fields = .parse(value);
    return if (fields.at(1).len > 0) fields.at(1) else null;
}

/// The tty a process is attached to, even when stdin is a pipe: any
/// /proc/self/fd/N link into /dev counts. A shell that redirects all
/// three standard streams still keeps the terminal open.
fn controllingTtyLine(out: *Str(32)) bool {
    var link_buf: [64]u8 = undefined;
    for (0..16) |fd| {
        var path_buf: [33]u8 = undefined;
        const path = mem.print(path_buf[0..32], "/proc/self/fd/{d}", .{fd}) catch continue;
        path_buf[path.len] = 0;
        const rc = linux.readlinkat(
            posix.AT.FDCWD,
            @ptrCast(&path_buf),
            &link_buf,
            link_buf.len,
        );
        if (linux.errno(rc) != .SUCCESS) continue;
        const line = ttyLineFromLink(link_buf[0..@intCast(rc)]) orelse continue;
        out.setTrunc(line);
        return true;
    }
    return false;
}

/// /dev/pts/62 is "pts/62" in utmp; /dev/null and pipes are not ttys.
fn ttyLineFromLink(link: []const u8) ?[]const u8 {
    if (!mem.startsWith(u8, link, "/dev/")) return null;
    const line = link[5..];
    if (mem.startsWith(u8, line, "pts/") or mem.startsWith(u8, line, "tty")) return line;
    return null;
}

test ttyLineFromLink {
    try testing.expectEqualStrings("pts/62", ttyLineFromLink("/dev/pts/62").?);
    try testing.expectEqualStrings("tty1", ttyLineFromLink("/dev/tty1").?);
    try testing.expectEqual(@as(?[]const u8, null), ttyLineFromLink("/dev/null"));
    try testing.expectEqual(@as(?[]const u8, null), ttyLineFromLink("pipe:[10307679]"));
    try testing.expectEqual(@as(?[]const u8, null), ttyLineFromLink("/dev/shm"));
}

test "UtmpRecord field offsets" {
    var raw: [@sizeOf(UtmpRecord)]u8 align(@alignOf(UtmpRecord)) = @splat(0);
    const record: *UtmpRecord = @ptrCast(&raw);
    record.ut_type = ut_user_process;
    @memcpy(record.ut_line[0.."pts/1".len], "pts/1");
    @memcpy(record.ut_host[0.."45.26.44.184".len], "45.26.44.184");
    try testing.expectEqualStrings("pts/1", mem.sliceTo(&record.ut_line, 0));
    try testing.expectEqualStrings("45.26.44.184", mem.sliceTo(&record.ut_host, 0));
}

// ------------------------------------------------------------------- CPU

// ID -> name for implementer 0x41 (ARM). Copied from util-linux 2.42.3
// sys-utils/lscpu-arm.c (GPL-2.0-or-later) — the same factual mapping
// lscpu prints, restricted to the server parts; unknown IDs read empty,
// which is lscpu's behavior too (no "Model name" line at all).
const ArmPart = struct { id: u16, name: []const u8 };
const arm_parts = [_]ArmPart{
    .{ .id = 0xc05, .name = "Cortex-A5" },
    .{ .id = 0xc07, .name = "Cortex-A7" },
    .{ .id = 0xc08, .name = "Cortex-A8" },
    .{ .id = 0xc09, .name = "Cortex-A9" },
    .{ .id = 0xc0d, .name = "Cortex-A17" },
    .{ .id = 0xc0e, .name = "Cortex-A17" },
    .{ .id = 0xc0f, .name = "Cortex-A15" },
    .{ .id = 0xd01, .name = "Cortex-A32" },
    .{ .id = 0xd02, .name = "Cortex-A34" },
    .{ .id = 0xd03, .name = "Cortex-A53" },
    .{ .id = 0xd04, .name = "Cortex-A35" },
    .{ .id = 0xd05, .name = "Cortex-A55" },
    .{ .id = 0xd06, .name = "Cortex-A65" },
    .{ .id = 0xd07, .name = "Cortex-A57" },
    .{ .id = 0xd08, .name = "Cortex-A72" },
    .{ .id = 0xd09, .name = "Cortex-A73" },
    .{ .id = 0xd0a, .name = "Cortex-A75" },
    .{ .id = 0xd0b, .name = "Cortex-A76" },
    .{ .id = 0xd0c, .name = "Neoverse-N1" },
    .{ .id = 0xd0d, .name = "Cortex-A77" },
    .{ .id = 0xd0e, .name = "Cortex-A76AE" },
    .{ .id = 0xd40, .name = "Neoverse-V1" },
    .{ .id = 0xd41, .name = "Cortex-A78" },
    .{ .id = 0xd42, .name = "Cortex-A78AE" },
    .{ .id = 0xd43, .name = "Cortex-A65AE" },
    .{ .id = 0xd44, .name = "Cortex-X1" },
    .{ .id = 0xd46, .name = "Cortex-A510" },
    .{ .id = 0xd47, .name = "Cortex-A710" },
    .{ .id = 0xd48, .name = "Cortex-X2" },
    .{ .id = 0xd49, .name = "Neoverse-N2" },
    .{ .id = 0xd4a, .name = "Neoverse-E1" },
    .{ .id = 0xd4b, .name = "Cortex-A78C" },
    .{ .id = 0xd4c, .name = "Cortex-X1C" },
    .{ .id = 0xd4d, .name = "Cortex-A715" },
    .{ .id = 0xd4e, .name = "Cortex-X3" },
    .{ .id = 0xd4f, .name = "Neoverse-V2" },
    .{ .id = 0xd80, .name = "Cortex-A520" },
    .{ .id = 0xd81, .name = "Cortex-A720" },
    .{ .id = 0xd82, .name = "Cortex-X4" },
    .{ .id = 0xd83, .name = "Neoverse-V3AE" },
    .{ .id = 0xd84, .name = "Neoverse-V3" },
    .{ .id = 0xd85, .name = "Cortex-X925" },
    .{ .id = 0xd87, .name = "Cortex-A725" },
    .{ .id = 0xd88, .name = "Cortex-A520AE" },
    .{ .id = 0xd89, .name = "Cortex-A720AE" },
    .{ .id = 0xd8a, .name = "C1-Nano" },
    .{ .id = 0xd8b, .name = "C1-Pro" },
    .{ .id = 0xd8c, .name = "C1-Ultra" },
    .{ .id = 0xd8e, .name = "Neoverse-N3" },
    .{ .id = 0xd8f, .name = "Cortex-A320" },
    .{ .id = 0xd90, .name = "C1-Premium" },
};
const arm_implementer: u8 = 0x41;

fn armModelName(midr: u64) ?[]const u8 {
    const implementer: u8 = @truncate(midr >> 24);
    const part: u16 = @truncate((midr >> 4) & 0xfff);
    if (implementer != arm_implementer) return null;
    for (arm_parts) |entry| {
        if (entry.id == part) return entry.name;
    }
    return null;
}

test armModelName {
    // Verified against lscpu on this host: midr 0x410fd841 -> Neoverse-V3.
    try testing.expectEqualStrings("Neoverse-V3", armModelName(0x410fd841).?);
    try testing.expectEqual(@as(?[]const u8, null), armModelName(0x410fffff));
    try testing.expectEqualStrings("Neoverse-N1", armModelName(0x410fd0c0).?);
}

/// The awk field-squash in the script: '{print $1 " " $2 " " $3 " " $4}'
/// — always four slots, so a one-word model gains three trailing spaces
/// ("Neoverse-V3   " in the fixtures; PRINT_DATA pads them invisible).
fn writeSquashedFields(w: *Io.Writer, model: []const u8) !void {
    const fields: Fields = .parse(model);
    for (1..5) |i| {
        if (i > 1) try w.writeAll(" ");
        try w.writeAll(fields.at(@intCast(i)));
    }
}

test writeSquashedFields {
    var buf: [96]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeSquashedFields(&w, "Neoverse-V3");
    try testing.expectEqualStrings("Neoverse-V3   ", w.buffered());
}

fn findCpuinfoLine(comptime key: []const u8, cpuinfo: []const u8, skip_bios: bool) ?[]const u8 {
    var rest = cpuinfo;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        if (!mem.startsWith(u8, line, key)) continue;
        // lscpu also prints "BIOS Model name" on DMI-capable boxes; the
        // script's grep -v BIOS skips it.
        if (skip_bios and mem.find(u8, line, "BIOS") != null) continue;
        const colon = mem.findScalar(u8, line, ':') orelse continue;
        return line[colon + 1 ..];
    }
    return null;
}

/// sysfs and /proc/sys values end with a newline; cut every blank kind
/// or every parse of a number from them fails on the trailing byte.
fn trim(s: []const u8) []const u8 {
    return mem.trim(u8, s, " \t\n\r");
}

test trim {
    try testing.expectEqualStrings("0x410fd841", trim("0x410fd841\n"));
    try testing.expectEqualStrings("0-3", trim("0-3\n"));
    try testing.expectEqualStrings("60", trim("60\n"));
    try testing.expectEqualStrings("", trim(""));
}

fn gatherCpuModel(cpuinfo: []const u8, midr_str: ?[]const u8, out: *Str(96)) void {
    // x86: /proc/cpuinfo "model name". aarch64: cpuinfo has no model name;
    // decode MIDR the way lscpu does.
    const source: []const u8 = blk: {
        if (findCpuinfoLine("model name", cpuinfo, true)) |value| break :blk trim(value);
        if (midr_str) |hex| {
            if (parseHexU64(hex)) |midr| {
                if (armModelName(midr)) |name| break :blk name;
            }
        }
        break :blk null;
    } orelse {
        out.setTrunc("");
        return;
    };
    var buf: [96]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    writeSquashedFields(&w, source) catch |err| keepTruncated(err);
    out.setTrunc(w.buffered());
}

/// "%.2f GHz" for the first clock source that answers, or empty. x86
/// puts the current clock in /proc/cpuinfo; arm64 usually has neither
/// that nor a cpufreq driver, which is why this can come back empty.
fn gatherCpuFreqGh(io: Io, cpuinfo: []const u8, out: *Str(16)) void {
    out.setTrunc("");
    if (findCpuinfoLine("cpu MHz", cpuinfo, false)) |value| {
        if (parseDecimalMilli(trim(value))) |milli| {
            setGhz(out, roundDiv(milli, 10_000));
            return;
        }
    }
    // cpufreq in kHz. Current first: it is the reading lscpu prints.
    const cpufreq_paths = [_][]const u8{
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq",
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
        "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq",
    };
    for (cpufreq_paths) |path| {
        var buf: [sysfs_read_max]u8 = undefined;
        const khz = parseUint(trim(readFileOrEmpty(io, path, &buf))) orelse continue;
        if (khz == 0) continue;
        setGhz(out, roundDiv(khz, 10_000));
        return;
    }
}

fn setGhz(out: *Str(16), hundredths: u64) void {
    out.print("{d}.{d:0>2}", .{ hundredths / 100, hundredths % 100 });
}

test gatherCpuFreqGh {
    const cpuinfo = "processor\t: 0\n" ++
        "vendor_id\t: GenuineIntel\n" ++
        "cpu family\t: 6\n" ++
        "cpu MHz\t\t: 2400.000\n";
    var out: Str(16) = .{};
    gatherCpuFreqGh(testing.io, cpuinfo, &out);
    try testing.expectEqualStrings("2.40", out.view());
}

/// Last-level Unified cache, summed across instances like lscpu's
/// "L3 cache: 48 MiB (1 instance)". The substitute row on hosts that
/// expose no clock: /sys/devices/system/cpu/cpu0/cpufreq is absent and
/// /proc/cpuinfo has no cpu MHz on most arm64 servers.
fn gatherCpuCache(io: Io, out: *Str(24)) void {
    out.setTrunc("");
    var best_level: u64 = 0;
    var best_bytes: u64 = 0;
    for (0..8) |index| {
        var path_buf: [96]u8 = undefined;
        const level_path = mem.print(
            &path_buf,
            "/sys/devices/system/cpu/cpu0/cache/index{d}/level",
            .{index},
        ) catch continue;
        var level_buf: [sysfs_read_max]u8 = undefined;
        const level = parseUint(trim(readFileOrEmpty(io, level_path, &level_buf))) orelse continue;
        const type_path = mem.print(
            &path_buf,
            "/sys/devices/system/cpu/cpu0/cache/index{d}/type",
            .{index},
        ) catch continue;
        var type_buf: [sysfs_read_max]u8 = undefined;
        if (!mem.eql(u8, trim(readFileOrEmpty(io, type_path, &type_buf)), "Unified")) continue;
        const size_path = mem.print(
            &path_buf,
            "/sys/devices/system/cpu/cpu0/cache/index{d}/size",
            .{index},
        ) catch continue;
        var size_buf: [sysfs_read_max]u8 = undefined;
        const size_text = trim(readFileOrEmpty(io, size_path, &size_buf));
        const size = parseCacheSize(size_text) orelse continue;
        if (level > best_level) {
            best_level = level;
            best_bytes = size;
        } else if (level == best_level) {
            best_bytes += size;
        }
    }
    if (best_level == 0 or best_bytes == 0) return;
    if (best_bytes >= 1 << 20) {
        out.print("L{d} {d} MiB", .{ best_level, best_bytes / (1 << 20) });
    } else {
        out.print("L{d} {d} KiB", .{ best_level, best_bytes / 1024 });
    }
}

/// sysfs cache sizes are "32K", "2048K", or occasionally "1M".
fn parseCacheSize(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    const multiplier: u64 = switch (s[s.len - 1]) {
        'K', 'k' => 1024,
        'M', 'm' => 1 << 20,
        else => 1,
    };
    const digits = if (multiplier == 1) s else s[0 .. s.len - 1];
    const value = parseUint(digits) orelse return null;
    return value * multiplier;
}

test parseCacheSize {
    try testing.expectEqual(@as(?u64, 64 * 1024), parseCacheSize("64K"));
    try testing.expectEqual(@as(?u64, 49152 * 1024), parseCacheSize("49152K"));
    try testing.expectEqual(@as(?u64, 2 * 1024 * 1024), parseCacheSize("2M"));
    try testing.expectEqual(@as(?u64, 1024), parseCacheSize("1024"));
    try testing.expectEqual(@as(?u64, null), parseCacheSize(""));
    try testing.expectEqual(@as(?u64, null), parseCacheSize("K"));
}

/// lscpu's Hypervisor vendor names, util-linux 2.42.3 lscpu.c
/// hv_vendors[], driven by /sys/hypervisor/type (Xen) or CPUID leaf
/// 0x40000000 signatures (x86). No flag on the box means "Bare Metal",
/// which is the aarch64 case on the verified host.
fn gatherCpuHypervisor(io: Io, cpuinfo: []const u8, out: *Str(32)) void {
    out.setTrunc("Bare Metal");
    if (!cpuinfoHasHypervisorFlag(cpuinfo)) return;
    var type_buf: [sysfs_read_max]u8 = undefined;
    const sysfs_type = trim(readFileOrEmpty(io, "/sys/hypervisor/type", &type_buf));
    if (sysfs_type.len > 0) {
        if (mem.eql(u8, sysfs_type, "xen") or mem.eql(u8, sysfs_type, "Xen")) {
            out.setTrunc("Xen");
            return;
        }
    }
    if (builtin.cpu.arch == .x86_64) {
        if (cpuidHypervisorVendor()) |name| out.setTrunc(name);
    }
}

fn cpuinfoHasHypervisorFlag(cpuinfo: []const u8) bool {
    const flags = findCpuinfoLine("flags", cpuinfo, false) orelse return false;
    const fields: Fields = .parse(flags);
    var i: u8 = 1;
    while (i <= fields.count) : (i += 1) {
        if (mem.eql(u8, fields.at(i), "hypervisor")) return true;
    }
    return false;
}

/// CPUID leaf 0x40000000 signature -> vendor name. x86_64 only, and
/// untestable on this aarch64 host; signatures per util-linux/QEMU docs.
fn cpuidHypervisorVendor() ?[]const u8 {
    const leaf_1 = cpuid(1);
    if ((leaf_1.ecx & (1 << 31)) == 0) return null;
    const sig = cpuid(0x40000000);
    const bytes = [12]u8{
        sig.ebx & 0xff, (sig.ebx >> 8) & 0xff, (sig.ebx >> 16) & 0xff, (sig.ebx >> 24) & 0xff,
        sig.ecx & 0xff, (sig.ecx >> 8) & 0xff, (sig.ecx >> 16) & 0xff, (sig.ecx >> 24) & 0xff,
        sig.edx & 0xff, (sig.edx >> 8) & 0xff, (sig.edx >> 16) & 0xff, (sig.edx >> 24) & 0xff,
    };
    const signature: []const u8 = &bytes;
    if (mem.eql(u8, signature[0..9], "KVMKVMKVM")) return "KVM";
    if (mem.eql(u8, signature[0..12], "Microsoft Hv")) return "Microsoft";
    if (mem.eql(u8, signature[0..12], "VMwareVMware")) return "VMware";
    if (mem.eql(u8, signature[0..12], "XenVMMXenVMM")) return "Xen";
    if (mem.eql(u8, signature[0..12], "VBoxVBoxVBox")) return "Oracle";
    if (mem.eql(u8, signature[0..11], "prl hyperv")) return "Parallels";
    return null;
}

fn cpuid(leaf: u32) struct { eax: u32, ebx: u32, ecx: u32, edx: u32 } {
    if (builtin.cpu.arch != .x86_64) return .{ .eax = 0, .ebx = 0, .ecx = 0, .edx = 0 };
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile (
        \\cpuid
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [sub] "{ecx}" (@as(u32, 0)),
        : "cc");
    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}

/// Parse "0-3" / "0-3,8" cpu lists; every cpu delivered exactly once.
fn walkPresentCpus(
    present: []const u8,
    ctx: anytype,
    onCpu: fn (ctx: @TypeOf(ctx), cpu: u32) void,
) void {
    var rest = trim(present);
    var seen: usize = 0;
    while (rest.len > 0 and seen < max_present_cpus) {
        const comma = mem.findScalar(u8, rest, ',') orelse rest.len;
        const token = rest[0..comma];
        rest = if (comma < rest.len) rest[comma + 1 ..] else rest[comma..];
        if (mem.findScalar(u8, token, '-')) |dash| {
            const lo = parseUint(trim(token[0..dash])) orelse continue;
            const hi = @min(parseUint(trim(token[dash + 1 ..])) orelse lo, max_present_cpus);
            var cpu: u64 = lo;
            while (cpu <= hi and seen < max_present_cpus) : ({
                cpu += 1;
                seen += 1;
            }) {
                onCpu(ctx, @intCast(cpu));
            }
        } else {
            const cpu = parseUint(trim(token)) orelse continue;
            if (cpu <= max_present_cpus) {
                seen += 1;
                onCpu(ctx, @intCast(cpu));
            }
        }
    }
}

test walkPresentCpus {
    const Collector = struct {
        const Self = @This();

        count: u32 = 0,
        max: u32 = 0,
        fn on(self: *Self, cpu: u32) void {
            self.count += 1;
            self.max = @max(self.max, cpu);
        }
    };
    var collector: Collector = .{};
    walkPresentCpus("0-3", &collector, Collector.on);
    try testing.expectEqual(@as(u32, 4), collector.count);
    try testing.expectEqual(@as(u32, 3), collector.max);

    collector = .{};
    walkPresentCpus("0-1,4", &collector, Collector.on);
    try testing.expectEqual(@as(u32, 3), collector.count);
    try testing.expectEqual(@as(u32, 4), collector.max);
}

/// Core(s) per socket and Socket(s) from sysfs topology, like lscpu:
/// distinct physical_package_id values are sockets; distinct core_id
/// values within a package are that socket's cores.
const TopologyCounts = struct {
    cores_per_socket: u32 = 0,
    sockets: u32 = 0,
};

fn gatherTopology(io: Io, present: []const u8) TopologyCounts {
    const Ctx = struct {
        const Self = @This();

        io: Io,
        sockets: [256]u32 = @splat(0), // distinct package ids; 0 = empty slot
        socket_count: u32 = 0,
        core_seen: [256][128]u8 = @splat(@splat(0)), // per-socket 1024-bit core map
        cores_per_socket: [256]u32 = @splat(0),

        fn rememberSocket(self: *Self, package: u32) usize {
            for (self.sockets, 0..) |slot, i| {
                if (slot == package) return i;
                if (slot == 0 and self.socket_count == i) {
                    self.sockets[i] = package;
                    self.socket_count += 1;
                    return i;
                }
            }
            return 0;
        }

        fn on(self: *Self, cpu: u32) void {
            // Values copy out of the read before the next one reuses the
            // buffers; a returned slice would dangle in read()'s frame.
            var path_buf: [96]u8 = undefined;
            var package_value: Str(16) = .{};
            var core_value: Str(16) = .{};
            readTopologyInto("physical_package_id", self.io, &package_value, &path_buf, cpu);
            readTopologyInto("core_id", self.io, &core_value, &path_buf, cpu);
            const package = parseUint(package_value.view()) orelse return;
            const core = parseUint(core_value.view()) orelse return;
            if (package > std.math.maxInt(u32)) return;
            const socket_index = self.rememberSocket(@intCast(package));
            if (core >= 1024) return;
            if ((self.core_seen[socket_index][core / 8] >> @intCast(core % 8)) & 1 == 0) {
                self.core_seen[socket_index][core / 8] |= @as(u8, 1) << @intCast(core % 8);
                self.cores_per_socket[socket_index] += 1;
            }
        }
    };
    var ctx: Ctx = .{ .io = io };
    walkPresentCpus(present, &ctx, Ctx.on);
    var out: TopologyCounts = .{ .sockets = ctx.socket_count };
    for (ctx.cores_per_socket[0..ctx.socket_count]) |n| {
        out.cores_per_socket = @max(out.cores_per_socket, n);
    }
    return out;
}

fn readTopologyInto(
    comptime kind: []const u8,
    io: Io,
    out: *Str(16),
    path_buf: *[96]u8,
    cpu: u32,
) void {
    const path = mem.print(
        path_buf,
        "/sys/devices/system/cpu/cpu{d}/topology/" ++ kind,
        .{cpu},
    ) catch {
        out.setTrunc("");
        return;
    };
    var file_buf: [sysfs_read_max]u8 = undefined;
    out.setTrunc(trim(readFileOrEmpty(io, path, &file_buf)));
}

fn countPresentCpus(present: []const u8) u32 {
    const Counter = struct {
        const Self = @This();

        count: u32 = 0,
        fn on(self: *Self, _: u32) void {
            self.count += 1;
        }
    };
    var counter: Counter = .{};
    walkPresentCpus(present, &counter, Counter.on);
    return counter.count;
}

fn gatherMeminfo(io: Io) struct { total_kib: u64, available_kib: u64 } {
    var meminfo_buf: [read_max]u8 = undefined;
    const meminfo = readFileOrEmpty(io, "/proc/meminfo", &meminfo_buf);
    var total: u64 = 0;
    var available: u64 = 0;
    var rest = meminfo;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        const fields: Fields = .parse(line);
        const value = parseUint(fields.at(2)) orelse continue;
        if (mem.eql(u8, fields.at(1), "MemTotal:")) total = value;
        if (mem.eql(u8, fields.at(1), "MemAvailable:")) available = value;
    }
    return .{ .total_kib = total, .available_kib = available };
}

test "gatherMeminfo core" {
    const meminfo = "MemTotal:       16000836 kB\n" ++
        "MemFree:         2382084 kB\n" ++
        "MemAvailable:    5495980 kB\n";
    var total: u64 = 0;
    var available: u64 = 0;
    var rest: []const u8 = meminfo;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        const fields: Fields = .parse(line);
        const value = parseUint(fields.at(2)) orelse continue;
        if (mem.eql(u8, fields.at(1), "MemTotal:")) total = value;
        if (mem.eql(u8, fields.at(1), "MemAvailable:")) available = value;
    }
    try testing.expectEqual(@as(u64, 16000836), total);
    try testing.expectEqual(@as(u64, 5495980), available);
}

// ------------------------------------------------------------------- disk

/// One row set per filesystem, not per mount. A btrfs filesystem with
/// several subvolumes (plus the ro bind mount NixOS adds under /nix/store)
/// shows the same block counts on every mount; folding by device keeps one
/// row and lists the mountpoints it backs.
const max_volumes = 8;
const max_fs_mounts = 4;

const Volume = struct {
    device: Str(80) = .{},
    mounts: [max_fs_mounts]Str(48) = @splat(.{}),
    mount_count: u8 = 0,
    used_mib: u64 = 0,
    total_mib: u64 = 0,
    zfs: bool = false,

    /// Nested mounts of the same filesystem (/nix then /nix/store) name
    /// one directory twice; keep the parent.
    fn addMount(self: *Volume, mount: []const u8) void {
        var i: u8 = 0;
        while (i < self.mount_count) : (i += 1) {
            const existing = self.mounts[i].view();
            if (sameOrUnder(existing, mount)) return;
            if (sameOrUnder(mount, existing)) {
                self.mounts[i].setTrunc(mount);
                return;
            }
        }
        if (self.mount_count < max_fs_mounts) {
            self.mounts[self.mount_count].setTrunc(mount);
            self.mount_count += 1;
        }
    }

    /// Mountpoints in display order: shortest first, so the label of a
    /// filesystem with several subvolumes names the mounts a reader
    /// recognizes before the long home path. Ties alphabetical.
    fn label(self: *const Volume, out: *Str(64)) void {
        var order: [max_fs_mounts]u8 = undefined;
        for (0..self.mount_count) |i| order[i] = @intCast(i);
        for (1..self.mount_count) |i| {
            const key = order[i];
            var j = i;
            while (j > 0) : (j -= 1) {
                const previous = self.mounts[order[j - 1]].view();
                if (mountLess(previous, self.mounts[key].view())) break;
                order[j] = order[j - 1];
            }
            order[j] = key;
        }
        out.setTrunc("");
        for (0..self.mount_count) |i| {
            if (i > 0) out.print(",", .{});
            out.print("{s}", .{self.mounts[order[i]].view()});
        }
    }
};

fn mountLess(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return a.len < b.len;
    return mem.order(u8, a, b) == .lt;
}

test mountLess {
    try testing.expect(mountLess("/", "/boot"));
    try testing.expect(mountLess("/nix", "/Users/matt"));
    try testing.expect(mountLess("/nix", "/tmp"));
    try testing.expect(!mountLess("/tmp", "/nix"));
}

/// a == b, or b sits under a (path-component boundary, not a string
/// prefix: /home does not contain /homework).
fn sameOrUnder(a: []const u8, b: []const u8) bool {
    if (!mem.startsWith(u8, b, a)) return false;
    return b.len == a.len or a.len == 1 or b[a.len] == '/';
}

test sameOrUnder {
    try testing.expect(sameOrUnder("/", "/nix"));
    try testing.expect(sameOrUnder("/nix", "/nix/store"));
    try testing.expect(sameOrUnder("/nix", "/nix"));
    try testing.expect(!sameOrUnder("/nix", "/nixos"));
    try testing.expect(!sameOrUnder("/home", "/homework"));
    try testing.expect(!sameOrUnder("/nix", "/tmp"));
}

const Volumes = struct {
    items: [max_volumes]Volume = @splat(.{}),
    count: u8 = 0,

    fn find(self: *Volumes, device: []const u8) ?*Volume {
        for (self.items[0..self.count]) |*volume| {
            if (mem.eql(u8, volume.device.view(), device)) return volume;
        }
        return null;
    }

    fn anyZfs(self: *const Volumes) bool {
        for (self.items[0..self.count]) |volume| {
            if (volume.zfs) return true;
        }
        return false;
    }
};

/// Kernel and synthetic filesystems that carry no capacity worth a row.
/// overlay and squashfs stay: they are a container's and an installer's
/// real root.
const pseudo_fstypes = [_][]const u8{
    "proc",       "sysfs",   "devtmpfs",  "devpts",      "tmpfs",
    "ramfs",      "cgroup",  "cgroup2",   "securityfs",  "pstore",
    "efivarfs",   "bpf",     "debugfs",   "mqueue",      "configfs",
    "hugetlbfs",  "tracefs", "fusectl",   "binfmt_misc", "autofs",
    "rpc_pipefs", "nsfs",    "selinuxfs",
};

fn isPseudoFs(fstype: []const u8) bool {
    for (pseudo_fstypes) |pseudo| {
        if (mem.eql(u8, fstype, pseudo)) return true;
    }
    return false;
}

/// /proc/mounts escapes space, tab, newline and backslash as octal.
fn unescapeMount(s: []const u8, out: []u8) ?[]const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (n == out.len) return null;
        if (s[i] != '\\' or i + 3 >= s.len) {
            out[n] = s[i];
            n += 1;
            i += 1;
            continue;
        }
        const code = parseOctal(s[i + 1 .. i + 4]) orelse {
            out[n] = s[i];
            n += 1;
            i += 1;
            continue;
        };
        out[n] = code;
        n += 1;
        i += 4;
    }
    return out[0..n];
}

fn parseOctal(s: []const u8) ?u8 {
    var v: u16 = 0;
    for (s) |c| {
        if (c < '0' or c > '7') return null;
        v = v * 8 + (c - '0');
    }
    return @intCast(v);
}

test unescapeMount {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("/", unescapeMount("/", &buf).?);
    try testing.expectEqualStrings("/mnt/my disk", unescapeMount("/mnt/my\\040disk", &buf).?);
    try testing.expectEqualStrings("/a\\b", unescapeMount("/a\\134b", &buf).?);
}

fn statfsPath(path: []const u8, st: *StatFs) bool {
    var buf: [4096]u8 = undefined;
    if (path.len >= buf.len) return false;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    const rc = linux.syscall2(.statfs, @intFromPtr(&buf), @intFromPtr(st));
    return linux.errno(rc) == .SUCCESS;
}

fn gatherVolumes(io: Io) Volumes {
    var mounts_buf: [mounts_read_max]u8 = undefined;
    const mounts = readFileOrEmpty(io, "/proc/mounts", &mounts_buf);
    var out: Volumes = .{};
    var rest = mounts;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        const fields: Fields = .parse(line);
        // device mountpoint fstype options dump pass
        const device = fields.at(1);
        const fstype = fields.at(3);
        if (device.len == 0 or isPseudoFs(fstype)) continue;
        var path_buf: [4096]u8 = undefined;
        const mount = unescapeMount(fields.at(2), &path_buf) orelse continue;
        var st: StatFs = undefined;
        if (!statfsPath(mount, &st)) continue;
        const frsize: u64 = if (st.f_frsize > 0) @intCast(st.f_frsize) else @intCast(st.f_bsize);
        if (frsize == 0 or st.f_blocks == 0) continue;
        const total_mib = divCeilProduct(st.f_blocks, frsize, 1 << 20);
        if (total_mib == 0) continue;
        if (out.find(device)) |volume| {
            volume.addMount(mount);
            continue;
        }
        if (out.count == max_volumes) continue;
        const volume = &out.items[out.count];
        volume.* = .{
            .used_mib = divCeilProduct(st.f_blocks -| st.f_bfree, frsize, 1 << 20),
            .total_mib = total_mib,
            .zfs = mem.eql(u8, fstype, "zfs"),
        };
        volume.device.setTrunc(device);
        volume.addMount(mount);
        out.count += 1;
    }
    sortVolumes(&out);
    return out;
}

/// Root first, then by label: mount order is boot order, which moves
/// when a unit reorders its mounts.
fn sortVolumes(volumes: *Volumes) void {
    var labels: [max_volumes]Str(64) = @splat(.{});
    for (0..volumes.count) |i| volumes.items[i].label(&labels[i]);
    for (1..volumes.count) |i| {
        const key = volumes.items[i];
        const key_label = labels[i];
        var j = i;
        while (j > 0 and mem.order(u8, labels[j - 1].view(), key_label.view()) == .gt) : (j -= 1) {
            volumes.items[j] = volumes.items[j - 1];
            labels[j] = labels[j - 1];
        }
        volumes.items[j] = key;
        labels[j] = key_label;
    }
}

test "Volume addMount folds nested mounts" {
    var volume: Volume = .{};
    volume.addMount("/nix");
    volume.addMount("/nix/store");
    volume.addMount("/tmp");
    volume.addMount("/nix");
    try testing.expectEqual(@as(u8, 2), volume.mount_count);
    var label: Str(64) = .{};
    volume.label(&label);
    try testing.expectEqualStrings("/nix,/tmp", label.view());
}

// -------------------------------------------------------------- last login

const LastLogin = struct {
    time_str: Str(64) = .{},
    ip: Str(64) = .{},
    ip_present: bool = false,
};

fn gatherLastLogin(io: Io, tz: *const Tz, uid_for_record: u32) LastLogin {
    var record_buf: [@sizeOf(LastlogRecord)]u8 = undefined;
    const offset: u64 = @as(u64, uid_for_record) * @sizeOf(LastlogRecord);
    const raw = readRecordOrEmpty(io, "/var/log/lastlog", &record_buf, offset);

    var out: LastLogin = .{};
    if (raw.len != @sizeOf(LastlogRecord)) {
        out.time_str.setTrunc("Never logged in");
        return out;
    }
    // logwtmp(3) fixed this layout, so the pointer cast is the kernel
    // ABI, not a guess.
    const record: *const LastlogRecord = @ptrCast(@alignCast(raw.ptr));
    if (record.ll_time == 0) {
        out.time_str.setTrunc("Never logged in");
        return out;
    }
    formatLastLoginTime(&out.time_str, record.ll_time, tz.offsetAt(record.ll_time));

    const host = mem.sliceTo(&record.ll_host, 0);
    if (isDottedQuad(host)) {
        out.ip_present = true;
        out.ip.setTrunc(host);
    }
    return out;
}

/// "Sat Sep 26 12:06:18 -0700". The script picked its awk fields as
/// $6, $7, $10, $8: day, time, a field that does not exist, offset. That
/// dropped the month and year and kept the empty field's separator.
fn formatLastLoginTime(out: *Str(64), epoch: i64, offset_seconds: i32) void {
    const local: i64 = epoch + offset_seconds;
    const days = @divFloor(local, 86400);
    const secs_of_day: u64 = @intCast(@mod(local, 86400));
    const date = civilFromDays(days);
    var offset_str: Str(8) = .{};
    {
        var ow: Io.Writer = .fixed(offset_str.bytes[0..]);
        writeTzOffset(&ow, offset_seconds) catch |err| keepTruncated(err);
        offset_str.len = @intCast(ow.buffered().len);
    }
    out.print("{s} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} {s}", .{
        weekday_names[weekdayFromDays(days)],
        month_names[date.month - 1],
        date.day,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
        offset_str.view(),
    });
}

test formatLastLoginTime {
    // 1790449578 is the fixture record: 2026-09-26 12:06:18 -0700.
    var out: Str(64) = .{};
    formatLastLoginTime(&out, 1790449578, -7 * 3600);
    try testing.expectEqualStrings("Sat Sep 26 12:06:18 -0700", out.view());
}

test "LastLogin record shape" {
    var record: LastlogRecord = undefined;
    @memset(mem.asBytes(&record), 0);
    record.ll_time = 1790449578; // the fixture: 2026-09-26 12:06:18 -0700
    @memcpy(record.ll_line[0.."pts/1".len], "pts/1");
    @memcpy(record.ll_host[0.."45.26.44.184".len], "45.26.44.184");
    try testing.expectEqualStrings("pts/1", mem.sliceTo(&record.ll_line, 0));
    try testing.expectEqualStrings("45.26.44.184", mem.sliceTo(&record.ll_host, 0));
}

// ------------------------------------------------------------------ uptime

fn gatherUptimeSeconds(io: Io) u64 {
    var uptime_buf: [sysfs_read_max]u8 = undefined;
    const uptime = readFileOrEmpty(io, "/proc/uptime", &uptime_buf);
    // "431344.46 1031310.91": procps floors to whole seconds.
    const milli = parseDecimalMilli(Fields.parse(uptime).at(1)) orelse return 0;
    return milli / 1000;
}

test "gatherUptimeSeconds core" {
    const milli = parseDecimalMilli("431344.46").?;
    try testing.expectEqual(@as(u64, 431344), milli / 1000);
}

/// procps uptime -p wording with the script's sed applied (words become
/// letters, commas stay): "4d, 23h, 50m". Zero units drop, minutes last.
fn writeUptime(w: *Io.Writer, seconds: u64) !void {
    const days = seconds / 86400;
    const rem = seconds % 86400;
    const hours = rem / 3600;
    const minutes = (rem % 3600) / 60;
    var parts_written: usize = 0;
    if (days > 0) {
        try w.print("{s}{d}d", .{ if (parts_written > 0) ", " else "", days });
        parts_written += 1;
    }
    if (hours > 0) {
        try w.print("{s}{d}h", .{ if (parts_written > 0) ", " else "", hours });
        parts_written += 1;
    }
    if (minutes > 0 or parts_written == 0) {
        try w.print("{s}{d}m", .{ if (parts_written > 0) ", " else "", minutes });
    }
}

test writeUptime {
    var buf: [32]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeUptime(&w, 4 * 86400 + 23 * 3600 + 50 * 60);
    try testing.expectEqualStrings("4d, 23h, 50m", w.buffered());
}

// --------------------------------------------------------------- rendering

const bar_full: []const u8 = "█";
const bar_empty: []const u8 = "░";

/// The script's bar_graph, over-100% quirk intact: num_blocks is not
/// clamped to width, so a loaded box draws a bar longer than the column
/// and PRINT_DATA truncates it into "███…".
fn writeBar(w: *Io.Writer, used: u64, total: u64, width: usize) !void {
    const hundredths = percentHundredths(used, total);
    const blocks = hundredths * width / 10000;
    for (0..@as(usize, @intCast(blocks))) |_| try w.writeAll(bar_full);
    if (blocks < width) {
        for (@as(usize, @intCast(blocks))..width) |_| try w.writeAll(bar_empty);
    }
}

test "writeBar quirk: over 100% is not clamped" {
    var buf: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    // Load 14.95 on 4 cores = 373.75% -> 112 blocks at width 30.
    try writeBar(&w, 1495, 400, 30);
    try testing.expectEqual(@as(usize, 112), codepointCount(w.buffered()));
}

test "writeBar zero total and partial fill" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeBar(&w, 81, 100, 30);
    try testing.expectEqual(@as(usize, 30), codepointCount(w.buffered()));
    var w2: Io.Writer = .fixed(&buf);
    try writeBar(&w2, 0, 0, 30);
    // All empties, 30 of them — checked structurally, not by eyeballing
    // 30 repeated glyphs (the lesson of this whole port).
    const empty_bar = w2.buffered();
    try testing.expectEqual(@as(usize, 30), codepointCount(empty_bar));
    try testing.expectEqual(@as(usize, 30 * bar_empty.len), empty_bar.len);
    try testing.expect(mem.startsWith(u8, empty_bar, bar_empty));
    try testing.expect(mem.endsWith(u8, empty_bar, bar_empty));
}

/// max_length over the script's data-string list, min'd with 32.
fn currentDataLen(candidates: []const []const u8) usize {
    var longest: usize = 0;
    for (candidates) |s| {
        longest = @max(longest, codepointCount(s));
    }
    return @min(longest, max_data_len);
}

test currentDataLen {
    // The fixtures on the verified host: the title's 30 codepoints set
    // the column width; a host of monsters clamps at 32.
    try testing.expectEqual(@as(usize, 30), currentDataLen(&.{
        "UNITED STATES GRAPHICS COMPANY", "Nixos 26.11 (Zokor) Zokor", "Linux 7.2.6 ",
    }));
    try testing.expectEqual(@as(usize, 32), currentDataLen(&.{
        "0123456789012345678901234567890123456789",
    }));
}

fn boxWidth(data_len: usize) usize {
    return data_len + max_name_len + borders_and_padding;
}

fn writeHeader(w: *Io.Writer, data_len: usize) !void {
    const length = boxWidth(data_len);
    try w.writeAll("┌");
    for (0..length - 2) |_| try w.writeAll("┬");
    try w.writeAll("┐\n");
    try w.writeAll("├");
    for (0..length - 2) |_| try w.writeAll("┴");
    try w.writeAll("┤\n");
}

const DividerKind = enum { top, middle, bottom };

fn writeDivider(w: *Io.Writer, kind: DividerKind, data_len: usize) !void {
    const length = boxWidth(data_len);
    const left: []const u8 = if (kind == .bottom) "└" else "├";
    const middle: []const u8 = switch (kind) {
        .top => "┬",
        .middle => "┼",
        .bottom => "┴",
    };
    const right: []const u8 = if (kind == .bottom) "┘" else "┤";
    try w.writeAll(left);
    // i == 14 is where the name column ends: 15 cells past the corner.
    for (0..length - 3) |i| {
        try w.writeAll("─");
        if (i == 14) try w.writeAll(middle);
    }
    try w.writeAll(right);
    try w.writeAll("\n");
}

fn writeCentered(w: *Io.Writer, text: []const u8, data_len: usize) !void {
    const total_width = data_len + max_name_len - borders_and_padding + 12;
    const text_len = codepointCount(text);
    const padding_left = (total_width -| text_len) / 2;
    const padding_right = total_width -| text_len - padding_left;
    try w.writeAll("│");
    for (0..padding_left) |_| try w.writeAll(" ");
    try w.writeAll(text);
    for (0..padding_right) |_| try w.writeAll(" ");
    try w.writeAll("│\n");
}

/// PRINT_DATA: name to 13 cells (over-long names cut to 10 plus "..."),
/// data to the column width (31+ codepoints cut to 27 plus "...").
fn writeDataRow(w: *Io.Writer, name: []const u8, data: []const u8, data_len: usize) !void {
    const data_codepoints = codepointCount(data);
    try w.writeAll("│ ");
    if (codepointCount(name) > max_name_len) {
        // cut(1) -c 10 then "...": exactly the 13-cell name column.
        try w.writeAll(cutCodepoints(name, max_name_len - 3));
        try w.writeAll("... │ ");
    } else {
        try padRight(w, name, max_name_len);
        try w.writeAll(" │ ");
    }
    // Upstream's odd test: >= 32 or == 31, both sides land here.
    if (data_codepoints >= max_data_len or data_codepoints == max_data_len - 1) {
        try w.writeAll(cutCodepoints(data, max_data_len - 5));
        try w.writeAll("... │\n");
    } else {
        try padRight(w, data, data_len);
        try w.writeAll(" │\n");
    }
}

// ------------------------------------------------------------------- report

const Report = struct {
    // Display strings; names carry over from the bash variables.
    os_name: Str(64) = .{},
    os_kernel: Str(64) = .{},
    net_hostname: Str(128) = .{},
    net_machine_ip: Str(64) = .{},
    net_machine_extra: [max_machine_addrs]Str(64) = @splat(.{}),
    net_machine_extra_count: u8 = 0,
    net_client_ip: Str(256) = .{},
    net_dns_ip: [max_dns_entries]Str(64) = @splat(.{}),
    net_dns_count: u8 = 0,
    net_current_user: Str(64) = .{},
    cpu_model: Str(96) = .{},
    cpu_cores_per_socket: u32 = 0,
    cpu_sockets: u32 = 0,
    cpu_hypervisor: Str(32) = .{},
    cpu_freq_gh: Str(16) = .{},
    cpu_cache: Str(24) = .{},
    load_1min_hd: u32 = 0,
    load_5min_hd: u32 = 0,
    load_15min_hd: u32 = 0,
    cpu_cores: u32 = 0,
    mem_total_kib: u64 = 0,
    mem_used_kib: i64 = 0,
    mem_percent_hd: u64 = 0,
    mem_used_gb_hd: u64 = 0,
    mem_total_gb_hd: u64 = 0,
    volumes: Volumes = .{},
    last_login: LastLogin = .{},
    uptime_seconds: u64 = 0,

    fn read(io: Io, environ: process.Environ) Report {
        var self: Report = .{};
        const uid = linux.getuid();

        // ---- Operating System Information
        const uts = posix.uname();
        gatherOsName(io, &self.os_name);
        gatherKernel(&uts, &self.os_kernel);

        // ---- Network Information
        var hosts_buf: [etc_read_max]u8 = undefined;
        const hosts = readFileOrEmpty(io, "/etc/hosts", &hosts_buf);
        resolveHostname(&uts, hosts, &self.net_hostname);
        gatherMachineIps(
            io,
            &self.net_machine_ip,
            &self.net_machine_extra,
            &self.net_machine_extra_count,
        );
        gatherClientIp(io, environ, &self.net_client_ip);
        gatherDnsServers(io, &self.net_dns_ip, &self.net_dns_count);
        var passwd_buf: [etc_read_max]u8 = undefined;
        const passwd = readFileOrEmpty(io, "/etc/passwd", &passwd_buf);
        const user_name = passwdUserName(passwd, uid) orelse "";
        self.net_current_user.setTrunc(user_name);

        // ---- CPU Information
        var cpuinfo_buf: [cpuinfo_read_max]u8 = undefined;
        const cpuinfo = readFileOrEmpty(io, "/proc/cpuinfo", &cpuinfo_buf);
        var midr_buf: [sysfs_read_max]u8 = undefined;
        const midr_str: ?[]const u8 = if (builtin.cpu.arch == .aarch64) blk: {
            const raw = readFileOrEmpty(
                io,
                "/sys/devices/system/cpu/cpu0/regs/identification/midr_el1",
                &midr_buf,
            );
            break :blk if (raw.len > 0) trim(raw) else null;
        } else null;
        gatherCpuModel(cpuinfo, midr_str, &self.cpu_model);
        gatherCpuFreqGh(io, cpuinfo, &self.cpu_freq_gh);
        // Only worth the sysfs walk when the clock row would be empty.
        if (self.cpu_freq_gh.view().len == 0) gatherCpuCache(io, &self.cpu_cache);
        gatherCpuHypervisor(io, cpuinfo, &self.cpu_hypervisor);
        var present_buf: [sysfs_read_max]u8 = undefined;
        const present = readFileOrEmpty(io, "/sys/devices/system/cpu/present", &present_buf);
        const topology = gatherTopology(io, present);
        self.cpu_cores_per_socket = topology.cores_per_socket;
        self.cpu_sockets = topology.sockets;
        self.cpu_cores = countPresentCpus(present);
        parseLoadAverages(io, &self);

        // ---- Memory Information
        const memory = gatherMeminfo(io);
        self.mem_total_kib = memory.total_kib;
        // The script subtracts first and lets awk print a negative if
        // the kernel ever reports available > total; i64 keeps that shape.
        self.mem_used_kib = @as(i64, @intCast(memory.total_kib)) -
            @as(i64, @intCast(memory.available_kib));
        const used_abs: u64 = @abs(self.mem_used_kib);
        self.mem_percent_hd = percentHundredths(used_abs, memory.total_kib);
        self.mem_used_gb_hd = roundDiv(used_abs * 100, 1024 * 1024);
        self.mem_total_gb_hd = roundDiv(memory.total_kib * 100, 1024 * 1024);

        // ---- Disk Information
        self.volumes = gatherVolumes(io);

        // ---- Last login (reads $USER's record, like lastlog -u "$USER")
        const tz = readTz(io, environ);
        const uid_for_record = uidFromUserEnv(environ, passwd, uid);
        self.last_login = gatherLastLogin(io, &tz, uid_for_record);

        // ---- Uptime
        self.uptime_seconds = gatherUptimeSeconds(io);
        return self;
    }
};

/// "18.37" -> 1837, the two decimals /proc/loadavg always prints.
fn parseHundredths(s: []const u8) u32 {
    const milli = parseDecimalMilli(s) orelse return 0;
    return @intCast(milli / 10);
}

test parseHundredths {
    try testing.expectEqual(@as(u32, 1837), parseHundredths("18.37"));
    try testing.expectEqual(@as(u32, 0), parseHundredths(""));
}

fn parseLoadAverages(io: Io, report: *Report) void {
    var loadavg_buf: [sysfs_read_max]u8 = undefined;
    const loadavg = readFileOrEmpty(io, "/proc/loadavg", &loadavg_buf);
    const fields: Fields = .parse(loadavg);
    report.load_1min_hd = parseHundredths(fields.at(1));
    report.load_5min_hd = parseHundredths(fields.at(2));
    report.load_15min_hd = parseHundredths(fields.at(3));
}

/// date(1) honors $TZ. Named zones resolve through the usual zoneinfo
/// dirs; anything unusable falls back to /etc/localtime (the TZ-unset
/// case, which is what the verified host runs with).
fn readTz(io: Io, environ: process.Environ) Tz {
    // date(1) honors $TZ; only its absolute-path form is supported
    // (named zones would need a zoneinfo-dir search for a case the
    // verified host never exercises). Anything else: /etc/localtime,
    // which is the TZ-unset behavior.
    const zone = environ.getPosix("TZ") orelse "";
    if (zone.len > 1 and zone[0] == ':' and zone[1] == '/') {
        var tz_buf: [tz_read_max]u8 = undefined;
        if (Tz.parse(readFileOrEmpty(io, zone[1..], &tz_buf))) |tz| return tz;
    }
    if (zone.len > 0 and zone[0] == '/') {
        var tz_buf: [tz_read_max]u8 = undefined;
        if (Tz.parse(readFileOrEmpty(io, zone, &tz_buf))) |tz| return tz;
    }
    var tz_buf: [tz_read_max]u8 = undefined;
    return Tz.parse(readFileOrEmpty(io, "/etc/localtime", &tz_buf)) orelse Tz{};
}

/// lastlog -u "$USER": the record of the user $USER names, which is not
/// necessarily the uid we run as. $USER unset or unresolvable -> ours.
fn uidFromUserEnv(environ: process.Environ, passwd: []const u8, fallback: u32) u32 {
    const user = environ.getPosix("USER") orelse return fallback;
    var rest = passwd;
    while (rest.len > 0) {
        const nl = mem.findScalar(u8, rest, '\n') orelse rest.len;
        const line = rest[0..nl];
        rest = if (nl < rest.len) rest[nl + 1 ..] else rest[nl..];
        const first = mem.findScalar(u8, line, ':') orelse continue;
        if (!mem.eql(u8, line[0..first], user)) continue;
        const second = mem.findScalar(u8, line[first + 1 ..], ':') orelse continue;
        const uid_start = first + 1 + second + 1;
        const third = mem.findScalar(u8, line[uid_start..], ':') orelse continue;
        if (parseUint(line[uid_start .. uid_start + third])) |u| {
            if (u <= std.math.maxInt(u32)) return @intCast(u);
        }
        break;
    }
    return fallback;
}

fn writeVolumeData(w: *Io.Writer, volume: *const Volume) !void {
    const percent_hd = percentHundredths(volume.used_mib, volume.total_mib);
    try writeHundredths(w, roundDiv(volume.used_mib * 100, 1024));
    try w.writeAll("/");
    try writeHundredths(w, roundDiv(volume.total_mib * 100, 1024));
    try w.print(" GB [{d}.{d:0>2}%]", .{ percent_hd / 100, percent_hd % 100 });
}

fn writeReport(w: *Io.Writer, report: *Report) !void {
    const r = report;

    // The pre-graph strings that feed set_current_len, empties included:
    // bar graphs are calculated after this point upstream, so they
    // contribute zero.
    var volume_rows: [max_volumes]Str(64) = @splat(.{});
    var volume_labels: [max_volumes]Str(64) = @splat(.{});
    for (0..r.volumes.count) |i| {
        const volume = &r.volumes.items[i];
        volume.label(&volume_labels[i]);
        var vw: Io.Writer = .fixed(volume_rows[i].bytes[0..]);
        try writeVolumeData(&vw, volume);
        volume_rows[i].len = @intCast(vw.buffered().len);
    }

    var mem_row: Str(64) = .{};
    {
        var mw: Io.Writer = .fixed(mem_row.bytes[0..]);
        try writeHundredths(&mw, r.mem_used_gb_hd);
        try mw.writeAll("/");
        try writeHundredths(&mw, r.mem_total_gb_hd);
        try mw.print(" GiB [{d}.{d:0>2}%]", .{ r.mem_percent_hd / 100, r.mem_percent_hd % 100 });
        mem_row.len = @intCast(mw.buffered().len);
    }
    var cores_row: Str(64) = .{};
    cores_row.print("{d} vCPU(s) / {d} Socket(s)", .{ r.cpu_cores_per_socket, r.cpu_sockets });
    var freq_row: Str(24) = .{};
    if (r.cpu_freq_gh.view().len > 0) freq_row.print("{s} GHz", .{r.cpu_freq_gh.view()});
    var uptime_row: Str(32) = .{};
    {
        var uw: Io.Writer = .fixed(uptime_row.bytes[0..]);
        try writeUptime(&uw, r.uptime_seconds);
        uptime_row.len = @intCast(uw.buffered().len);
    }

    const candidates = [_][]const u8{
        report_title,
        r.os_name.view(),
        r.os_kernel.view(),
        r.net_hostname.view(),
        r.net_machine_ip.view(),
        r.net_client_ip.view(),
        r.net_current_user.view(),
        r.cpu_model.view(),
        cores_row.view(),
        r.cpu_hypervisor.view(),
        freq_row.view(),
        r.cpu_cache.view(),
        "", // cpu_1min_bar_graph: unset at set_current_len time upstream
        "", // cpu_5min_bar_graph
        "", // cpu_15min_bar_graph
        "", // disk_bar_graph
        if (r.volumes.anyZfs()) "HEALTH O.K." else "", // zfs_health
        mem_row.view(),
        "", // mem_bar_graph
        r.last_login.time_str.view(),
        r.last_login.ip.view(),
        r.last_login.ip.view(), // upstream lists it twice; harmless
        uptime_row.view(),
    };
    var data_len = currentDataLen(&candidates);
    for (volume_rows[0..r.volumes.count]) |row| {
        data_len = @min(@max(data_len, codepointCount(row.view())), max_data_len);
    }
    for (r.net_machine_extra[0..r.net_machine_extra_count]) |extra| {
        data_len = @min(@max(data_len, codepointCount(extra.view())), max_data_len);
    }

    // ---- Machine Report (row order mirrors the script 1:1)
    try writeHeader(w, data_len);
    try writeCentered(w, report_title, data_len);
    try writeCentered(w, "TR-100 MACHINE REPORT", data_len);
    try writeDivider(w, .top, data_len);
    try writeDataRow(w, "OS", r.os_name.view(), data_len);
    try writeDataRow(w, "KERNEL", r.os_kernel.view(), data_len);
    try writeDivider(w, .middle, data_len);
    try writeDataRow(w, "HOSTNAME", r.net_hostname.view(), data_len);
    try writeDataRow(w, "MACHINE IP", r.net_machine_ip.view(), data_len);
    for (r.net_machine_extra[0..r.net_machine_extra_count]) |extra| {
        try writeDataRow(w, "", extra.view(), data_len);
    }
    try writeDataRow(w, "CLIENT  IP", r.net_client_ip.view(), data_len);
    for (0..r.net_dns_count) |i| {
        var name_row: Str(16) = .{};
        name_row.print("DNS  IP {d}", .{i + 1});
        try writeDataRow(w, name_row.view(), r.net_dns_ip[i].view(), data_len);
    }
    try writeDataRow(w, "USER", r.net_current_user.view(), data_len);
    try writeDivider(w, .middle, data_len);
    try writeDataRow(w, "PROCESSOR", r.cpu_model.view(), data_len);
    try writeDataRow(w, "CORES", cores_row.view(), data_len);
    try writeDataRow(w, "HYPERVISOR", r.cpu_hypervisor.view(), data_len);
    // A clock row with no clock rendered " GHz". When no frequency source
    // exists, the last-level cache is the hardware fact worth the slot.
    if (freq_row.view().len > 0) {
        try writeDataRow(w, "CPU FREQ", freq_row.view(), data_len);
    } else if (r.cpu_cache.view().len > 0) {
        try writeDataRow(w, "CPU CACHE", r.cpu_cache.view(), data_len);
    }
    try writeBarRow(w, "LOAD  1m", r.load_1min_hd, @as(u64, r.cpu_cores) * 100, data_len);
    try writeBarRow(w, "LOAD  5m", r.load_5min_hd, @as(u64, r.cpu_cores) * 100, data_len);
    try writeBarRow(w, "LOAD 15m", r.load_15min_hd, @as(u64, r.cpu_cores) * 100, data_len);
    try writeDivider(w, .middle, data_len);
    for (0..r.volumes.count) |i| {
        const volume = &r.volumes.items[i];
        try writeDataRow(w, volume_labels[i].view(), volume_rows[i].view(), data_len);
        try writeBarRow(w, "DISK USAGE", volume.used_mib, volume.total_mib, data_len);
    }
    if (r.volumes.anyZfs()) {
        try writeDataRow(w, "ZFS HEALTH", "HEALTH O.K.", data_len);
    }
    try writeDivider(w, .middle, data_len);
    try writeDataRow(w, "MEMORY", mem_row.view(), data_len);
    try writeBarRow(w, "USAGE", @abs(r.mem_used_kib), r.mem_total_kib, data_len);
    try writeDivider(w, .middle, data_len);
    try writeDataRow(w, "LAST LOGIN", r.last_login.time_str.view(), data_len);
    if (r.last_login.ip_present) {
        try writeDataRow(w, "", r.last_login.ip.view(), data_len);
    }
    try writeDataRow(w, "UPTIME", uptime_row.view(), data_len);
    try writeDivider(w, .bottom, data_len);
}

/// A data row carrying a bar graph: the script's bar_graph(used, total)
/// into the data column.
fn writeBarRow(w: *Io.Writer, name: []const u8, used: u64, total: u64, data_len: usize) !void {
    var bar: Str(1024) = .{};
    var bw: Io.Writer = .fixed(bar.bytes[0..]);
    try writeBar(&bw, used, total, data_len);
    bar.len = @intCast(bw.buffered().len);
    try writeDataRow(w, name, bar.view(), data_len);
}

pub fn main(init: process.Init.Minimal) !void {
    const gpa = if (use_safe_allocator)
        safe_allocator.allocator()
    else
        heap.page_allocator;

    defer if (use_safe_allocator) {
        _ = safe_allocator.deinit();
    };

    var arena_allocator: heap.ArenaAllocator = .init(gpa);
    defer arena_allocator.deinit();
    const arena = arena_allocator.allocator();

    var threaded: Io.Threaded = .init(arena, .{
        .argv0 = .init(.{ .vector = init.args.vector }),
        .environ = init.environ,
    });

    const io = threaded.io();

    var report: Report = .read(io, init.environ);

    var stdout_buffer: [stdout_buffer_len]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const w = &stdout_writer.interface;
    // A reader that leaves early (report | head) or a full disk is not a
    // crash: there is nowhere left to print, so stop quietly. Propagating
    // WriteFailed panicked with a stack trace and could abort.
    writeReport(w, &report) catch return;
    w.flush() catch return;
}

test "row geometry against golden shape" {
    // Structural checks against the bash golden's verified geometry: a
    // 30-wide data column makes 50-cell borders, 48 fill glyphs in the
    // header's run, dividers breaking at cell 15, centered titles with
    // their padding split. Expectations are built with loops — counting
    // repeated glyphs by eye is exactly how the bash version won.
    var buf: [4096]u8 = undefined;
    var expect_buf: [4096]u8 = undefined;

    var w: Io.Writer = .fixed(&buf);
    try writeHeader(&w, 30);
    {
        var ew: Io.Writer = .fixed(&expect_buf);
        try ew.writeAll("┌");
        for (0..48) |_| try ew.writeAll("┬");
        try ew.writeAll("┐\n├");
        for (0..48) |_| try ew.writeAll("┴");
        try ew.writeAll("┤\n");
        try testing.expectEqualStrings(ew.buffered(), w.buffered());
    }

    var w2: Io.Writer = .fixed(&buf);
    try writeDivider(&w2, .top, 30);
    {
        var ew: Io.Writer = .fixed(&expect_buf);
        try ew.writeAll("├");
        for (0..15) |_| try ew.writeAll("─");
        try ew.writeAll("┬");
        for (0..32) |_| try ew.writeAll("─");
        try ew.writeAll("┤\n");
        try testing.expectEqualStrings(ew.buffered(), w2.buffered());
    }

    var w3: Io.Writer = .fixed(&buf);
    try writeCentered(&w3, "UNITED STATES GRAPHICS COMPANY", 30);
    {
        var ew: Io.Writer = .fixed(&expect_buf);
        try ew.writeAll("│");
        for (0..9) |_| try ew.writeAll(" ");
        try ew.writeAll("UNITED STATES GRAPHICS COMPANY");
        for (0..9) |_| try ew.writeAll(" ");
        try ew.writeAll("│\n");
        try testing.expectEqualStrings(ew.buffered(), w3.buffered());
    }

    var w4: Io.Writer = .fixed(&buf);
    try writeDataRow(&w4, "OS", "Nixos 26.11 (Zokor) Zokor", 30);
    {
        var ew: Io.Writer = .fixed(&expect_buf);
        try ew.writeAll("│ OS");
        // "OS" padded to 13 cells plus the column separator: 12 spaces.
        for (0..12) |_| try ew.writeAll(" ");
        try ew.writeAll("│ Nixos 26.11 (Zokor) Zokor");
        // 25 codepoints padded to 30 plus the column separator: 6 spaces.
        for (0..6) |_| try ew.writeAll(" ");
        try ew.writeAll("│\n");
        try testing.expectEqualStrings(ew.buffered(), w4.buffered());
    }
}

test "writeDataRow truncation quirk" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    // 31 codepoints triggers the cut at 27 + "..." (upstream's odd
    // >= 32 || == 31 test puts both widths in the same branch).
    var bar_buf: [128]u8 = undefined;
    var bw: Io.Writer = .fixed(&bar_buf);
    for (0..31) |_| try bw.writeAll("█");
    try writeDataRow(&w, "LOAD  1m", bw.buffered(), 30);
    // The cut leaves 27 glyphs + "..." = exactly the 30-codepoint column,
    // so the row keeps the standard 50-cell width and ends on a cut.
    const row = w.buffered();
    // 50 cells + the newline; golden rows measured without it are 50.
    try testing.expectEqual(@as(usize, 51), codepointCount(row));
    try testing.expect(mem.endsWith(u8, row, "█... │\n"));
}
