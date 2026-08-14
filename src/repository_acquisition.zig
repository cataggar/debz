const std = @import("std");

pub const Uri = std.Uri;

pub const Deadlines = struct {
    connect_ms: u64,
    read_ms: u64,
    overall_ms: u64,
};

pub const ProxyEndpoint = struct {
    uri: Uri,
    authorization: ?[]const u8 = null,
};

/// Proxy selection is always explicit. Null entries mean direct connection for
/// that scheme; no environment variables or host package-manager settings are read.
pub const ProxyPolicy = struct {
    http: ?ProxyEndpoint = null,
    https: ?ProxyEndpoint = null,

    pub const direct: ProxyPolicy = .{};
};

pub const RetryPolicy = struct {
    max_attempts: u16 = 1,
    retry_408: bool = true,
    retry_429: bool = true,
    retry_5xx: bool = true,
    backoff_ms: *const fn (attempt: u16) u64 = noBackoff,

    fn noBackoff(_: u16) u64 {
        return 0;
    }
};

pub const Credential = struct {
    authorization: []const u8,
};

pub const CredentialsProvider = struct {
    context: ?*anyopaque = null,
    getFn: *const fn (?*anyopaque, Uri) anyerror!?Credential = noCredentials,

    pub fn get(self: CredentialsProvider, uri: Uri) !?Credential {
        return self.getFn(self.context, uri);
    }

    fn noCredentials(_: ?*anyopaque, _: Uri) !?Credential {
        return null;
    }

    pub const none: CredentialsProvider = .{};
};

pub const Clock = struct {
    context: ?*anyopaque,
    nowMsFn: *const fn (?*anyopaque) u64,
    sleepMsFn: *const fn (?*anyopaque, u64) anyerror!void,

    pub fn nowMs(self: Clock) u64 {
        return self.nowMsFn(self.context);
    }

    pub fn sleepMs(self: Clock, milliseconds: u64) !void {
        return self.sleepMsFn(self.context, milliseconds);
    }
};

pub const Request = struct {
    uri: Uri,
    proxy: ProxyPolicy = .direct,
    deadlines: Deadlines,
    redirect_limit: u16,
    retry: RetryPolicy = .{},
    max_response_bytes: usize,
    credentials: CredentialsProvider = .none,
};

pub const Timing = struct {
    started_ms: u64,
    completed_ms: u64,
    attempts: u16,
};

pub const Provenance = struct {
    effective_uri: []u8,
    status: ?u16,
    size: usize,
    timing: Timing,

    pub fn deinit(self: *Provenance, allocator: std.mem.Allocator) void {
        allocator.free(self.effective_uri);
        self.* = undefined;
    }
};

pub const Result = struct {
    bytes: []u8,
    provenance: Provenance,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.provenance.deinit(allocator);
        self.* = undefined;
    }
};

pub const HttpRequest = struct {
    uri: Uri,
    proxy: ProxyPolicy,
    deadlines: Deadlines,
    max_response_bytes: usize,
    authorization: ?[]const u8,
};

pub const HttpResponse = struct {
    status: u16,
    body: []u8,
    location: ?[]u8 = null,

    pub fn deinit(self: *HttpResponse, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        if (self.location) |location| allocator.free(location);
        self.* = undefined;
    }
};

pub const Transport = struct {
    context: ?*anyopaque,
    requestFn: *const fn (?*anyopaque, std.mem.Allocator, HttpRequest) anyerror!HttpResponse,

    pub fn request(self: Transport, allocator: std.mem.Allocator, request_value: HttpRequest) !HttpResponse {
        return self.requestFn(self.context, allocator, request_value);
    }
};

pub const FileRead = struct {
    bytes: []u8,
    regular: bool,
};

pub const FileSystem = struct {
    context: ?*anyopaque,
    readFn: *const fn (?*anyopaque, std.mem.Allocator, []const u8, usize, Deadlines) anyerror!FileRead,

    pub fn read(
        self: FileSystem,
        allocator: std.mem.Allocator,
        path: []const u8,
        limit: usize,
        deadlines: Deadlines,
    ) !FileRead {
        return self.readFn(self.context, allocator, path, limit, deadlines);
    }
};

pub const Dependencies = struct {
    transport: Transport,
    files: FileSystem,
    clock: Clock,
};

pub const Error = error{
    UnsupportedScheme,
    InvalidConfiguration,
    InvalidFileUri,
    NonLocalFileAuthority,
    AmbiguousFilePath,
    NotRegularFile,
    ResponseTooLarge,
    RedirectLimitExceeded,
    MissingRedirectLocation,
    InvalidRedirect,
    NotFound,
    HttpStatus,
    OverallDeadlineExceeded,
};

pub fn acquire(
    allocator: std.mem.Allocator,
    request_value: Request,
    dependencies: Dependencies,
) !Result {
    if (request_value.max_response_bytes == 0 or
        request_value.deadlines.connect_ms == 0 or
        request_value.deadlines.read_ms == 0 or
        request_value.deadlines.overall_ms == 0 or
        request_value.retry.max_attempts == 0)
    {
        return error.InvalidConfiguration;
    }

    const started_ms = dependencies.clock.nowMs();
    if (std.ascii.eqlIgnoreCase(request_value.uri.scheme, "file")) {
        return acquireFile(allocator, request_value, dependencies, started_ms);
    }
    if (!std.ascii.eqlIgnoreCase(request_value.uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(request_value.uri.scheme, "https"))
    {
        return error.UnsupportedScheme;
    }
    return acquireHttp(allocator, request_value, dependencies, started_ms);
}

fn acquireFile(
    allocator: std.mem.Allocator,
    request_value: Request,
    dependencies: Dependencies,
    started_ms: u64,
) !Result {
    const uri = request_value.uri;
    if (uri.query != null or uri.fragment != null or uri.user != null or uri.password != null or uri.port != null)
        return error.InvalidFileUri;
    if (uri.host) |host_component| {
        var host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
        const host = host_component.toRaw(&host_buffer) catch return error.InvalidFileUri;
        if (host.len != 0 and !std.ascii.eqlIgnoreCase(host, "localhost"))
            return error.NonLocalFileAuthority;
    }

    const encoded_path = switch (uri.path) {
        .raw => |path| path,
        .percent_encoded => |path| path,
    };
    if (encoded_path.len == 0 or encoded_path[0] != '/') return error.InvalidFileUri;
    if (hasAmbiguousPath(encoded_path)) return error.AmbiguousFilePath;

    const decoded_storage = try allocator.dupe(u8, encoded_path);
    defer allocator.free(decoded_storage);
    const decoded = std.Uri.percentDecodeInPlace(decoded_storage);
    if (std.mem.findScalar(u8, decoded, 0) != null or hasDotSegment(decoded))
        return error.AmbiguousFilePath;

    checkOverall(dependencies.clock, started_ms, request_value.deadlines.overall_ms) catch
        return error.OverallDeadlineExceeded;
    const remaining_ms = request_value.deadlines.overall_ms -
        elapsed(started_ms, dependencies.clock.nowMs());
    const read = try dependencies.files.read(
        allocator,
        decoded,
        request_value.max_response_bytes,
        withRemainingOverall(request_value.deadlines, remaining_ms),
    );
    errdefer allocator.free(read.bytes);
    if (!read.regular) return error.NotRegularFile;
    if (read.bytes.len > request_value.max_response_bytes) return error.ResponseTooLarge;
    const completed_ms = dependencies.clock.nowMs();
    if (elapsed(started_ms, completed_ms) > request_value.deadlines.overall_ms)
        return error.OverallDeadlineExceeded;

    return .{
        .bytes = read.bytes,
        .provenance = .{
            .effective_uri = try redactUri(allocator, uri),
            .status = null,
            .size = read.bytes.len,
            .timing = .{
                .started_ms = started_ms,
                .completed_ms = completed_ms,
                .attempts = 1,
            },
        },
    };
}

fn acquireHttp(
    allocator: std.mem.Allocator,
    request_value: Request,
    dependencies: Dependencies,
    started_ms: u64,
) !Result {
    var uri_text = try formatUri(allocator, request_value.uri, false);
    defer allocator.free(uri_text);
    var current_uri = try Uri.parse(uri_text);
    var redirects: u16 = 0;
    var attempts: u16 = 0;
    var total_attempts: u16 = 0;
    const initial_origin = try origin(allocator, current_uri);
    defer allocator.free(initial_origin);

    while (true) {
        checkOverall(dependencies.clock, started_ms, request_value.deadlines.overall_ms) catch
            return error.OverallDeadlineExceeded;

        const current_origin = try origin(allocator, current_uri);
        defer allocator.free(current_origin);
        const may_authorize = std.mem.eql(u8, initial_origin, current_origin);
        const credential = if (may_authorize) try request_value.credentials.get(current_uri) else null;

        attempts += 1;
        total_attempts = std.math.add(u16, total_attempts, 1) catch
            return error.InvalidConfiguration;
        const remaining_ms = request_value.deadlines.overall_ms -
            elapsed(started_ms, dependencies.clock.nowMs());
        var response = dependencies.transport.request(allocator, .{
            .uri = current_uri,
            .proxy = request_value.proxy,
            .deadlines = withRemainingOverall(request_value.deadlines, remaining_ms),
            .max_response_bytes = request_value.max_response_bytes,
            .authorization = if (credential) |value| value.authorization else null,
        }) catch |err| {
            if (attempts < request_value.retry.max_attempts and isSafeTransient(err)) {
                try deterministicBackoff(request_value, dependencies, attempts, started_ms);
                continue;
            }
            return err;
        };
        var response_live = true;
        errdefer if (response_live) response.deinit(allocator);

        if (response.body.len > request_value.max_response_bytes) return error.ResponseTooLarge;
        if (isRedirect(response.status)) {
            if (redirects >= request_value.redirect_limit) return error.RedirectLimitExceeded;
            const location = response.location orelse return error.MissingRedirectLocation;
            const next_text = resolveUri(allocator, current_uri, location) catch return error.InvalidRedirect;
            response.deinit(allocator);
            response_live = false;
            allocator.free(uri_text);
            uri_text = next_text;
            current_uri = Uri.parse(uri_text) catch return error.InvalidRedirect;
            if (!std.ascii.eqlIgnoreCase(current_uri.scheme, "http") and
                !std.ascii.eqlIgnoreCase(current_uri.scheme, "https"))
                return error.InvalidRedirect;
            redirects += 1;
            attempts = 0;
            continue;
        }

        if (response.status < 200 or response.status >= 300) {
            if (attempts < request_value.retry.max_attempts and
                shouldRetryStatus(request_value.retry, response.status))
            {
                response.deinit(allocator);
                response_live = false;
                try deterministicBackoff(request_value, dependencies, attempts, started_ms);
                continue;
            }
            if (response.status == 404) return error.NotFound;
            return error.HttpStatus;
        }

        const completed_ms = dependencies.clock.nowMs();
        if (elapsed(started_ms, completed_ms) > request_value.deadlines.overall_ms)
            return error.OverallDeadlineExceeded;
        const effective_uri = try redactUri(allocator, current_uri);
        const status = response.status;
        const body = response.body;
        response.body = &.{};
        response.deinit(allocator);
        response_live = false;
        return .{
            .bytes = body,
            .provenance = .{
                .effective_uri = effective_uri,
                .status = status,
                .size = body.len,
                .timing = .{
                    .started_ms = started_ms,
                    .completed_ms = completed_ms,
                    .attempts = total_attempts,
                },
            },
        };
    }
}

fn deterministicBackoff(request_value: Request, dependencies: Dependencies, attempt: u16, started_ms: u64) !void {
    const delay = request_value.retry.backoff_ms(attempt);
    const now = dependencies.clock.nowMs();
    if (elapsed(started_ms, now) > request_value.deadlines.overall_ms or
        delay > request_value.deadlines.overall_ms - elapsed(started_ms, now))
        return error.OverallDeadlineExceeded;
    try dependencies.clock.sleepMs(delay);
}

fn checkOverall(clock: Clock, started_ms: u64, overall_ms: u64) !void {
    if (elapsed(started_ms, clock.nowMs()) > overall_ms) return error.OverallDeadlineExceeded;
}

fn elapsed(started: u64, now: u64) u64 {
    return if (now >= started) now - started else 0;
}

fn withRemainingOverall(deadlines: Deadlines, remaining_ms: u64) Deadlines {
    return .{
        .connect_ms = @min(deadlines.connect_ms, remaining_ms),
        .read_ms = @min(deadlines.read_ms, remaining_ms),
        .overall_ms = remaining_ms,
    };
}

fn shouldRetryStatus(policy: RetryPolicy, status: u16) bool {
    return (status == 408 and policy.retry_408) or
        (status == 429 and policy.retry_429) or
        (status >= 500 and status <= 599 and policy.retry_5xx);
}

fn isSafeTransient(err: anyerror) bool {
    return switch (err) {
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.ConnectionTimedOut,
        error.NetworkUnreachable,
        error.HostLacksNetworkAddresses,
        error.TemporaryNameServerFailure,
        error.ReadFailed,
        error.WriteFailed,
        error.ConnectDeadlineExceeded,
        error.ReadDeadlineExceeded,
        => true,
        else => false,
    };
}

fn isRedirect(status: u16) bool {
    return status == 301 or status == 302 or status == 303 or status == 307 or status == 308;
}

fn hasAmbiguousPath(path: []const u8) bool {
    var i: usize = 0;
    while (i + 2 < path.len) : (i += 1) {
        if (path[i] != '%') continue;
        const value = std.fmt.parseInt(u8, path[i + 1 .. i + 3], 16) catch continue;
        if (value == '/' or value == '\\' or value == 0) return true;
    }
    return false;
}

fn hasDotSegment(path: []const u8) bool {
    var segments = std.mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return true;
    }
    return false;
}

pub fn redactUri(allocator: std.mem.Allocator, uri: Uri) ![]u8 {
    var without_query = uri;
    without_query.query = null;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try without_query.writeToStream(&output.writer, .{
        .scheme = true,
        .authentication = false,
        .authority = true,
        .path = true,
        .query = false,
        .fragment = false,
        .port = true,
    });
    if (uri.query) |query_component| {
        const query = switch (query_component) {
            .raw, .percent_encoded => |value| value,
        };
        try output.writer.writeByte('?');
        var parameters = std.mem.splitScalar(u8, query, '&');
        var first = true;
        while (parameters.next()) |parameter| {
            if (!first) try output.writer.writeByte('&');
            first = false;
            if (std.mem.indexOfScalar(u8, parameter, '=')) |equals| {
                try output.writer.print("{s}=REDACTED", .{parameter[0..equals]});
            } else {
                try output.writer.writeAll(parameter);
            }
        }
    }
    return output.toOwnedSlice();
}

fn formatUri(allocator: std.mem.Allocator, uri: Uri, authentication: bool) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try uri.writeToStream(&output.writer, .{
        .scheme = true,
        .authentication = authentication,
        .authority = true,
        .path = true,
        .query = true,
        .fragment = false,
        .port = true,
    });
    return output.toOwnedSlice();
}

fn origin(allocator: std.mem.Allocator, uri: Uri) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try output.writer.print("{s}://", .{uri.scheme});
    const host = uri.host orelse return error.InvalidRedirect;
    try host.formatHost(&output.writer);
    const port = uri.port orelse if (std.ascii.eqlIgnoreCase(uri.scheme, "https")) @as(u16, 443) else @as(u16, 80);
    try output.writer.print(":{d}", .{port});
    const bytes = try output.toOwnedSlice();
    for (bytes) |*byte| byte.* = std.ascii.toLower(byte.*);
    return bytes;
}

fn resolveUri(allocator: std.mem.Allocator, base: Uri, location: []const u8) ![]u8 {
    var capacity = location.len + 4096;
    while (capacity <= 1024 * 1024) : (capacity *= 2) {
        const buffer = try allocator.alloc(u8, capacity);
        defer allocator.free(buffer);
        @memcpy(buffer[0..location.len], location);
        var auxiliary = buffer;
        const resolved = Uri.resolveInPlace(base, location.len, &auxiliary) catch |err| switch (err) {
            error.NoSpaceLeft => continue,
            else => return err,
        };
        return formatUri(allocator, resolved, false);
    }
    return error.InvalidRedirect;
}

pub const Production = struct {
    io: std.Io,

    pub fn dependencies(self: *Production) Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = httpRequest },
            .files = .{ .context = self, .readFn = fileRead },
            .clock = .{
                .context = self,
                .nowMsFn = nowMs,
                .sleepMsFn = sleepMs,
            },
        };
    }

    fn nowMs(context: ?*anyopaque) u64 {
        const self: *Production = @ptrCast(@alignCast(context.?));
        const timestamp = std.Io.Clock.awake.now(self.io);
        return @intCast(@max(0, @divFloor(timestamp.nanoseconds, std.time.ns_per_ms)));
    }

    fn sleepMs(context: ?*anyopaque, milliseconds: u64) !void {
        const self: *Production = @ptrCast(@alignCast(context.?));
        const bounded: i64 = @intCast(@min(milliseconds, @as(u64, std.math.maxInt(i64))));
        try self.io.sleep(.fromMilliseconds(bounded), .awake);
    }

    fn fileRead(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        limit: usize,
        deadlines: Deadlines,
    ) !FileRead {
        const self: *Production = @ptrCast(@alignCast(context.?));
        const file = try std.Io.Dir.openFileAbsolute(self.io, path, .{ .mode = .read_only });
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return .{ .bytes = try allocator.alloc(u8, 0), .regular = false };
        if (stat.size > limit) return error.ResponseTooLarge;
        var buffer: [8192]u8 = undefined;
        var reader = file.reader(self.io, &buffer);
        return .{
            .bytes = try bodyWithDeadline(
                self.io,
                &reader.interface,
                allocator,
                limit,
                deadlines.read_ms,
            ),
            .regular = true,
        };
    }

    fn httpRequest(context: ?*anyopaque, allocator: std.mem.Allocator, request_value: HttpRequest) !HttpResponse {
        const self: *Production = @ptrCast(@alignCast(context.?));
        var client: std.http.Client = .{ .allocator = allocator, .io = self.io };
        defer client.deinit();
        const started_ms = nowIoMs(self.io);

        var http_proxy: std.http.Client.Proxy = undefined;
        var https_proxy: std.http.Client.Proxy = undefined;
        var http_proxy_host: ?[]const u8 = null;
        defer if (http_proxy_host) |host| allocator.free(host);
        var https_proxy_host: ?[]const u8 = null;
        defer if (https_proxy_host) |host| allocator.free(host);
        if (request_value.proxy.http) |endpoint| {
            http_proxy = try makeProxy(allocator, endpoint);
            http_proxy_host = http_proxy.host.bytes;
            client.http_proxy = &http_proxy;
        }
        if (request_value.proxy.https) |endpoint| {
            https_proxy = try makeProxy(allocator, endpoint);
            https_proxy_host = https_proxy.host.bytes;
            client.https_proxy = &https_proxy;
        }

        var request = try requestWithDeadline(
            &client,
            request_value.uri,
            request_value.authorization,
            stageTimeout(self.io, started_ms, request_value.deadlines.connect_ms, request_value.deadlines.overall_ms),
        );
        defer request.deinit();
        try sendWithDeadline(
            &request,
            stageTimeout(self.io, started_ms, request_value.deadlines.connect_ms, request_value.deadlines.overall_ms),
        );
        var header_buffer: [8192]u8 = undefined;
        var response = try headWithDeadline(
            &request,
            &header_buffer,
            stageTimeout(self.io, started_ms, request_value.deadlines.read_ms, request_value.deadlines.overall_ms),
        );
        const status: u16 = @intFromEnum(response.head.status);
        const location = if (response.head.location) |value| try allocator.dupe(u8, value) else null;
        errdefer if (location) |value| allocator.free(value);
        var transfer_buffer: [64]u8 = undefined;
        var decompress: std.http.Decompress = undefined;
        const decompression_size: usize = switch (response.head.content_encoding) {
            .identity => 0,
            .zstd => @as(usize, std.compress.zstd.default_window_len),
            .deflate, .gzip => @as(usize, std.compress.flate.max_window_len),
            .compress => return error.UnsupportedCompressionMethod,
        };
        const decompression_buffer = try allocator.alloc(u8, decompression_size);
        defer allocator.free(decompression_buffer);
        const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompression_buffer);
        const body = try bodyWithDeadline(
            self.io,
            reader,
            allocator,
            request_value.max_response_bytes,
            stageTimeout(self.io, started_ms, request_value.deadlines.read_ms, request_value.deadlines.overall_ms),
        );
        return .{ .status = status, .body = body, .location = location };
    }

    fn makeProxy(allocator: std.mem.Allocator, endpoint: ProxyEndpoint) !std.http.Client.Proxy {
        if (endpoint.uri.user != null or endpoint.uri.password != null or
            endpoint.uri.query != null or endpoint.uri.fragment != null)
            return error.InvalidProxyUri;
        const protocol = std.http.Client.Protocol.fromScheme(endpoint.uri.scheme) orelse
            return error.UnsupportedUriScheme;
        var host_buffer: [std.Io.net.HostName.max_len]u8 = undefined;
        const borrowed_host = try endpoint.uri.getHost(&host_buffer);
        const host_bytes = try allocator.dupe(u8, borrowed_host.bytes);
        return .{
            .protocol = protocol,
            .host = .{ .bytes = host_bytes },
            .authorization = endpoint.authorization,
            .port = endpoint.uri.port orelse switch (protocol) {
                .plain => 80,
                .tls => 443,
            },
            .supports_connect = true,
        };
    }

    fn createRequest(
        client: *std.http.Client,
        uri: Uri,
        authorization: ?[]const u8,
    ) std.http.Client.RequestError!std.http.Client.Request {
        return client.request(.GET, uri, .{
            .redirect_behavior = .unhandled,
            .keep_alive = false,
            .headers = .{
                .authorization = if (authorization) |value| .{ .override = value } else .omit,
            },
        });
    }

    fn requestWithDeadline(
        client: *std.http.Client,
        uri: Uri,
        authorization: ?[]const u8,
        timeout_ms: u64,
    ) !std.http.Client.Request {
        const Outcome = union(enum) {
            result: std.http.Client.RequestError!std.http.Client.Request,
            timeout: void,
        };
        var outcomes: [2]Outcome = undefined;
        var select = std.Io.Select(Outcome).init(client.io, &outcomes);
        select.async(.result, createRequest, .{ client, uri, authorization });
        select.async(.timeout, waitTimeout, .{ client.io, timeout_ms });
        switch (try select.await()) {
            .result => |result| {
                select.cancelDiscard();
                return result;
            },
            .timeout => {
                while (select.cancel()) |outcome| switch (outcome) {
                    .result => |result| if (result) |request_value| {
                        var abandoned = request_value;
                        abandoned.deinit();
                    } else |_| {},
                    .timeout => {},
                };
                return error.ConnectDeadlineExceeded;
            },
        }
    }

    fn sendRequest(request: *std.http.Client.Request) @TypeOf(request.sendBodiless()) {
        return request.sendBodiless();
    }

    fn sendWithDeadline(request: *std.http.Client.Request, timeout_ms: u64) !void {
        const SendResult = @TypeOf(request.sendBodiless());
        const Outcome = union(enum) { result: SendResult, timeout: void };
        var outcomes: [2]Outcome = undefined;
        var select = std.Io.Select(Outcome).init(request.client.io, &outcomes);
        select.async(.result, sendRequest, .{request});
        select.async(.timeout, waitTimeout, .{ request.client.io, timeout_ms });
        switch (try select.await()) {
            .result => |result| {
                select.cancelDiscard();
                return result;
            },
            .timeout => {
                select.cancelDiscard();
                return error.ConnectDeadlineExceeded;
            },
        }
    }

    fn receiveHead(
        request: *std.http.Client.Request,
        buffer: []u8,
    ) @TypeOf(request.receiveHead(buffer)) {
        return request.receiveHead(buffer);
    }

    fn headWithDeadline(
        request: *std.http.Client.Request,
        buffer: []u8,
        timeout_ms: u64,
    ) !std.http.Client.Response {
        const HeadResult = @TypeOf(request.receiveHead(buffer));
        const Outcome = union(enum) { result: HeadResult, timeout: void };
        var outcomes: [2]Outcome = undefined;
        var select = std.Io.Select(Outcome).init(request.client.io, &outcomes);
        select.async(.result, receiveHead, .{ request, buffer });
        select.async(.timeout, waitTimeout, .{ request.client.io, timeout_ms });
        switch (try select.await()) {
            .result => |result| {
                select.cancelDiscard();
                return result;
            },
            .timeout => {
                select.cancelDiscard();
                return error.ReadDeadlineExceeded;
            },
        }
    }

    fn readBody(
        reader: *std.Io.Reader,
        allocator: std.mem.Allocator,
        limit: usize,
    ) std.Io.Reader.LimitedAllocError![]u8 {
        return reader.allocRemaining(allocator, .limited(limit));
    }

    fn bodyWithDeadline(
        io: std.Io,
        reader: *std.Io.Reader,
        allocator: std.mem.Allocator,
        limit: usize,
        timeout_ms: u64,
    ) ![]u8 {
        const BodyResult = std.Io.Reader.LimitedAllocError![]u8;
        const Outcome = union(enum) { result: BodyResult, timeout: void };
        var outcomes: [2]Outcome = undefined;
        var select = std.Io.Select(Outcome).init(io, &outcomes);
        select.async(.result, readBody, .{ reader, allocator, limit });
        select.async(.timeout, waitTimeout, .{ io, timeout_ms });
        switch (try select.await()) {
            .result => |result| {
                select.cancelDiscard();
                return result;
            },
            .timeout => {
                while (select.cancel()) |outcome| switch (outcome) {
                    .result => |result| if (result) |bytes| allocator.free(bytes) else |_| {},
                    .timeout => {},
                };
                return error.ReadDeadlineExceeded;
            },
        }
    }

    fn waitTimeout(io: std.Io, timeout_ms: u64) void {
        const bounded: i64 = @intCast(@min(timeout_ms, @as(u64, std.math.maxInt(i64))));
        io.sleep(.fromMilliseconds(bounded), .awake) catch {};
    }

    fn nowIoMs(io: std.Io) u64 {
        const timestamp = std.Io.Clock.awake.now(io);
        return @intCast(@max(0, @divFloor(timestamp.nanoseconds, std.time.ns_per_ms)));
    }

    fn stageTimeout(io: std.Io, started_ms: u64, operation_ms: u64, overall_ms: u64) u64 {
        const spent = elapsed(started_ms, nowIoMs(io));
        if (spent >= overall_ms) return 0;
        return @min(operation_ms, overall_ms - spent);
    }
};

test "redaction removes userinfo and fragment" {
    const allocator = std.testing.allocator;
    const uri = try Uri.parse("https://alice:secret@example.test/path?q=ok#token");
    const redacted = try redactUri(allocator, uri);
    defer allocator.free(redacted);
    try std.testing.expectEqualStrings("https://example.test/path?q=REDACTED", redacted);
}

test "file acquisition rejects remote authority and ambiguous traversal" {
    const allocator = std.testing.allocator;
    var fixture = TestFixture{};
    const deps = fixture.dependencies();
    try std.testing.expectError(error.NonLocalFileAuthority, acquire(allocator, .{
        .uri = try Uri.parse("file://remote/etc/passwd"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .max_response_bytes = 10,
    }, deps));
    try std.testing.expectError(error.AmbiguousFilePath, acquire(allocator, .{
        .uri = try Uri.parse("file:///safe/%2e%2e/secret"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .max_response_bytes = 10,
    }, deps));
}

test "file acquisition requires a regular bounded file" {
    const allocator = std.testing.allocator;
    var fixture = TestFixture{ .file_bytes = "abc", .file_regular = true };
    var result = try acquire(allocator, .{
        .uri = try Uri.parse("file://localhost/repo/Packages"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .max_response_bytes = 3,
    }, fixture.dependencies());
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("abc", result.bytes);
    try std.testing.expectEqualStrings("file://localhost/repo/Packages", result.provenance.effective_uri);
    try std.testing.expectEqual(@as(?u16, null), result.provenance.status);

    fixture.file_regular = false;
    try std.testing.expectError(error.NotRegularFile, acquire(allocator, .{
        .uri = try Uri.parse("file:///repo"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .max_response_bytes = 3,
    }, fixture.dependencies()));
}

test "redirect strips credentials across origins" {
    const allocator = std.testing.allocator;
    var fixture = TestFixture{
        .responses = &.{
            .{ .status = 302, .body = "", .location = "https://other.test/final" },
            .{ .status = 200, .body = "ok" },
        },
        .credential = .{ .authorization = "Bearer secret" },
    };
    var result = try acquire(allocator, .{
        .uri = try Uri.parse("https://user:password@example.test/start"),
        .deadlines = testDeadlines(),
        .redirect_limit = 2,
        .max_response_bytes = 16,
        .credentials = fixture.credentials(),
    }, fixture.dependencies());
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("ok", result.bytes);
    try std.testing.expectEqualStrings("https://other.test/final", result.provenance.effective_uri);
    try std.testing.expectEqual(@as(usize, 2), fixture.request_count);
    try std.testing.expectEqual(@as(u16, 2), result.provenance.timing.attempts);
    try std.testing.expect(fixture.saw_authorization[0]);
    try std.testing.expect(!fixture.saw_authorization[1]);
}

test "redirect limit is bounded" {
    const allocator = std.testing.allocator;
    var fixture = TestFixture{
        .responses = &.{.{ .status = 302, .body = "", .location = "/again" }},
    };
    try std.testing.expectError(error.RedirectLimitExceeded, acquire(allocator, .{
        .uri = try Uri.parse("http://example.test/start"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .max_response_bytes = 16,
    }, fixture.dependencies()));
}

test "safe transient status retries with deterministic backoff" {
    const allocator = std.testing.allocator;
    var fixture = TestFixture{
        .responses = &.{
            .{ .status = 503, .body = "later" },
            .{ .status = 200, .body = "ready" },
        },
    };
    var result = try acquire(allocator, .{
        .uri = try Uri.parse("https://example.test/Packages"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .retry = .{ .max_attempts = 2, .backoff_ms = fixedBackoff },
        .max_response_bytes = 16,
    }, fixture.dependencies());
    defer result.deinit(allocator);
    try std.testing.expectEqualStrings("ready", result.bytes);
    try std.testing.expectEqual(@as(u64, 7), fixture.now_ms);
    try std.testing.expectEqual(@as(u16, 2), result.provenance.timing.attempts);
}

test "not found status is explicit and has no partial-success fallback" {
    const allocator = std.testing.allocator;
    var fixture = TestFixture{
        .responses = &.{.{ .status = 404, .body = "not repository data" }},
    };
    try std.testing.expectError(error.NotFound, acquire(allocator, .{
        .uri = try Uri.parse("https://example.test/missing"),
        .deadlines = testDeadlines(),
        .redirect_limit = 0,
        .retry = .{ .max_attempts = 3 },
        .max_response_bytes = 64,
    }, fixture.dependencies()));
    try std.testing.expectEqual(@as(usize, 1), fixture.request_count);
}

test "production transport rejects ambiguous explicit proxy configuration" {
    const allocator = std.testing.allocator;
    var production: Production = .{ .io = std.testing.io };
    try std.testing.expectError(error.InvalidProxyUri, Production.httpRequest(&production, allocator, .{
        .uri = try Uri.parse("https://example.test/"),
        .proxy = .{ .https = .{ .uri = try Uri.parse("http://proxy.test/?secret=value") } },
        .deadlines = testDeadlines(),
        .max_response_bytes = 16,
        .authorization = null,
    }));
}

fn fixedBackoff(_: u16) u64 {
    return 7;
}

fn testDeadlines() Deadlines {
    return .{ .connect_ms = 100, .read_ms = 100, .overall_ms = 1000 };
}

const FixtureResponse = struct {
    status: u16,
    body: []const u8,
    location: ?[]const u8 = null,
};

const TestFixture = struct {
    now_ms: u64 = 0,
    file_bytes: []const u8 = "",
    file_regular: bool = true,
    responses: []const FixtureResponse = &.{},
    request_count: usize = 0,
    saw_authorization: [8]bool = @splat(false),
    credential: ?Credential = null,

    fn dependencies(self: *TestFixture) Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = transportRequest },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{ .context = self, .nowMsFn = nowMs, .sleepMsFn = sleepMs },
        };
    }

    fn credentials(self: *TestFixture) CredentialsProvider {
        return .{ .context = self, .getFn = getCredential };
    }

    fn nowMs(context: ?*anyopaque) u64 {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        return self.now_ms;
    }

    fn sleepMs(context: ?*anyopaque, milliseconds: u64) !void {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        self.now_ms += milliseconds;
    }

    fn getCredential(context: ?*anyopaque, _: Uri) !?Credential {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        return self.credential;
    }

    fn readFile(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        _: []const u8,
        limit: usize,
        _: Deadlines,
    ) !FileRead {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        if (self.file_bytes.len > limit) return error.ResponseTooLarge;
        return .{
            .bytes = try allocator.dupe(u8, self.file_bytes),
            .regular = self.file_regular,
        };
    }

    fn transportRequest(context: ?*anyopaque, allocator: std.mem.Allocator, request_value: HttpRequest) !HttpResponse {
        const self: *TestFixture = @ptrCast(@alignCast(context.?));
        if (self.request_count >= self.responses.len) return error.ConnectionResetByPeer;
        const index = self.request_count;
        self.request_count += 1;
        self.saw_authorization[index] = request_value.authorization != null;
        const fixture = self.responses[index];
        if (fixture.body.len > request_value.max_response_bytes) return error.ResponseTooLarge;
        return .{
            .status = fixture.status,
            .body = try allocator.dupe(u8, fixture.body),
            .location = if (fixture.location) |value| try allocator.dupe(u8, value) else null,
        };
    }
};
