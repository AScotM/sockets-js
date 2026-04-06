#!/usr/bin/env node

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const process = require("process");

class ToolConfig {
    constructor(options = {}) {
        this.logLevel = "INFO";
        this.jsonOutput = false;
        this.compactJson = false;
        this.help = false;
        this.showPerformance = false;
        this.quiet = false;
        this.extended = false;
        this.color = "auto";
        this.sockstatPath = "/proc/net/sockstat";
        this.sockstat6Path = "/proc/net/sockstat6";
        this.netlinkPath = "/proc/net/netlink";
        this.packetPath = "/proc/net/packet";
        this.snmpPath = "/proc/net/snmp";
        this.netstatPath = "/proc/net/netstat";
        this.outputFile = null;
        this.configFile = null;
        this.allowedRoots = ["/proc", "/tmp/socket-stats"];
        this.maxFileSize = 10 * 1024 * 1024;
        this.maxLineCount = 10000;
        this.maxLineSize = 1024 * 1024;
        this.includeZeros = false;
        this.apply(options);
    }

    apply(options) {
        for (const [key, value] of Object.entries(options)) {
            if (Object.prototype.hasOwnProperty.call(this, key)) {
                this[key] = value;
            }
        }
    }

    clone() {
        return new ToolConfig(JSON.parse(JSON.stringify(this)));
    }
}

class Logger {
    constructor(level = "INFO", quiet = false) {
        this.levels = {
            DEBUG: 10,
            INFO: 20,
            WARNING: 30,
            ERROR: 40
        };
        this.level = this.normalizeLevel(level);
        this.quiet = quiet;
        this.dedup = new Map();
        this.dedupTtlMs = 300000;
        this.dedupMaxSize = 1000;
    }

    normalizeLevel(level) {
        const upper = String(level || "INFO").toUpperCase();
        return this.levels[upper] ? upper : "INFO";
    }

    setLevel(level) {
        this.level = this.normalizeLevel(level);
    }

    setQuiet(quiet) {
        this.quiet = Boolean(quiet);
    }

    shouldLog(level) {
        const normalized = this.normalizeLevel(level);
        return this.levels[normalized] >= this.levels[this.level];
    }

    cleanDedup(now = Date.now()) {
        for (const [key, ts] of this.dedup.entries()) {
            if (now - ts > this.dedupTtlMs) {
                this.dedup.delete(key);
            }
        }
        if (this.dedup.size <= this.dedupMaxSize) {
            return;
        }
        const entries = Array.from(this.dedup.entries()).sort((a, b) => a[1] - b[1]);
        const excess = this.dedup.size - this.dedupMaxSize;
        for (let i = 0; i < excess; i += 1) {
            this.dedup.delete(entries[i][0]);
        }
    }

    log(level, message) {
        const normalized = this.normalizeLevel(level);
        if (this.quiet && normalized !== "ERROR") {
            return;
        }
        if (!this.shouldLog(normalized)) {
            return;
        }
        if (normalized === "DEBUG") {
            const key = `${normalized}:${message}`;
            const now = Date.now();
            this.cleanDedup(now);
            const prev = this.dedup.get(key);
            if (prev && now - prev < this.dedupTtlMs) {
                return;
            }
            this.dedup.set(key, now);
        }
        const ts = new Date().toISOString();
        process.stderr.write(`[${ts}] ${normalized}: ${message}\n`);
    }

    debug(message) {
        this.log("DEBUG", message);
    }

    info(message) {
        this.log("INFO", message);
    }

    warning(message) {
        this.log("WARNING", message);
    }

    error(message) {
        this.log("ERROR", message);
    }
}

class ProtocolStats {
    constructor(name, defaults = {}) {
        this.name = String(name);
        this.fields = {};
        for (const [k, v] of Object.entries(defaults)) {
            this.fields[k] = ProtocolStats.toInt(v);
        }
    }

    static toInt(value) {
        if (typeof value === "number" && Number.isInteger(value)) {
            return value;
        }
        const parsed = Number.parseInt(String(value), 10);
        if (!Number.isFinite(parsed)) {
            throw new Error(`Failed to parse integer value: ${value}`);
        }
        return parsed;
    }

    set(field, value) {
        this.fields[field] = ProtocolStats.toInt(value);
    }

    get(field, fallback = 0) {
        return Object.prototype.hasOwnProperty.call(this.fields, field) ? this.fields[field] : fallback;
    }

    add(field, value) {
        this.fields[field] = this.get(field, 0) + ProtocolStats.toInt(value);
    }

    hasPositiveInUse() {
        return this.get("in_use", 0) > 0;
    }

    isEmpty() {
        return Object.values(this.fields).every(v => v === 0);
    }

    toJSON() {
        return { ...this.fields };
    }
}

class Metadata {
    constructor({ source, hostname, generatedAt, pid, platform, nodeVersion }) {
        this.source = source;
        this.hostname = hostname;
        this.generated_at = generatedAt;
        this.pid = pid;
        this.platform = platform;
        this.node_version = nodeVersion;
    }

    static create(source) {
        return new Metadata({
            source,
            hostname: os.hostname() || "unknown",
            generatedAt: new Date().toISOString(),
            pid: process.pid,
            platform: process.platform,
            nodeVersion: process.version
        });
    }

    toJSON() {
        return {
            source: this.source,
            hostname: this.hostname,
            generated_at: this.generated_at,
            pid: this.pid,
            platform: this.platform,
            node_version: this.node_version
        };
    }
}

class PerformanceMetrics {
    constructor(startHrtime, startMemory) {
        this.startHrtime = startHrtime;
        this.startMemory = startMemory;
        this.finishHrtime = null;
        this.finishMemory = null;
    }

    stop() {
        this.finishHrtime = process.hrtime.bigint();
        this.finishMemory = process.memoryUsage();
    }

    toJSON() {
        const endHr = this.finishHrtime ?? process.hrtime.bigint();
        const endMem = this.finishMemory ?? process.memoryUsage();
        const durationNs = endHr - this.startHrtime;
        return {
            execution_time_seconds: Number(durationNs) / 1e9,
            rss_mb: endMem.rss / 1024 / 1024,
            heap_total_mb: endMem.heapTotal / 1024 / 1024,
            heap_used_mb: endMem.heapUsed / 1024 / 1024,
            external_mb: endMem.external / 1024 / 1024,
            array_buffers_mb: endMem.arrayBuffers / 1024 / 1024,
            start_heap_used_mb: this.startMemory.heapUsed / 1024 / 1024
        };
    }
}

class SocketStatsReport {
    constructor(metadata) {
        this.metadata = metadata;
        this.sockets_used = 0;
        this.protocols = new Map();
        this.tcp_ext = {};
        this.notes = [];
        this.read_sources = [];
        this.summary = {
            protocol_count: 0,
            populated_protocol_count: 0,
            total_protocol_fields: 0,
            total_memory_units: 0,
            total_in_use: 0
        };
    }

    setSocketsUsed(value) {
        this.sockets_used = ProtocolStats.toInt(value);
    }

    addProtocol(key, protocol) {
        this.protocols.set(String(key), protocol);
        this.refreshSummary();
    }

    hasProtocol(key) {
        return this.protocols.has(String(key));
    }

    getProtocol(key) {
        const proto = this.protocols.get(String(key));
        if (!proto) {
            throw new Error(`Unknown protocol: ${key}`);
        }
        return proto;
    }

    tryGetProtocol(key) {
        return this.protocols.get(String(key)) || null;
    }

    addNote(note) {
        this.notes.push(String(note));
    }

    addReadSource(filePath, status = "ok") {
        this.read_sources.push({
            path: filePath,
            status
        });
    }

    setTcpExt(values) {
        const out = {};
        for (const [k, v] of Object.entries(values || {})) {
            out[k] = ProtocolStats.toInt(v);
        }
        this.tcp_ext = out;
    }

    refreshSummary() {
        let protocolCount = 0;
        let populatedProtocolCount = 0;
        let totalProtocolFields = 0;
        let totalMemoryUnits = 0;
        let totalInUse = 0;

        for (const protocol of this.protocols.values()) {
            protocolCount += 1;
            const fields = protocol.toJSON();
            const keys = Object.keys(fields);
            totalProtocolFields += keys.length;
            if (!protocol.isEmpty()) {
                populatedProtocolCount += 1;
            }
            if (Object.prototype.hasOwnProperty.call(fields, "memory")) {
                totalMemoryUnits += fields.memory;
            }
            if (Object.prototype.hasOwnProperty.call(fields, "in_use")) {
                totalInUse += fields.in_use;
            }
        }

        this.summary = {
            protocol_count: protocolCount,
            populated_protocol_count: populatedProtocolCount,
            total_protocol_fields: totalProtocolFields,
            total_memory_units: totalMemoryUnits,
            total_in_use: totalInUse
        };
    }

    toJSONObject(includeZeros = false) {
        this.refreshSummary();
        const out = {
            metadata: this.metadata.toJSON(),
            sockets_used: this.sockets_used,
            summary: { ...this.summary },
            read_sources: [...this.read_sources]
        };

        for (const [key, proto] of this.protocols.entries()) {
            if (!includeZeros && proto.isEmpty()) {
                continue;
            }
            out[key] = proto.toJSON();
        }

        if (Object.keys(this.tcp_ext).length > 0) {
            out.tcp_ext = { ...this.tcp_ext };
        }

        if (this.notes.length > 0) {
            out.notes = [...this.notes];
        }

        return out;
    }
}

class TerminalFormatter {
    constructor(config) {
        this.config = config;
    }

    supportsColor() {
        if (this.config.color === "always") {
            return true;
        }
        if (this.config.color === "never") {
            return false;
        }
        return Boolean(process.stdout.isTTY && process.env.TERM && process.env.TERM !== "dumb");
    }

    colors() {
        const enabled = this.supportsColor();
        if (!enabled) {
            return {
                title: "",
                section: "",
                key: "",
                accent: "",
                reset: ""
            };
        }
        return {
            title: "\x1b[1;36m",
            section: "\x1b[1;35m",
            key: "\x1b[1;34m",
            accent: "\x1b[1;33m",
            reset: "\x1b[0m"
        };
    }

    formatProtocolName(key) {
        const mapping = {
            tcp: "TCP",
            udp: "UDP",
            udp_lite: "UDPLite",
            raw: "RAW",
            frag: "FRAG",
            tcp6: "TCP6",
            udp6: "UDP6",
            unix: "UNIX",
            icmp: "ICMP",
            icmp6: "ICMP6",
            netlink: "Netlink",
            packet: "Packet"
        };
        return mapping[key] || String(key).toUpperCase();
    }

    outputHumanReadable(report, metrics = null) {
        const c = this.colors();
        const lines = [];
        const data = report.toJSONObject(this.config.includeZeros);

        lines.push(`${c.title}Socket Statistics${c.reset}`);
        lines.push(`${c.title}=================${c.reset}`);
        lines.push(`${c.accent}Generated:${c.reset} ${data.metadata.generated_at}`);
        lines.push(`${c.accent}Hostname:${c.reset}  ${data.metadata.hostname}`);
        lines.push(`${c.accent}Source:${c.reset}    ${data.metadata.source}`);
        lines.push(`${c.accent}PID:${c.reset}       ${data.metadata.pid}`);
        lines.push(`${c.accent}Platform:${c.reset}  ${data.metadata.platform}`);
        lines.push(`${c.accent}Node:${c.reset}      ${data.metadata.node_version}`);
        lines.push("");
        lines.push(`${c.accent}Sockets used:${c.reset} ${data.sockets_used}`);
        lines.push(`${c.accent}Protocols:${c.reset}    ${data.summary.protocol_count}`);
        lines.push(`${c.accent}Populated:${c.reset}    ${data.summary.populated_protocol_count}`);
        lines.push(`${c.accent}Total in use:${c.reset} ${data.summary.total_in_use}`);
        lines.push(`${c.accent}Memory units:${c.reset} ${data.summary.total_memory_units}`);
        lines.push("");

        const baseProtocols = ["tcp", "udp", "udp_lite", "raw", "frag"];
        for (const key of baseProtocols) {
            const proto = report.tryGetProtocol(key);
            if (!proto) {
                continue;
            }
            if (!this.config.includeZeros && proto.isEmpty()) {
                continue;
            }
            lines.push(`${c.section}${this.formatProtocolName(key)}:${c.reset}`);
            for (const [field, value] of Object.entries(proto.toJSON())) {
                const name = field.replace(/_/g, " ").replace(/\b\w/g, ch => ch.toUpperCase());
                lines.push(`  ${c.key}${name}:${c.reset} ${value}`);
            }
            lines.push("");
        }

        if (this.config.extended) {
            lines.push(`${c.title}Extended Protocol Information${c.reset}`);
            lines.push(`${c.title}=============================${c.reset}`);
            const extendedProtocols = ["tcp6", "udp6", "unix", "netlink", "packet", "icmp", "icmp6"];
            for (const key of extendedProtocols) {
                const proto = report.tryGetProtocol(key);
                if (!proto) {
                    continue;
                }
                if (!this.config.includeZeros && !proto.hasPositiveInUse() && proto.isEmpty()) {
                    continue;
                }
                if (!this.config.includeZeros && !proto.hasPositiveInUse() && !proto.isEmpty()) {
                    continue;
                }
                lines.push(`${c.section}${this.formatProtocolName(key)}:${c.reset}`);
                for (const [field, value] of Object.entries(proto.toJSON())) {
                    const name = field.replace(/_/g, " ").replace(/\b\w/g, ch => ch.toUpperCase());
                    lines.push(`  ${c.key}${name}:${c.reset} ${value}`);
                }
                lines.push("");
            }
            if (Object.keys(report.tcp_ext).length > 0) {
                lines.push(`${c.section}TcpExt:${c.reset}`);
                const keys = Object.keys(report.tcp_ext).sort();
                for (const key of keys) {
                    lines.push(`  ${c.key}${key}:${c.reset} ${report.tcp_ext[key]}`);
                }
                lines.push("");
            }
        }

        if (data.read_sources.length > 0) {
            lines.push(`${c.title}Read Sources${c.reset}`);
            lines.push(`${c.title}===========${c.reset}`);
            for (const item of data.read_sources) {
                lines.push(`  ${c.key}${item.status}:${c.reset} ${item.path}`);
            }
            lines.push("");
        }

        if (data.notes && data.notes.length > 0) {
            lines.push(`${c.title}Notes${c.reset}`);
            lines.push(`${c.title}=====${c.reset}`);
            for (const note of data.notes) {
                lines.push(`  - ${note}`);
            }
            lines.push("");
        }

        if (metrics) {
            lines.push(`${c.title}Performance Metrics${c.reset}`);
            lines.push(`${c.title}===================${c.reset}`);
            lines.push(`  ${c.key}Execution time:${c.reset} ${metrics.execution_time_seconds.toFixed(6)}s`);
            lines.push(`  ${c.key}RSS:${c.reset}            ${metrics.rss_mb.toFixed(2)} MB`);
            lines.push(`  ${c.key}Heap total:${c.reset}     ${metrics.heap_total_mb.toFixed(2)} MB`);
            lines.push(`  ${c.key}Heap used:${c.reset}      ${metrics.heap_used_mb.toFixed(2)} MB`);
            lines.push(`  ${c.key}External:${c.reset}       ${metrics.external_mb.toFixed(2)} MB`);
            lines.push(`  ${c.key}Array buffers:${c.reset}  ${metrics.array_buffers_mb.toFixed(2)} MB`);
            lines.push(`  ${c.key}Start heap used:${c.reset} ${metrics.start_heap_used_mb.toFixed(2)} MB`);
            lines.push("");
        }

        return lines.join("\n").replace(/\n+$/, "") + "\n";
    }
}

class SafeFileReader {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
    }

    normalizePath(inputPath) {
        if (typeof inputPath !== "string") {
            throw new Error("Path must be a string");
        }
        let result = inputPath.replace(/\0/g, "").trim();
        if (result.length === 0) {
            throw new Error("Path must not be empty");
        }
        result = result.replace(/\\/g, "/");
        return result;
    }

    resolvePath(filePath) {
        const normalized = this.normalizePath(filePath);
        return fs.realpathSync(normalized);
    }

    isPathAllowed(resolvedPath) {
        for (const root of this.config.allowedRoots) {
            const resolvedRoot = fs.existsSync(root) ? fs.realpathSync(root) : root;
            if (resolvedPath === resolvedRoot || resolvedPath.startsWith(`${resolvedRoot}${path.sep}`)) {
                return true;
            }
        }
        return false;
    }

    statChecked(filePath) {
        const resolved = this.resolvePath(filePath);
        if (!this.isPathAllowed(resolved)) {
            throw new Error(`Path not allowed: ${filePath}`);
        }
        const stat = fs.lstatSync(resolved);
        if (!stat.isFile()) {
            throw new Error(`Not a regular file: ${filePath}`);
        }
        if (stat.size > this.config.maxFileSize) {
            throw new Error(`File size exceeds limit: ${filePath}`);
        }
        return {
            resolved,
            stat
        };
    }

    readLines(filePath) {
        const { resolved } = this.statChecked(filePath);
        const content = fs.readFileSync(resolved, "utf8");
        const lines = content.split(/\r?\n/);
        if (lines.length > this.config.maxLineCount) {
            throw new Error(`File appears too large or malformed: ${filePath}`);
        }
        for (const line of lines) {
            if (line.length > this.config.maxLineSize) {
                throw new Error(`Line too long in file: ${filePath}`);
            }
        }
        return {
            resolved,
            lines
        };
    }
}

class IniLoader {
    static parseValue(raw) {
        const value = String(raw).trim();
        if (/^(true|yes|on)$/i.test(value)) {
            return true;
        }
        if (/^(false|no|off)$/i.test(value)) {
            return false;
        }
        if (/^-?\d+$/.test(value)) {
            return Number.parseInt(value, 10);
        }
        if (value.includes(",")) {
            return value.split(",").map(v => v.trim()).filter(Boolean);
        }
        return value;
    }

    static parse(text) {
        const result = {};
        const lines = String(text).split(/\r?\n/);
        for (const rawLine of lines) {
            const line = rawLine.trim();
            if (!line || line.startsWith(";") || line.startsWith("#")) {
                continue;
            }
            if (line.startsWith("[") && line.endsWith("]")) {
                continue;
            }
            const idx = line.indexOf("=");
            if (idx === -1) {
                continue;
            }
            const key = line.slice(0, idx).trim();
            const value = line.slice(idx + 1).trim();
            if (!key) {
                continue;
            }
            result[key] = IniLoader.parseValue(value);
        }
        return result;
    }
}

class SocketStatsTool {
    constructor() {
        this.config = new ToolConfig();
        this.logger = new Logger(this.config.logLevel, this.config.quiet);
        this.metrics = new PerformanceMetrics(process.hrtime.bigint(), process.memoryUsage());
        this.shutdownRequested = false;
        this.fileReader = new SafeFileReader(this.config, this.logger);
        this.protocolParserCache = null;
        this.boundSignalHandler = this.handleSignal.bind(this);
    }

    handleSignal(signalName) {
        this.shutdownRequested = true;
        this.logger.warning(`Shutdown requested by signal ${signalName}`);
    }

    installSignalHandlers() {
        const signals = ["SIGINT", "SIGTERM", "SIGHUP"];
        for (const sig of signals) {
            try {
                process.on(sig, this.boundSignalHandler);
            } catch (err) {
                this.logger.debug(`Could not install signal handler for ${sig}: ${err.message}`);
            }
        }
    }

    parseArgs(argv = process.argv.slice(2)) {
        const updates = {};
        for (let i = 0; i < argv.length; i += 1) {
            const arg = argv[i];
            if (arg === "--json") {
                updates.jsonOutput = true;
                continue;
            }
            if (arg === "--compact-json") {
                updates.jsonOutput = true;
                updates.compactJson = true;
                continue;
            }
            if (arg === "--help") {
                updates.help = true;
                continue;
            }
            if (arg === "--performance") {
                updates.showPerformance = true;
                continue;
            }
            if (arg === "--quiet") {
                updates.quiet = true;
                continue;
            }
            if (arg === "--extended") {
                updates.extended = true;
                continue;
            }
            if (arg === "--include-zeros") {
                updates.includeZeros = true;
                continue;
            }
            if (arg === "--version") {
                this.showVersion();
                process.exit(0);
            }
            if (arg === "--log-level") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --log-level");
                }
                updates.logLevel = String(argv[i]).toUpperCase();
                continue;
            }
            if (arg === "--path") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --path");
                }
                updates.sockstatPath = String(argv[i]);
                continue;
            }
            if (arg === "--config") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --config");
                }
                updates.configFile = String(argv[i]);
                continue;
            }
            if (arg === "--output") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --output");
                }
                updates.outputFile = String(argv[i]);
                continue;
            }
            if (arg === "--color") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --color");
                }
                updates.color = String(argv[i]).toLowerCase();
                continue;
            }
            if (arg === "--max-file-size") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --max-file-size");
                }
                updates.maxFileSize = Number.parseInt(String(argv[i]), 10);
                continue;
            }
            if (arg === "--max-line-count") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --max-line-count");
                }
                updates.maxLineCount = Number.parseInt(String(argv[i]), 10);
                continue;
            }
            if (arg === "--max-line-size") {
                i += 1;
                if (i >= argv.length) {
                    throw new Error("Missing value for --max-line-size");
                }
                updates.maxLineSize = Number.parseInt(String(argv[i]), 10);
                continue;
            }
            throw new Error(`Unknown argument: ${arg}`);
        }
        this.config.apply(updates);
        this.refreshRuntimeHelpers();
    }

    refreshRuntimeHelpers() {
        this.logger.setLevel(this.config.logLevel);
        this.logger.setQuiet(this.config.quiet);
        this.fileReader = new SafeFileReader(this.config, this.logger);
        this.protocolParserCache = null;
    }

    loadConfigFile() {
        if (!this.config.configFile) {
            return;
        }
        const { resolved, lines } = this.fileReader.readLines(this.config.configFile);
        const data = IniLoader.parse(lines.join("\n"));
        const mapped = {};
        for (const [k, v] of Object.entries(data)) {
            switch (k) {
                case "log_level":
                    mapped.logLevel = String(v).toUpperCase();
                    break;
                case "json_output":
                    mapped.jsonOutput = Boolean(v);
                    break;
                case "compact_json":
                    mapped.compactJson = Boolean(v);
                    break;
                case "help":
                    mapped.help = Boolean(v);
                    break;
                case "show_performance":
                    mapped.showPerformance = Boolean(v);
                    break;
                case "quiet":
                    mapped.quiet = Boolean(v);
                    break;
                case "extended":
                    mapped.extended = Boolean(v);
                    break;
                case "include_zeros":
                    mapped.includeZeros = Boolean(v);
                    break;
                case "sockstat_path":
                    mapped.sockstatPath = String(v);
                    break;
                case "sockstat6_path":
                    mapped.sockstat6Path = String(v);
                    break;
                case "netlink_path":
                    mapped.netlinkPath = String(v);
                    break;
                case "packet_path":
                    mapped.packetPath = String(v);
                    break;
                case "snmp_path":
                    mapped.snmpPath = String(v);
                    break;
                case "netstat_path":
                    mapped.netstatPath = String(v);
                    break;
                case "output_file":
                    mapped.outputFile = String(v);
                    break;
                case "color":
                    mapped.color = String(v).toLowerCase();
                    break;
                case "max_file_size":
                    mapped.maxFileSize = ProtocolStats.toInt(v);
                    break;
                case "max_line_count":
                    mapped.maxLineCount = ProtocolStats.toInt(v);
                    break;
                case "max_line_size":
                    mapped.maxLineSize = ProtocolStats.toInt(v);
                    break;
                case "allowed_roots":
                    mapped.allowedRoots = Array.isArray(v) ? v.map(String) : [String(v)];
                    break;
                default:
                    break;
            }
        }
        this.config.apply(mapped);
        this.refreshRuntimeHelpers();
        this.logger.debug(`Loaded configuration from ${resolved}`);
    }

    validateConfig() {
        const validLogLevels = ["DEBUG", "INFO", "WARNING", "ERROR"];
        if (!validLogLevels.includes(String(this.config.logLevel).toUpperCase())) {
            throw new Error(`Invalid log level: ${this.config.logLevel}`);
        }
        if (!["auto", "always", "never"].includes(this.config.color)) {
            throw new Error(`Invalid color mode: ${this.config.color}`);
        }
        if (!Number.isInteger(this.config.maxFileSize) || this.config.maxFileSize < 1) {
            throw new Error("Invalid max file size");
        }
        if (!Number.isInteger(this.config.maxLineCount) || this.config.maxLineCount < 1) {
            throw new Error("Invalid max line count");
        }
        if (!Number.isInteger(this.config.maxLineSize) || this.config.maxLineSize < 1) {
            throw new Error("Invalid max line size");
        }
        const pathFields = [
            "sockstatPath",
            "sockstat6Path",
            "netlinkPath",
            "packetPath",
            "snmpPath",
            "netstatPath"
        ];
        for (const field of pathFields) {
            const value = this.config[field];
            if (typeof value !== "string" || value.includes("\0") || value.trim() === "") {
                throw new Error(`Invalid path in config field: ${field}`);
            }
            if (!/^[a-zA-Z0-9/_\-.]+$/.test(value)) {
                throw new Error(`Invalid path format in config field: ${field}`);
            }
        }
    }

    createEmptyReport() {
        const report = new SocketStatsReport(Metadata.create(this.config.sockstatPath));

        report.addProtocol("tcp", new ProtocolStats("TCP", {
            in_use: 0,
            orphan: 0,
            time_wait: 0,
            allocated: 0,
            memory: 0
        }));
        report.addProtocol("udp", new ProtocolStats("UDP", {
            in_use: 0,
            memory: 0
        }));
        report.addProtocol("udp_lite", new ProtocolStats("UDPLite", {
            in_use: 0
        }));
        report.addProtocol("raw", new ProtocolStats("RAW", {
            in_use: 0
        }));
        report.addProtocol("frag", new ProtocolStats("FRAG", {
            in_use: 0,
            memory: 0
        }));

        if (this.config.extended) {
            report.addProtocol("tcp6", new ProtocolStats("TCP6", {
                in_use: 0,
                orphan: 0,
                time_wait: 0,
                allocated: 0,
                memory: 0
            }));
            report.addProtocol("udp6", new ProtocolStats("UDP6", {
                in_use: 0,
                memory: 0
            }));
            report.addProtocol("unix", new ProtocolStats("UNIX", {
                in_use: 0,
                dynamic: 0,
                inode: 0
            }));
            report.addProtocol("icmp", new ProtocolStats("ICMP", {
                in_use: 0
            }));
            report.addProtocol("icmp6", new ProtocolStats("ICMP6", {
                in_use: 0
            }));
            report.addProtocol("netlink", new ProtocolStats("Netlink", {
                in_use: 0
            }));
            report.addProtocol("packet", new ProtocolStats("Packet", {
                in_use: 0,
                memory: 0
            }));
        }

        return report;
    }

    getProtocolParsers() {
        if (this.protocolParserCache) {
            return this.protocolParserCache;
        }
        this.protocolParserCache = {
            "sockets:": (parts, report) => {
                if (parts.length >= 3) {
                    report.setSocketsUsed(this.parseInt(parts[2]));
                }
            },
            "TCP:": (parts, report) => {
                this.parseProtocolSection(parts, report, "tcp", {
                    inuse: "in_use",
                    orphan: "orphan",
                    tw: "time_wait",
                    alloc: "allocated",
                    mem: "memory"
                });
            },
            "UDP:": (parts, report) => {
                this.parseProtocolSection(parts, report, "udp", {
                    inuse: "in_use",
                    mem: "memory"
                });
            },
            "UDPLITE:": (parts, report) => {
                this.parseProtocolSection(parts, report, "udp_lite", {
                    inuse: "in_use"
                });
            },
            "RAW:": (parts, report) => {
                this.parseProtocolSection(parts, report, "raw", {
                    inuse: "in_use"
                });
            },
            "FRAG:": (parts, report) => {
                this.parseProtocolSection(parts, report, "frag", {
                    inuse: "in_use",
                    memory: "memory"
                });
            },
            "TCP6:": (parts, report) => {
                if (this.config.extended && report.hasProtocol("tcp6")) {
                    this.parseProtocolSection(parts, report, "tcp6", {
                        inuse: "in_use",
                        orphan: "orphan",
                        tw: "time_wait",
                        alloc: "allocated",
                        mem: "memory"
                    });
                }
            },
            "UDP6:": (parts, report) => {
                if (this.config.extended && report.hasProtocol("udp6")) {
                    this.parseProtocolSection(parts, report, "udp6", {
                        inuse: "in_use",
                        mem: "memory"
                    });
                }
            }
        };
        return this.protocolParserCache;
    }

    parseInt(value) {
        const parsed = Number.parseInt(String(value), 10);
        if (!Number.isInteger(parsed)) {
            throw new Error(`Failed to parse integer: ${value}`);
        }
        return parsed;
    }

    parseProtocolSection(parts, report, key, mapping) {
        let protocol = report.tryGetProtocol(key);
        if (!protocol) {
            protocol = new ProtocolStats(key);
            report.addProtocol(key, protocol);
        }
        for (let i = 1; i < parts.length; i += 2) {
            if (i + 1 >= parts.length) {
                break;
            }
            const field = parts[i];
            const value = parts[i + 1];
            if (Object.prototype.hasOwnProperty.call(mapping, field)) {
                protocol.set(mapping[field], this.parseInt(value));
            } else {
                this.logger.debug(`Unknown ${key} field: ${field}`);
            }
        }
    }

    parseLine(line, report) {
        if (line.length > this.config.maxLineSize) {
            this.logger.warning("Line too long, skipping");
            return;
        }
        const parts = String(line).trim().split(/\s+/).filter(Boolean);
        if (parts.length < 2) {
            this.logger.debug(`Skipping malformed line: ${line}`);
            return;
        }
        const section = parts[0];
        const parsers = this.getProtocolParsers();
        const fn = parsers[section];
        if (fn) {
            fn(parts, report);
        } else {
            this.logger.debug(`Unknown section: ${section}`);
        }
    }

    readSockstat(report) {
        const { resolved, lines } = this.fileReader.readLines(this.config.sockstatPath);
        report.addReadSource(resolved, "ok");
        let count = 0;
        for (const raw of lines) {
            if (this.shutdownRequested) {
                report.addNote("Parsing interrupted by shutdown request");
                break;
            }
            const line = raw.trim();
            if (!line) {
                continue;
            }
            this.parseLine(line, report);
            count += 1;
            if (count > this.config.maxLineCount) {
                throw new Error("Sockstat file appears too large or malformed");
            }
        }
        this.logger.debug(`Processed ${count} lines from ${resolved}`);
    }

    loadProtocolSectionFromFile(filePath, section, report, protocolKey, mapping) {
        try {
            const { resolved, lines } = this.fileReader.readLines(filePath);
            report.addReadSource(resolved, "ok");
            for (const raw of lines) {
                if (this.shutdownRequested) {
                    break;
                }
                const line = raw.trim();
                if (!line) {
                    continue;
                }
                if (line.startsWith(section)) {
                    const parts = line.split(/\s+/);
                    this.parseProtocolSection(parts, report, protocolKey, mapping);
                    return;
                }
            }
            report.addNote(`Section ${section} not found in ${resolved}`);
        } catch (err) {
            report.addReadSource(filePath, "unavailable");
            this.logger.debug(`Could not load protocol section ${section} from ${filePath}: ${err.message}`);
        }
    }

    countFileEntries(filePath, skipHeader = true) {
        const { resolved, lines } = this.fileReader.readLines(filePath);
        let count = 0;
        let first = true;
        for (const raw of lines) {
            if (this.shutdownRequested) {
                break;
            }
            if (first && skipHeader) {
                first = false;
                continue;
            }
            if (raw.trim()) {
                count += 1;
            }
        }
        return { resolved, count };
    }

    loadSnmpMetric(filePath, targetSection) {
        const { resolved, lines } = this.fileReader.readLines(filePath);
        for (let i = 0; i < lines.length - 1; i += 1) {
            if (this.shutdownRequested) {
                break;
            }
            const head = lines[i].trim();
            const data = lines[i + 1].trim();
            if (!head.startsWith(targetSection) || !data.startsWith(targetSection)) {
                continue;
            }
            const headParts = head.split(/\s+/);
            const dataParts = data.split(/\s+/);
            const mapping = {};
            for (let j = 1; j < headParts.length && j < dataParts.length; j += 1) {
                mapping[headParts[j]] = this.parseInt(dataParts[j]);
            }
            return { resolved, mapping };
        }
        return { resolved, mapping: {} };
    }

    parseTcpExtPairs(line) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 3 || parts[0] !== "TcpExt:") {
            return {};
        }
        const out = {};
        for (let i = 1; i < parts.length; i += 2) {
            if (i + 1 >= parts.length) {
                break;
            }
            out[parts[i]] = this.parseInt(parts[i + 1]);
        }
        return out;
    }

    loadNetstat(report) {
        try {
            const { resolved, lines } = this.fileReader.readLines(this.config.netstatPath);
            report.addReadSource(resolved, "ok");
            for (let i = 0; i < lines.length - 1; i += 1) {
                if (this.shutdownRequested) {
                    break;
                }
                const head = lines[i].trim();
                const data = lines[i + 1].trim();
                if (!head.startsWith("TcpExt:") || !data.startsWith("TcpExt:")) {
                    continue;
                }
                const headParts = head.split(/\s+/);
                const dataParts = data.split(/\s+/);
                const values = {};
                for (let j = 1; j < headParts.length && j < dataParts.length; j += 1) {
                    values[headParts[j]] = this.parseInt(dataParts[j]);
                }
                report.setTcpExt(values);
                return;
            }
            for (const line of lines) {
                if (line.startsWith("TcpExt:")) {
                    const parsed = this.parseTcpExtPairs(line);
                    if (Object.keys(parsed).length > 0) {
                        report.setTcpExt(parsed);
                        return;
                    }
                }
            }
        } catch (err) {
            report.addReadSource(this.config.netstatPath, "unavailable");
            this.logger.debug(`Could not read netstat data: ${err.message}`);
        }
    }

    loadExtendedProtocolInfo(report) {
        if (!this.config.extended) {
            return;
        }

        this.loadProtocolSectionFromFile(
            this.config.sockstat6Path,
            "TCP6:",
            report,
            "tcp6",
            {
                inuse: "in_use",
                orphan: "orphan",
                tw: "time_wait",
                alloc: "allocated",
                mem: "memory"
            }
        );

        this.loadProtocolSectionFromFile(
            this.config.sockstat6Path,
            "UDP6:",
            report,
            "udp6",
            {
                inuse: "in_use",
                mem: "memory"
            }
        );

        this.loadProtocolSectionFromFile(
            this.config.sockstat6Path,
            "UNIX:",
            report,
            "unix",
            {
                inuse: "in_use",
                dynamic: "dynamic",
                inode: "inode"
            }
        );

        try {
            const { resolved, count } = this.countFileEntries(this.config.netlinkPath, true);
            report.addReadSource(resolved, "ok");
            const proto = report.tryGetProtocol("netlink");
            if (proto) {
                proto.set("in_use", count);
            }
        } catch (err) {
            report.addReadSource(this.config.netlinkPath, "unavailable");
            this.logger.debug(`Could not load netlink info: ${err.message}`);
        }

        try {
            const { resolved, count } = this.countFileEntries(this.config.packetPath, true);
            report.addReadSource(resolved, "ok");
            const proto = report.tryGetProtocol("packet");
            if (proto) {
                proto.set("in_use", count);
            }
        } catch (err) {
            report.addReadSource(this.config.packetPath, "unavailable");
            this.logger.debug(`Could not load packet info: ${err.message}`);
        }

        try {
            const { resolved, mapping } = this.loadSnmpMetric(this.config.snmpPath, "Icmp:");
            report.addReadSource(resolved, "ok");
            const proto = report.tryGetProtocol("icmp");
            if (proto) {
                let total = 0;
                for (const value of Object.values(mapping)) {
                    total += value;
                }
                proto.set("in_use", total);
            }
        } catch (err) {
            report.addReadSource(this.config.snmpPath, "unavailable");
            this.logger.debug(`Could not load ICMP info: ${err.message}`);
        }

        try {
            const { resolved, mapping } = this.loadSnmpMetric(this.config.snmpPath, "Icmp6:");
            report.addReadSource(resolved, "ok");
            const proto = report.tryGetProtocol("icmp6");
            if (proto) {
                let total = 0;
                for (const value of Object.values(mapping)) {
                    total += value;
                }
                proto.set("in_use", total);
            }
        } catch (err) {
            report.addReadSource(this.config.snmpPath, "unavailable");
            this.logger.debug(`Could not load ICMP6 info: ${err.message}`);
        }

        this.loadNetstat(report);
    }

    displayStats(report) {
        const metrics = this.config.showPerformance ? this.metrics.toJSON() : null;
        let output;
        if (this.config.jsonOutput) {
            const payload = report.toJSONObject(this.config.includeZeros);
            if (metrics) {
                payload.performance = metrics;
            }
            output = this.config.compactJson
                ? JSON.stringify(payload)
                : JSON.stringify(payload, null, 2);
            output += "\n";
        } else {
            output = new TerminalFormatter(this.config).outputHumanReadable(report, metrics);
        }

        if (this.config.outputFile) {
            fs.writeFileSync(this.config.outputFile, output, "utf8");
            if (!this.config.quiet) {
                process.stdout.write(`Wrote output to ${this.config.outputFile}\n`);
            }
            return;
        }

        if (!this.config.quiet) {
            process.stdout.write(output);
        }
    }

    showVersion() {
        process.stdout.write("Socket Statistics Tool JS 2.0.0\n");
        process.stdout.write(`Node ${process.version}\n`);
    }

    showHelp() {
        const scriptName = path.basename(process.argv[1] || "main.js");
        const text = [
            "Socket Statistics Tool JS 2.0.0",
            "",
            `Usage: ${scriptName} [OPTIONS]`,
            "",
            "Options:",
            "  --json                  Output report as pretty JSON",
            "  --compact-json          Output report as compact JSON",
            "  --log-level LEVEL       Set log level (DEBUG, INFO, WARNING, ERROR)",
            "  --path PATH             Path to sockstat file",
            "  --config FILE           Load configuration from ini-style file",
            "  --output FILE           Write output to file",
            "  --performance           Include performance metrics",
            "  --quiet                 Suppress normal stdout output",
            "  --extended              Read additional protocol information",
            "  --include-zeros         Include empty protocols in output",
            "  --color MODE            auto, always, never",
            "  --max-file-size BYTES   Maximum readable file size",
            "  --max-line-count N      Maximum allowed line count",
            "  --max-line-size BYTES   Maximum allowed line length",
            "  --version               Show version",
            "  --help                  Show this help",
            "",
            "Examples:",
            `  ${scriptName} --json`,
            `  ${scriptName} --extended --performance`,
            `  ${scriptName} --path /tmp/test-sockstat --json`,
            `  ${scriptName} --config /etc/socket-stats/config.ini --compact-json`,
            ""
        ].join("\n");
        process.stdout.write(text);
    }

    run() {
        this.installSignalHandlers();
        try {
            this.parseArgs();
            if (this.config.help) {
                this.showHelp();
                return;
            }
            this.loadConfigFile();
            this.validateConfig();
            const report = this.createEmptyReport();
            this.logger.info(`Reading socket statistics from ${this.config.sockstatPath}`);
            this.readSockstat(report);
            this.loadExtendedProtocolInfo(report);
            report.refreshSummary();
            this.metrics.stop();
            this.displayStats(report);
        } catch (err) {
            this.metrics.stop();
            this.logger.error(err && err.message ? err.message : String(err));
            process.exitCode = 1;
        }
    }
}

if (require.main === module) {
    new SocketStatsTool().run();
}
