#!/usr/bin/env node

"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const process = require("process");

const VERSION = "4.0.0";

class ToolConfig {
    constructor(options = {}) {
        this.logLevel = "INFO";
        this.jsonOutput = false;
        this.compactJson = false;
        this.help = false;
        this.version = false;
        this.showPerformance = false;
        this.quiet = false;
        this.extended = false;
        this.color = "auto";
        this.sockstatPath = "/proc/net/sockstat";
        this.sockstat6Path = "/proc/net/sockstat6";
        this.netlinkPath = "/proc/net/netlink";
        this.packetPath = "/proc/net/packet";
        this.snmpPath = "/proc/net/snmp";
        this.snmp6Path = "/proc/net/snmp6";
        this.netstatPath = "/proc/net/netstat";
        this.unixPath = "/proc/net/unix";
        this.outputFile = null;
        this.configFile = null;
        this.allowedRoots = ["/proc", "/tmp/socket-stats"];
        this.maxFileSize = 10 * 1024 * 1024;
        this.maxLineCount = 10000;
        this.maxLineSize = 1024 * 1024;
        this.includeZeros = false;
        this.tcpStates = false;
        this.processes = false;
        this.processLimit = 25;
        this.watch = false;
        this.interval = 2;
        this.count = 0;
        this.csvOutput = false;
        this.thresholdTcp = null;
        this.thresholdEstablished = null;
        this.thresholdTimewait = null;
        this.thresholdOrphan = null;
        this.thresholdRetrans = null;
        this.apply(options);
    }

    apply(options) {
        for (const [key, value] of Object.entries(options || {})) {
            if (Object.prototype.hasOwnProperty.call(this, key)) {
                this[key] = value;
            }
        }
    }

    clone() {
        return new ToolConfig(this.toObject());
    }

    toObject() {
        return JSON.parse(JSON.stringify(this));
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
        this.quiet = Boolean(quiet);
        this.dedup = new Map();
        this.dedupTtlMs = 300000;
        this.dedupMaxSize = 1000;
    }

    normalizeLevel(level) {
        const upper = String(level || "INFO").toUpperCase();
        return Object.prototype.hasOwnProperty.call(this.levels, upper)
            ? upper
            : "INFO";
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

        const entries = Array.from(this.dedup.entries()).sort(
            (a, b) => a[1] - b[1]
        );

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

        for (const [key, value] of Object.entries(defaults)) {
            this.fields[key] = ProtocolStats.toInt(value);
        }
    }

    static toInt(value) {
        if (typeof value === "number" && Number.isInteger(value)) {
            return value;
        }

        const raw = String(value);
        if (!/^-?\d+$/.test(raw)) {
            throw new Error(`Invalid integer value: ${value}`);
        }
        const parsed = Number(raw);

        if (!Number.isSafeInteger(parsed)) {
            throw new Error(`Failed to parse integer value: ${value}`);
        }

        return parsed;
    }

    set(field, value) {
        this.fields[field] = ProtocolStats.toInt(value);
    }

    get(field, fallback = 0) {
        return Object.prototype.hasOwnProperty.call(this.fields, field)
            ? this.fields[field]
            : fallback;
    }

    add(field, value) {
        this.fields[field] =
            this.get(field, 0) + ProtocolStats.toInt(value);
    }

    hasPositiveInUse() {
        return this.get("in_use", 0) > 0;
    }

    isEmpty() {
        return Object.values(this.fields).every(value => value === 0);
    }

    toJSON() {
        return { ...this.fields };
    }
}

class Metadata {
    constructor({
        source,
        hostname,
        generatedAt,
        pid,
        platform,
        nodeVersion
    }) {
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
        const endHr =
            this.finishHrtime ?? process.hrtime.bigint();

        const endMem =
            this.finishMemory ?? process.memoryUsage();

        const durationNs = endHr - this.startHrtime;

        return {
            execution_time_seconds: Number(durationNs) / 1e9,
            rss_mb: endMem.rss / 1024 / 1024,
            heap_total_mb: endMem.heapTotal / 1024 / 1024,
            heap_used_mb: endMem.heapUsed / 1024 / 1024,
            external_mb: endMem.external / 1024 / 1024,
            array_buffers_mb:
                endMem.arrayBuffers / 1024 / 1024,
            start_heap_used_mb:
                this.startMemory.heapUsed / 1024 / 1024
        };
    }
}

class SocketStatsReport {
    constructor(metadata) {
        this.metadata = metadata;
        this.sockets_used = 0;
        this.protocols = new Map();
        this.tcp_ext = {};
        this.tcp_states = {};
        this.auxiliary = {};
        this.processes = [];
        this.counters = {};
        this.sampling = null;
        this.alerts = [];
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
        const normalizedPath = String(filePath);
        const normalizedStatus = String(status);

        const exists = this.read_sources.some(
            item =>
                item.path === normalizedPath &&
                item.status === normalizedStatus
        );

        if (!exists) {
            this.read_sources.push({
                path: normalizedPath,
                status: normalizedStatus
            });
        }
    }

    setTcpExt(values) {
        const out = {};

        for (const [key, value] of Object.entries(values || {})) {
            out[key] = ProtocolStats.toInt(value);
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

            if (
                Object.prototype.hasOwnProperty.call(
                    fields,
                    "memory"
                )
            ) {
                totalMemoryUnits += fields.memory;
            }

            if (
                Object.prototype.hasOwnProperty.call(
                    fields,
                    "in_use"
                )
            ) {
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
            read_sources: [...this.read_sources],
            tcp_states: {...this.tcp_states},
            auxiliary: {...this.auxiliary},
            processes: [...this.processes],
            counters: {...this.counters},
            sampling: this.sampling,
            alerts: [...this.alerts]
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

        return Boolean(
            process.stdout.isTTY &&
            process.env.TERM &&
            process.env.TERM !== "dumb"
        );
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

    shouldRenderProtocol(proto) {
        if (this.config.includeZeros) {
            return true;
        }

        return !proto.isEmpty();
    }

    renderProtocolSection(lines, colorSet, report, key) {
        const proto = report.tryGetProtocol(key);

        if (!proto || !this.shouldRenderProtocol(proto)) {
            return;
        }

        lines.push(
            `${colorSet.section}${this.formatProtocolName(key)}:${colorSet.reset}`
        );

        for (const [field, value] of Object.entries(proto.toJSON())) {
            const name = field
                .replace(/_/g, " ")
                .replace(/\b\w/g, ch => ch.toUpperCase());

            lines.push(
                `  ${colorSet.key}${name}:${colorSet.reset} ${value}`
            );
        }

        lines.push("");
    }

    outputHumanReadable(report, metrics = null) {
        const c = this.colors();
        const lines = [];
        const data = report.toJSONObject(
            this.config.includeZeros
        );

        lines.push(
            `${c.title}Socket Statistics${c.reset}`
        );
        lines.push(
            `${c.title}=================${c.reset}`
        );
        lines.push(
            `${c.accent}Generated:${c.reset} ${data.metadata.generated_at}`
        );
        lines.push(
            `${c.accent}Hostname:${c.reset}  ${data.metadata.hostname}`
        );
        lines.push(
            `${c.accent}Source:${c.reset}    ${data.metadata.source}`
        );
        lines.push(
            `${c.accent}PID:${c.reset}       ${data.metadata.pid}`
        );
        lines.push(
            `${c.accent}Platform:${c.reset}  ${data.metadata.platform}`
        );
        lines.push(
            `${c.accent}Node:${c.reset}      ${data.metadata.node_version}`
        );
        lines.push("");

        lines.push(
            `${c.accent}Sockets used:${c.reset} ${data.sockets_used}`
        );
        lines.push(
            `${c.accent}Protocols:${c.reset}    ${data.summary.protocol_count}`
        );
        lines.push(
            `${c.accent}Populated:${c.reset}    ${data.summary.populated_protocol_count}`
        );
        lines.push(
            `${c.accent}Total in use:${c.reset} ${data.summary.total_in_use}`
        );
        lines.push(
            `${c.accent}Memory units:${c.reset} ${data.summary.total_memory_units}`
        );
        lines.push("");

        for (const key of [
            "tcp",
            "udp",
            "udp_lite",
            "raw",
            "frag"
        ]) {
            this.renderProtocolSection(
                lines,
                c,
                report,
                key
            );
        }

        if (this.config.extended) {
            lines.push(
                `${c.title}Extended Protocol Information${c.reset}`
            );
            lines.push(
                `${c.title}=============================${c.reset}`
            );

            for (const key of [
                "tcp6",
                "udp6",
                "unix",
                "netlink",
                "packet",
                "icmp",
                "icmp6"
            ]) {
                this.renderProtocolSection(
                    lines,
                    c,
                    report,
                    key
                );
            }

            if (
                Object.keys(report.tcp_ext).length > 0
            ) {
                lines.push(
                    `${c.section}TcpExt:${c.reset}`
                );

                const keys =
                    Object.keys(report.tcp_ext).sort();

                for (const key of keys) {
                    lines.push(
                        `  ${c.key}${key}:${c.reset} ${report.tcp_ext[key]}`
                    );
                }

                lines.push("");
            }
        }

        if (data.read_sources.length > 0) {
            lines.push(
                `${c.title}Read Sources${c.reset}`
            );
            lines.push(
                `${c.title}===========${c.reset}`
            );

            for (const item of data.read_sources) {
                lines.push(
                    `  ${c.key}${item.status}:${c.reset} ${item.path}`
                );
            }

            lines.push("");
        }

        if (
            data.notes &&
            data.notes.length > 0
        ) {
            lines.push(
                `${c.title}Notes${c.reset}`
            );
            lines.push(
                `${c.title}=====${c.reset}`
            );

            for (const note of data.notes) {
                lines.push(`  - ${note}`);
            }

            lines.push("");
        }

        if (metrics) {
            lines.push(
                `${c.title}Performance Metrics${c.reset}`
            );
            lines.push(
                `${c.title}===================${c.reset}`
            );
            lines.push(
                `  ${c.key}Execution time:${c.reset} ${metrics.execution_time_seconds.toFixed(6)}s`
            );
            lines.push(
                `  ${c.key}RSS:${c.reset}            ${metrics.rss_mb.toFixed(2)} MB`
            );
            lines.push(
                `  ${c.key}Heap total:${c.reset}     ${metrics.heap_total_mb.toFixed(2)} MB`
            );
            lines.push(
                `  ${c.key}Heap used:${c.reset}      ${metrics.heap_used_mb.toFixed(2)} MB`
            );
            lines.push(
                `  ${c.key}External:${c.reset}       ${metrics.external_mb.toFixed(2)} MB`
            );
            lines.push(
                `  ${c.key}Array buffers:${c.reset}  ${metrics.array_buffers_mb.toFixed(2)} MB`
            );
            lines.push(
                `  ${c.key}Start heap used:${c.reset} ${metrics.start_heap_used_mb.toFixed(2)} MB`
            );
            lines.push("");
        }

        return (
            lines
                .join("\n")
                .replace(/\n+$/, "") +
            "\n"
        );
    }
}

class SafeFileReader {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.allowedRootCache = null;
    }

    normalizePath(inputPath) {
        if (typeof inputPath !== "string") {
            throw new Error("Path must be a string");
        }

        let result = inputPath
            .replace(/\0/g, "")
            .trim();

        if (result.length === 0) {
            throw new Error(
                "Path must not be empty"
            );
        }

        result = result.replace(/\\/g, "/");

        return result;
    }

    resolvePath(filePath) {
        return fs.realpathSync(
            this.normalizePath(filePath)
        );
    }

    getAllowedRoots() {
        if (this.allowedRootCache) {
            return this.allowedRootCache;
        }

        this.allowedRootCache =
            this.config.allowedRoots.map(root => {
                const normalized =
                    this.normalizePath(root);

                return fs.existsSync(normalized)
                    ? fs.realpathSync(normalized)
                    : path.resolve(normalized);
            });

        return this.allowedRootCache;
    }

    isPathAllowed(resolvedPath) {
        for (const root of this.getAllowedRoots()) {
            if (
                resolvedPath === root ||
                resolvedPath.startsWith(
                    `${root}${path.sep}`
                )
            ) {
                return true;
            }
        }

        return false;
    }

    statChecked(filePath) {
        const resolved =
            this.resolvePath(filePath);

        if (!this.isPathAllowed(resolved)) {
            throw new Error(
                `Path not allowed: ${filePath}`
            );
        }

        const stat = fs.lstatSync(resolved);

        if (!stat.isFile()) {
            throw new Error(
                `Not a regular file: ${filePath}`
            );
        }

        if (
            stat.size >
            this.config.maxFileSize
        ) {
            throw new Error(
                `File size exceeds limit: ${filePath}`
            );
        }

        return {
            resolved,
            stat
        };
    }

    readLines(filePath) {
        const { resolved } =
            this.statChecked(filePath);

        const content =
            fs.readFileSync(
                resolved,
                "utf8"
            );

        const lines =
            content.split(/\r?\n/);

        if (
            lines.length >
            this.config.maxLineCount
        ) {
            throw new Error(
                `File appears too large or malformed: ${filePath}`
            );
        }

        for (const line of lines) {
            if (
                line.length >
                this.config.maxLineSize
            ) {
                throw new Error(
                    `Line too long in file: ${filePath}`
                );
            }
        }

        return {
            resolved,
            lines
        };
    }
}

class ConfigFileReader {
    constructor(config) {
        this.config = config;
    }

    normalizePath(inputPath) {
        if (typeof inputPath !== "string") {
            throw new Error(
                "Configuration path must be a string"
            );
        }

        const result = inputPath
            .replace(/\0/g, "")
            .trim();

        if (!result) {
            throw new Error(
                "Configuration path must not be empty"
            );
        }

        return result;
    }

    readLines(filePath) {
        const normalized =
            this.normalizePath(filePath);

        const resolved =
            fs.realpathSync(normalized);

        const stat =
            fs.lstatSync(resolved);

        if (!stat.isFile()) {
            throw new Error(
                `Not a regular configuration file: ${filePath}`
            );
        }

        if (
            stat.size >
            this.config.maxFileSize
        ) {
            throw new Error(
                `Configuration file exceeds size limit: ${filePath}`
            );
        }

        const content =
            fs.readFileSync(
                resolved,
                "utf8"
            );

        const lines =
            content.split(/\r?\n/);

        if (
            lines.length >
            this.config.maxLineCount
        ) {
            throw new Error(
                `Configuration file has too many lines: ${filePath}`
            );
        }

        for (const line of lines) {
            if (
                line.length >
                this.config.maxLineSize
            ) {
                throw new Error(
                    `Configuration line too long: ${filePath}`
                );
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
        const value =
            String(raw).trim();

        if (/^(true|yes|on)$/i.test(value)) {
            return true;
        }

        if (/^(false|no|off)$/i.test(value)) {
            return false;
        }

        if (/^-?\d+$/.test(value)) {
            return Number.parseInt(
                value,
                10
            );
        }

        if (value.includes(",")) {
            return value
                .split(",")
                .map(item => item.trim())
                .filter(Boolean);
        }

        return value;
    }

    static parse(text) {
        const result = {};
        const lines =
            String(text).split(/\r?\n/);

        for (const rawLine of lines) {
            const line = rawLine.trim();

            if (
                !line ||
                line.startsWith(";") ||
                line.startsWith("#")
            ) {
                continue;
            }

            if (
                line.startsWith("[") &&
                line.endsWith("]")
            ) {
                continue;
            }

            const idx =
                line.indexOf("=");

            if (idx === -1) {
                continue;
            }

            const key =
                line.slice(0, idx).trim();

            const value =
                line.slice(idx + 1).trim();

            if (!key) {
                continue;
            }

            result[key] =
                IniLoader.parseValue(value);
        }

        return result;
    }
}
class ArgParser {
    constructor(argv) {
        this.argv = argv;
        this.index = 0;
        this.updates = {};
    }

    nextValue(flag) {
        this.index += 1;

        if (this.index >= this.argv.length) {
            throw new Error(`Missing value for ${flag}`);
        }

        return this.argv[this.index];
    }

    parse() {
        for (
            this.index = 0;
            this.index < this.argv.length;
            this.index += 1
        ) {
            const arg = this.argv[this.index];

            switch (arg) {
                case "--json":
                    this.updates.jsonOutput = true;
                    break;

                case "--compact-json":
                    this.updates.jsonOutput = true;
                    this.updates.compactJson = true;
                    break;

                case "--help":
                    this.updates.help = true;
                    break;

                case "--version":
                    this.updates.version = true;
                    break;

                case "--performance":
                    this.updates.showPerformance = true;
                    break;

                case "--quiet":
                    this.updates.quiet = true;
                    break;

                case "--extended":
                    this.updates.extended = true;
                    break;

                case "--tcp-states":
                    this.updates.tcpStates = true;
                    break;

                case "--processes":
                    this.updates.processes = true;
                    this.updates.tcpStates = true;
                    break;

                case "--watch":
                    this.updates.watch = true;
                    break;

                case "--csv":
                    this.updates.csvOutput = true;
                    break;

                case "--interval":
                    this.updates.interval = Number(this.nextValue(arg));
                    break;

                case "--count":
                    this.updates.count = Number(this.nextValue(arg));
                    break;

                case "--process-limit":
                    this.updates.processLimit = Number(this.nextValue(arg));
                    break;

                case "--threshold-tcp":
                    this.updates.thresholdTcp = Number(this.nextValue(arg));
                    break;

                case "--threshold-established":
                    this.updates.thresholdEstablished = Number(this.nextValue(arg));
                    break;

                case "--threshold-timewait":
                    this.updates.thresholdTimewait = Number(this.nextValue(arg));
                    break;

                case "--threshold-orphan":
                    this.updates.thresholdOrphan = Number(this.nextValue(arg));
                    break;

                case "--threshold-retrans":
                    this.updates.thresholdRetrans = Number(this.nextValue(arg));
                    break;

                case "--include-zeros":
                    this.updates.includeZeros = true;
                    break;

                case "--log-level":
                    this.updates.logLevel =
                        String(this.nextValue(arg)).toUpperCase();
                    break;

                case "--path":
                    this.updates.sockstatPath =
                        String(this.nextValue(arg));
                    break;

                case "--config":
                    this.updates.configFile =
                        String(this.nextValue(arg));
                    break;

                case "--output":
                    this.updates.outputFile =
                        String(this.nextValue(arg));
                    break;

                case "--color":
                    this.updates.color =
                        String(this.nextValue(arg)).toLowerCase();
                    break;

                case "--max-file-size":
                    this.updates.maxFileSize =
                        Number.parseInt(
                            String(this.nextValue(arg)),
                            10
                        );
                    break;

                case "--max-line-count":
                    this.updates.maxLineCount =
                        Number.parseInt(
                            String(this.nextValue(arg)),
                            10
                        );
                    break;

                case "--max-line-size":
                    this.updates.maxLineSize =
                        Number.parseInt(
                            String(this.nextValue(arg)),
                            10
                        );
                    break;

                default:
                    throw new Error(
                        `Unknown argument: ${arg}`
                    );
            }
        }

        return this.updates;
    }
}

class ConfigMapper {
    static mapIni(data) {
        const mapped = {};

        const rules = {
            log_level: value => ({
                logLevel: String(value).toUpperCase()
            }),

            json_output: value => ({
                jsonOutput: Boolean(value)
            }),

            compact_json: value => ({
                compactJson: Boolean(value),
                jsonOutput: Boolean(value) || undefined
            }),

            help: value => ({
                help: Boolean(value)
            }),

            version: value => ({
                version: Boolean(value)
            }),

            show_performance: value => ({
                showPerformance: Boolean(value)
            }),

            quiet: value => ({
                quiet: Boolean(value)
            }),

            extended: value => ({
                extended: Boolean(value)
            }),

            tcp_states: value => ({tcpStates: Boolean(value)}),
            processes: value => ({processes: Boolean(value)}),
            watch: value => ({watch: Boolean(value)}),
            csv_output: value => ({csvOutput: Boolean(value)}),
            interval: value => ({interval: Number(value)}),
            count: value => ({count: Number(value)}),
            process_limit: value => ({processLimit: Number(value)}),
            threshold_tcp: value => ({thresholdTcp: Number(value)}),
            threshold_established: value => ({thresholdEstablished: Number(value)}),
            threshold_timewait: value => ({thresholdTimewait: Number(value)}),
            threshold_orphan: value => ({thresholdOrphan: Number(value)}),
            threshold_retrans: value => ({thresholdRetrans: Number(value)}),

            include_zeros: value => ({
                includeZeros: Boolean(value)
            }),

            sockstat_path: value => ({
                sockstatPath: String(value)
            }),

            sockstat6_path: value => ({
                sockstat6Path: String(value)
            }),

            netlink_path: value => ({
                netlinkPath: String(value)
            }),

            packet_path: value => ({
                packetPath: String(value)
            }),

            snmp_path: value => ({
                snmpPath: String(value)
            }),

            snmp6_path: value => ({
                snmp6Path: String(value)
            }),

            netstat_path: value => ({
                netstatPath: String(value)
            }),

            unix_path: value => ({
                unixPath: String(value)
            }),

            output_file: value => ({
                outputFile: String(value)
            }),

            color: value => ({
                color: String(value).toLowerCase()
            }),

            max_file_size: value => ({
                maxFileSize:
                    ProtocolStats.toInt(value)
            }),

            max_line_count: value => ({
                maxLineCount:
                    ProtocolStats.toInt(value)
            }),

            max_line_size: value => ({
                maxLineSize:
                    ProtocolStats.toInt(value)
            }),

            allowed_roots: value => ({
                allowedRoots:
                    Array.isArray(value)
                        ? value.map(String)
                        : [String(value)]
            })
        };

        for (
            const [key, value]
            of Object.entries(data || {})
        ) {
            if (
                !Object.prototype.hasOwnProperty.call(
                    rules,
                    key
                )
            ) {
                continue;
            }

            const partial = rules[key](value);

            for (
                const [partialKey, partialValue]
                of Object.entries(partial)
            ) {
                if (partialValue !== undefined) {
                    mapped[partialKey] = partialValue;
                }
            }
        }

        return mapped;
    }
}

class ProtocolRegistry {
    constructor(tool) {
        this.tool = tool;
        this.sectionParsers =
            this.buildSectionParsers();
        this.extendedFileSpecs =
            this.buildExtendedFileSpecs();
    }

    buildSectionParsers() {
        return {
            "sockets:": (parts, report) => {
                if (parts.length >= 3) {
                    report.setSocketsUsed(
                        this.tool.parseInt(parts[2])
                    );
                }
            },

            "TCP:": (parts, report) => {
                this.tool.parseProtocolSection(
                    parts,
                    report,
                    "tcp",
                    {
                        inuse: "in_use",
                        orphan: "orphan",
                        tw: "time_wait",
                        alloc: "allocated",
                        mem: "memory"
                    }
                );
            },

            "UDP:": (parts, report) => {
                this.tool.parseProtocolSection(
                    parts,
                    report,
                    "udp",
                    {
                        inuse: "in_use",
                        mem: "memory"
                    }
                );
            },

            "UDPLITE:": (parts, report) => {
                this.tool.parseProtocolSection(
                    parts,
                    report,
                    "udp_lite",
                    {
                        inuse: "in_use"
                    }
                );
            },

            "RAW:": (parts, report) => {
                this.tool.parseProtocolSection(
                    parts,
                    report,
                    "raw",
                    {
                        inuse: "in_use"
                    }
                );
            },

            "FRAG:": (parts, report) => {
                this.tool.parseProtocolSection(
                    parts,
                    report,
                    "frag",
                    {
                        inuse: "in_use",
                        memory: "memory"
                    }
                );
            },

            "TCP6:": (parts, report) => {
                if (
                    this.tool.config.extended &&
                    report.hasProtocol("tcp6")
                ) {
                    this.tool.parseProtocolSection(
                        parts,
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
                }
            },

            "UDP6:": (parts, report) => {
                if (
                    this.tool.config.extended &&
                    report.hasProtocol("udp6")
                ) {
                    this.tool.parseProtocolSection(
                        parts,
                        report,
                        "udp6",
                        {
                            inuse: "in_use",
                            mem: "memory"
                        }
                    );
                }
            }
        };
    }

    buildExtendedFileSpecs() {
        return [
            {
                filePathKey: "sockstat6Path",
                section: "TCP6:",
                protocolKey: "tcp6",
                mapping: {
                    inuse: "in_use",
                    orphan: "orphan",
                    tw: "time_wait",
                    alloc: "allocated",
                    mem: "memory"
                }
            },

            {
                filePathKey: "sockstat6Path",
                section: "UDP6:",
                protocolKey: "udp6",
                mapping: {
                    inuse: "in_use",
                    mem: "memory"
                }
            }
        ];
    }
}


class AdvancedSocketInspector {
    constructor(config, logger) {
        this.config = config;
        this.logger = logger;
        this.procRoot = path.dirname(path.dirname(this.config.sockstatPath));
        this.stateNames = {
            "01": "ESTABLISHED",
            "02": "SYN_SENT",
            "03": "SYN_RECV",
            "04": "FIN_WAIT1",
            "05": "FIN_WAIT2",
            "06": "TIME_WAIT",
            "07": "CLOSE",
            "08": "CLOSE_WAIT",
            "09": "LAST_ACK",
            "0A": "LISTEN",
            "0B": "CLOSING",
            "0C": "NEW_SYN_RECV"
        };
        this.inodes = new Set();
    }

    source(name) {
        return path.join(this.procRoot, "net", name);
    }

    read(name, report) {
        const file = this.source(name);
        try {
            const stat = fs.statSync(file);
            if (!stat.isFile() || stat.size > this.config.maxFileSize) {
                throw new Error("Source is not a readable file within size limits");
            }
            const text = fs.readFileSync(file, "utf8");
            if (Buffer.byteLength(text) > this.config.maxFileSize) {
                throw new Error("Source exceeded read limit");
            }
            report.addReadSource(file, "ok");
            return text;
        } catch (err) {
            report.addReadSource(file, "unavailable");
            this.logger.debug(`${file}: ${err.message}`);
            return null;
        }
    }

    parseTable(name, text, report) {
        const lines = text.split(/\r?\n/);
        let entries = 0;
        for (const raw of lines.slice(1)) {
            const fields = raw.trim().split(/\s+/);
            if (fields.length < 10 || !/^\d+:$/.test(fields[0])) {
                continue;
            }
            entries += 1;
            const state = this.stateNames[fields[3].toUpperCase()] || "UNKNOWN";
            report.tcp_states[state] = (report.tcp_states[state] || 0) + 1;
            if (/^\d+$/.test(fields[9])) {
                this.inodes.add(fields[9]);
            }
        }
        report.auxiliary[`${name}_entries`] = entries;
    }

    parseSocketTable(name, text, report) {
        const lines = text.split(/\r?\n/).slice(1);
        let entries = 0;
        for (const raw of lines) {
            const fields = raw.trim().split(/\s+/);
            if (fields.length < 10 || !/^\d+:$/.test(fields[0])) {
                continue;
            }
            entries += 1;
            if (/^\d+$/.test(fields[9])) {
                this.inodes.add(fields[9]);
            }
        }
        report.auxiliary[`${name}_entries`] = entries;
    }

    parseUnixTable(text, report) {
        let entries = 0;
        for (const raw of text.split(/\r?\n/).slice(1)) {
            const fields = raw.trim().split(/\s+/);
            if (fields.length < 7 || !/^\d+:$/.test(fields[0])) {
                continue;
            }
            entries += 1;
            if (/^\d+$/.test(fields[6])) {
                this.inodes.add(fields[6]);
            }
        }
        report.auxiliary.unix_entries = entries;
    }

    parseMib(text, report) {
        const lines = text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
        for (let i = 0; i + 1 < lines.length; i += 1) {
            const keys = lines[i].split(/\s+/);
            const values = lines[i + 1].split(/\s+/);
            if (keys[0] !== values[0] || keys.length !== values.length) {
                continue;
            }
            if (!keys[0].endsWith(":")) {
                continue;
            }
            const section = keys[0].slice(0, -1);
            const result = {};
            for (let j = 1; j < keys.length; j += 1) {
                const raw = values[j];
                if (!/^-?\d+$/.test(raw)) {
                    continue;
                }
                const value = Number(raw);
                if (Number.isSafeInteger(value)) {
                    result[keys[j]] = value;
                }
            }
            report.counters[section] = result;
            i += 1;
        }
    }

    parseSnmp6(text, report) {
        for (const raw of text.split(/\r?\n/)) {
            const fields = raw.trim().split(/\s+/);
            if (fields.length !== 2 || !/^-?\d+$/.test(fields[1])) {
                continue;
            }
            const match = /^(Ip6|Icmp6|Udp6|Tcp6)(.+)$/.exec(fields[0]);
            if (!match) {
                continue;
            }
            const value = Number(fields[1]);
            if (!Number.isSafeInteger(value)) {
                continue;
            }
            if (!report.counters[match[1]]) {
                report.counters[match[1]] = {};
            }
            report.counters[match[1]][match[2]] = value;
        }
    }

    inspectProcesses(report) {
        const result = [];
        let pids;
        try {
            pids = fs.readdirSync(this.procRoot).filter(x => /^\d+$/.test(x));
        } catch (err) {
            report.addNote(`Process scan unavailable: ${err.message}`);
            return;
        }
        for (const pid of pids) {
            const dir = path.join(this.procRoot, pid, "fd");
            let descriptors;
            try {
                descriptors = fs.readdirSync(dir);
            } catch (_) {
                continue;
            }
            const owned = new Set();
            for (const fd of descriptors) {
                let target;
                try {
                    target = fs.readlinkSync(path.join(dir, fd));
                } catch (_) {
                    continue;
                }
                const match = /^socket:\[(\d+)\]$/.exec(target);
                if (match && this.inodes.has(match[1])) {
                    owned.add(match[1]);
                }
            }
            if (owned.size === 0) {
                continue;
            }
            let command = "unknown";
            try {
                command = fs.readFileSync(path.join(this.procRoot, pid, "comm"), "utf8").trim();
            } catch (_) {}
            result.push({pid: Number(pid), command, sockets: owned.size});
        }
        result.sort((a, b) => b.sockets - a.sockets || a.pid - b.pid);
        report.processes = result.slice(0, this.config.processLimit);
    }

    inspect(report) {
        const needsTables = this.config.tcpStates || this.config.processes || this.config.extended;
        if (needsTables) {
            for (const name of ["tcp", "tcp6"]) {
                const text = this.read(name, report);
                if (text !== null) {
                    this.parseTable(name, text, report);
                }
            }
        }
        if (this.config.processes || this.config.extended) {
            for (const name of ["udp", "udp6", "udplite", "udplite6", "raw", "raw6"]) {
                const text = this.read(name, report);
                if (text !== null) {
                    this.parseSocketTable(name, text, report);
                }
            }
            const unix = this.read("unix", report);
            if (unix !== null) {
                this.parseUnixTable(unix, report);
            }
        }
        if (this.config.extended || this.config.watch) {
            for (const name of ["snmp", "netstat"]) {
                const text = this.read(name, report);
                if (text !== null) {
                    this.parseMib(text, report);
                }
            }
            if (this.config.extended) {
                const text = this.read("snmp6", report);
                if (text !== null) {
                    this.parseSnmp6(text, report);
                }
            }
        }
        if (this.config.processes) {
            this.inspectProcesses(report);
        }
    }
}

class SampleAnalyzer {
    constructor(config) {
        this.config = config;
        this.previous = null;
        this.counterNames = [
            ["Tcp", "InSegs"],
            ["Tcp", "OutSegs"],
            ["Tcp", "RetransSegs"],
            ["Tcp", "ActiveOpens"],
            ["Tcp", "PassiveOpens"],
            ["Tcp", "OutRsts"],
            ["Udp", "InDatagrams"],
            ["Udp", "OutDatagrams"],
            ["Udp", "InErrors"],
            ["TcpExt", "TCPSynRetrans"],
            ["TcpExt", "TCPTimeouts"],
            ["TcpExt", "TCPLossProbes"]
        ];
    }

    analyze(report) {
        const now = process.hrtime.bigint();
        const rates = {};
        let elapsed = null;
        if (this.previous) {
            elapsed = Number(now - this.previous.time) / 1e9;
            if (elapsed > 0) {
                for (const [section, key] of this.counterNames) {
                    const a = report.counters[section]?.[key];
                    const b = this.previous.counters[section]?.[key];
                    if (Number.isSafeInteger(a) && Number.isSafeInteger(b) && a >= b) {
                        rates[`${section}.${key}`] = Number(((a - b) / elapsed).toFixed(3));
                    }
                }
            }
        }
        report.sampling = {
            elapsed_seconds: elapsed === null ? null : Number(elapsed.toFixed(6)),
            rates_per_second: rates
        };
        this.previous = {time: now, counters: JSON.parse(JSON.stringify(report.counters))};
        const checks = [
            ["tcp_in_use", report.tryGetProtocol("tcp")?.get("in_use"), this.config.thresholdTcp],
            ["tcp_established", report.tcp_states.ESTABLISHED || 0, this.config.thresholdEstablished],
            ["tcp_time_wait", report.tcp_states.TIME_WAIT || 0, this.config.thresholdTimewait],
            ["tcp_orphan", report.tryGetProtocol("tcp")?.get("orphan"), this.config.thresholdOrphan],
            ["tcp_retransmits_per_second", rates["Tcp.RetransSegs"], this.config.thresholdRetrans]
        ];
        report.alerts = checks.filter(([, value, limit]) =>
            limit !== null && value !== undefined && value > limit
        ).map(([metric, value, threshold]) => ({metric, value, threshold}));
    }
}

class CsvFormatter {
    static columns() {
        return [
            "timestamp", "hostname", "sockets_used", "tcp_in_use", "tcp_orphan",
            "tcp_time_wait", "tcp_allocated", "tcp_memory", "udp_in_use",
            "tcp_established", "tcp_listen", "tcp_close_wait", "tcp_syn_sent",
            "tcp_table_entries", "tcp6_table_entries", "unix_entries", "process_count",
            "elapsed_seconds", "tcp_in_segments_per_second", "tcp_out_segments_per_second",
            "tcp_retransmits_per_second", "udp_in_datagrams_per_second",
            "udp_out_datagrams_per_second", "alert_count"
        ];
    }

    static escape(value) {
        if (value === undefined || value === null) {
            return "";
        }
        const str = String(value);
        return /[",\r\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
    }

    static row(report) {
        const tcp = report.tryGetProtocol("tcp");
        const udp = report.tryGetProtocol("udp");
        const rates = report.sampling?.rates_per_second || {};
        return [
            report.metadata.generated_at, report.metadata.hostname, report.sockets_used,
            tcp?.get("in_use"), tcp?.get("orphan"), tcp?.get("time_wait"),
            tcp?.get("allocated"), tcp?.get("memory"), udp?.get("in_use"),
            report.tcp_states.ESTABLISHED, report.tcp_states.LISTEN,
            report.tcp_states.CLOSE_WAIT, report.tcp_states.SYN_SENT,
            report.auxiliary.tcp_entries, report.auxiliary.tcp6_entries,
            report.auxiliary.unix_entries, report.processes.length,
            report.sampling?.elapsed_seconds, rates["Tcp.InSegs"],
            rates["Tcp.OutSegs"], rates["Tcp.RetransSegs"],
            rates["Udp.InDatagrams"], rates["Udp.OutDatagrams"], report.alerts.length
        ].map(CsvFormatter.escape).join(",") + "\n";
    }
}

class MonitoringSession {
    constructor(tool) {
        this.tool = tool;
        this.analyzer = new SampleAnalyzer(tool.config);
        this.samples = 0;
        this.stopped = false;
        this.csvHeaderWritten = false;
        this.timer = null;
        this.waitResolve = null;
    }

    stop() {
        this.stopped = true;
        if (this.timer !== null) {
            clearTimeout(this.timer);
            this.timer = null;
        }
        if (this.waitResolve) {
            const resolve = this.waitResolve;
            this.waitResolve = null;
            resolve();
        }
    }

    wait(ms) {
        if (this.stopped) {
            return Promise.resolve();
        }
        return new Promise(resolve => {
            this.waitResolve = resolve;
            this.timer = setTimeout(() => {
                this.timer = null;
                this.waitResolve = null;
                resolve();
            }, ms);
        });
    }

    collect() {
        const report = this.tool.createEmptyReport();
        this.tool.readSockstat(report);
        this.tool.loadExtendedProtocolInfo(report);
        new AdvancedSocketInspector(this.tool.config, this.tool.logger).inspect(report);
        report.refreshSummary();
        this.analyzer.analyze(report);
        return report;
    }

    output(report) {
        let text;
        if (this.tool.config.csvOutput) {
            text = this.csvHeaderWritten ? "" : CsvFormatter.columns().join(",") + "\n";
            text += CsvFormatter.row(report);
            this.csvHeaderWritten = true;
        } else if (this.tool.config.jsonOutput) {
            const data = report.toJSONObject(this.tool.config.includeZeros);
            if (this.tool.config.showPerformance) {
                data.performance = this.tool.metrics.toJSON();
            }
            text = JSON.stringify(data, null, this.tool.config.compactJson ? 0 : 2) + "\n";
        } else {
            text = this.tool.buildOutput(report);
            const extra = [];
            if (Object.keys(report.tcp_states).length) {
                extra.push("TCP connection states:");
                for (const [key, value] of Object.entries(report.tcp_states).sort((a, b) => b[1] - a[1])) {
                    extra.push(`  ${key}: ${value}`);
                }
            }
            if (report.processes.length) {
                extra.push("Socket-owning processes:");
                for (const item of report.processes) {
                    extra.push(`  PID ${item.pid} ${item.command}: ${item.sockets}`);
                }
            }
            if (report.sampling && Object.keys(report.sampling.rates_per_second).length) {
                extra.push("Counter rates per second:");
                for (const [key, value] of Object.entries(report.sampling.rates_per_second)) {
                    extra.push(`  ${key}: ${value}`);
                }
            }
            if (report.alerts.length) {
                extra.push("Threshold alerts:");
                for (const alert of report.alerts) {
                    extra.push(`  ${alert.metric}: ${alert.value} > ${alert.threshold}`);
                }
            }
            if (extra.length) {
                text += "\n" + extra.join("\n") + "\n";
            }
        }
        if (this.tool.config.outputFile) {
            fs.appendFileSync(this.tool.config.outputFile, text, "utf8");
        } else if (!this.tool.config.quiet) {
            process.stdout.write(text);
        }
    }

    async run() {
        if (this.tool.config.outputFile) {
            fs.writeFileSync(this.tool.config.outputFile, "", "utf8");
        }
        while (!this.stopped && !this.tool.shutdownRequested) {
            const started = process.hrtime.bigint();
            const report = this.collect();
            this.tool.metrics.stop();
            this.output(report);
            this.samples += 1;
            if (!this.tool.config.watch || (this.tool.config.count > 0 && this.samples >= this.tool.config.count)) {
                break;
            }
            const elapsed = Number(process.hrtime.bigint() - started) / 1e6;
            await this.wait(Math.max(0, this.tool.config.interval * 1000 - elapsed));
        }
    }
}

class SocketStatsTool {
    constructor() {
        this.config = new ToolConfig();

        this.logger = new Logger(
            this.config.logLevel,
            this.config.quiet
        );

        this.metrics = new PerformanceMetrics(
            process.hrtime.bigint(),
            process.memoryUsage()
        );

        this.shutdownRequested = false;
        this.interruptedSignal = null;

        this.fileReader = new SafeFileReader(
            this.config,
            this.logger
        );

        this.configFileReader =
            new ConfigFileReader(this.config);

        this.protocolRegistry =
            new ProtocolRegistry(this);

        this.boundSignalHandler =
            this.handleSignal.bind(this);

        this.cliUpdates = {};
    }

    refreshRuntimeHelpers() {
        this.logger.setLevel(
            this.config.logLevel
        );

        this.logger.setQuiet(
            this.config.quiet
        );

        this.fileReader =
            new SafeFileReader(
                this.config,
                this.logger
            );

        this.configFileReader =
            new ConfigFileReader(
                this.config
            );

        this.protocolRegistry =
            new ProtocolRegistry(this);
    }

    handleSignal(signalName) {
        if (!this.shutdownRequested) {
            this.logger.warning(
                `Shutdown requested by signal ${signalName}`
            );
        }

        this.shutdownRequested = true;
        this.interruptedSignal = signalName;
        if (this.session) {
            this.session.stop();
        }
    }

    installSignalHandlers() {
        for (
            const sig
            of ["SIGINT", "SIGTERM", "SIGHUP"]
        ) {
            try {
                process.on(
                    sig,
                    this.boundSignalHandler
                );
            } catch (err) {
                this.logger.debug(
                    `Could not install signal handler for ${sig}: ${err.message}`
                );
            }
        }
    }

    parseArgs(
        argv = process.argv.slice(2)
    ) {
        this.cliUpdates =
            new ArgParser(argv).parse();

        this.config.apply(
            this.cliUpdates
        );

        this.refreshRuntimeHelpers();
    }

    loadConfigFile() {
        if (!this.config.configFile) {
            return;
        }

        const configFile =
            this.config.configFile;

        const { resolved, lines } =
            this.configFileReader.readLines(
                configFile
            );

        const data =
            IniLoader.parse(
                lines.join("\n")
            );

        const mapped =
            ConfigMapper.mapIni(data);

        const cliUpdates = {
            ...this.cliUpdates
        };

        this.config =
            new ToolConfig();

        this.config.apply(mapped);
        this.config.apply(cliUpdates);

        this.refreshRuntimeHelpers();

        this.logger.debug(
            `Loaded configuration from ${resolved}`
        );
    }

    validateConfig() {
        const validLogLevels = [
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR"
        ];

        if (
            !validLogLevels.includes(
                String(
                    this.config.logLevel
                ).toUpperCase()
            )
        ) {
            throw new Error(
                `Invalid log level: ${this.config.logLevel}`
            );
        }

        if (
            ![
                "auto",
                "always",
                "never"
            ].includes(
                this.config.color
            )
        ) {
            throw new Error(
                `Invalid color mode: ${this.config.color}`
            );
        }

        if (
            !Number.isInteger(
                this.config.maxFileSize
            ) ||
            this.config.maxFileSize < 1
        ) {
            throw new Error(
                "Invalid max file size"
            );
        }

        if (
            !Number.isInteger(
                this.config.maxLineCount
            ) ||
            this.config.maxLineCount < 1
        ) {
            throw new Error(
                "Invalid max line count"
            );
        }

        if (
            !Number.isInteger(
                this.config.maxLineSize
            ) ||
            this.config.maxLineSize < 1
        ) {
            throw new Error(
                "Invalid max line size"
            );
        }

        if (
            !Array.isArray(
                this.config.allowedRoots
            ) ||
            this.config.allowedRoots.length === 0
        ) {
            throw new Error(
                "Invalid allowed roots"
            );
        }

        for (
            const root
            of this.config.allowedRoots
        ) {
            if (
                typeof root !== "string" ||
                root.includes("\0") ||
                root.trim() === ""
            ) {
                throw new Error(
                    "Invalid allowed root entry"
                );
            }
        }

        if (!Number.isFinite(this.config.interval) || this.config.interval <= 0) {
            throw new Error("Interval must be positive");
        }

        for (const field of ["count", "processLimit"]) {
            if (!Number.isSafeInteger(this.config[field]) || this.config[field] < 0) {
                throw new Error(`Invalid ${field}`);
            }
        }

        for (const field of [
            "thresholdTcp",
            "thresholdEstablished",
            "thresholdTimewait",
            "thresholdOrphan",
            "thresholdRetrans"
        ]) {
            const value = this.config[field];
            if (value !== null && (!Number.isFinite(value) || value < 0)) {
                throw new Error(`Invalid ${field}`);
            }
        }

        if (this.config.csvOutput && this.config.jsonOutput) {
            throw new Error("CSV and JSON modes are mutually exclusive");
        }

        for (
            const field
            of [
                "sockstatPath",
                "sockstat6Path",
                "netlinkPath",
                "packetPath",
                "snmpPath",
                "snmp6Path",
                "netstatPath",
                "unixPath"
            ]
        ) {
            const value =
                this.config[field];

            if (
                typeof value !== "string" ||
                value.includes("\0") ||
                value.trim() === ""
            ) {
                throw new Error(
                    `Invalid path in config field: ${field}`
                );
            }

            if (
                !/^[a-zA-Z0-9/_\-.]+$/.test(
                    value
                )
            ) {
                throw new Error(
                    `Invalid path format in config field: ${field}`
                );
            }
        }
    }

    createEmptyReport() {
        const report =
            new SocketStatsReport(
                Metadata.create(
                    this.config.sockstatPath
                )
            );

        const baseProtocols = {
            tcp: {
                name: "TCP",
                fields: {
                    in_use: 0,
                    orphan: 0,
                    time_wait: 0,
                    allocated: 0,
                    memory: 0
                }
            },

            udp: {
                name: "UDP",
                fields: {
                    in_use: 0,
                    memory: 0
                }
            },

            udp_lite: {
                name: "UDPLite",
                fields: {
                    in_use: 0
                }
            },

            raw: {
                name: "RAW",
                fields: {
                    in_use: 0
                }
            },

            frag: {
                name: "FRAG",
                fields: {
                    in_use: 0,
                    memory: 0
                }
            }
        };

        const extendedProtocols = {
            tcp6: {
                name: "TCP6",
                fields: {
                    in_use: 0,
                    orphan: 0,
                    time_wait: 0,
                    allocated: 0,
                    memory: 0
                }
            },

            udp6: {
                name: "UDP6",
                fields: {
                    in_use: 0,
                    memory: 0
                }
            },

            unix: {
                name: "UNIX",
                fields: {
                    in_use: 0
                }
            },

            icmp: {
                name: "ICMP",
                fields: {}
            },

            icmp6: {
                name: "ICMP6",
                fields: {}
            },

            netlink: {
                name: "Netlink",
                fields: {
                    in_use: 0
                }
            },

            packet: {
                name: "Packet",
                fields: {
                    in_use: 0
                }
            }
        };

        for (
            const [key, spec]
            of Object.entries(
                baseProtocols
            )
        ) {
            report.addProtocol(
                key,
                new ProtocolStats(
                    spec.name,
                    spec.fields
                )
            );
        }

        if (this.config.extended) {
            for (
                const [key, spec]
                of Object.entries(
                    extendedProtocols
                )
            ) {
                report.addProtocol(
                    key,
                    new ProtocolStats(
                        spec.name,
                        spec.fields
                    )
                );
            }
        }

        return report;
    }

    parseInt(value) {
        const raw = String(value);
        if (!/^-?\d+$/.test(raw)) {
            throw new Error(`Invalid integer: ${value}`);
        }
        const parsed = Number(raw);

        if (!Number.isSafeInteger(parsed)) {
            throw new Error(
                `Failed to parse integer: ${value}`
            );
        }

        return parsed;
    }

    parseProtocolSection(
        parts,
        report,
        key,
        mapping
    ) {
        let protocol =
            report.tryGetProtocol(key);

        if (!protocol) {
            protocol =
                new ProtocolStats(key);

            report.addProtocol(
                key,
                protocol
            );
        }

        for (
            let i = 1;
            i < parts.length;
            i += 2
        ) {
            if (
                i + 1 >= parts.length
            ) {
                break;
            }

            const field =
                parts[i];

            const value =
                parts[i + 1];

            if (
                Object.prototype.hasOwnProperty.call(
                    mapping,
                    field
                )
            ) {
                protocol.set(
                    mapping[field],
                    this.parseInt(value)
                );
            } else {
                this.logger.debug(
                    `Unknown ${key} field: ${field}`
                );
            }
        }
    }

    parseLine(line, report) {
        if (
            line.length >
            this.config.maxLineSize
        ) {
            this.logger.warning(
                "Line too long, skipping"
            );
            return;
        }

        const parts =
            String(line)
                .trim()
                .split(/\s+/)
                .filter(Boolean);

        if (parts.length < 2) {
            this.logger.debug(
                `Skipping malformed line: ${line}`
            );
            return;
        }

        const fn =
            this.protocolRegistry
                .sectionParsers[
                    parts[0]
                ];

        if (fn) {
            fn(parts, report);
        } else {
            this.logger.debug(
                `Unknown section: ${parts[0]}`
            );
        }
    }

    readSockstat(report) {
        const { resolved, lines } =
            this.fileReader.readLines(
                this.config.sockstatPath
            );

        report.addReadSource(
            resolved,
            "ok"
        );

        let count = 0;

        for (const raw of lines) {
            if (
                this.shutdownRequested
            ) {
                report.addNote(
                    "Parsing interrupted by shutdown request"
                );
                break;
            }

            const line = raw.trim();

            if (!line) {
                continue;
            }

            this.parseLine(
                line,
                report
            );

            count += 1;

            if (
                count >
                this.config.maxLineCount
            ) {
                throw new Error(
                    "Sockstat file appears too large or malformed"
                );
            }
        }

        this.logger.debug(
            `Processed ${count} lines from ${resolved}`
        );
    }

    loadProtocolSectionsFromFile(
        filePath,
        specs,
        report
    ) {
        try {
            const { resolved, lines } =
                this.fileReader.readLines(
                    filePath
                );

            report.addReadSource(
                resolved,
                "ok"
            );

            const pending =
                new Map();

            for (const spec of specs) {
                pending.set(
                    spec.section,
                    spec
                );
            }

            for (const raw of lines) {
                if (
                    this.shutdownRequested
                ) {
                    break;
                }

                const line =
                    raw.trim();

                if (!line) {
                    continue;
                }

                const firstSpace =
                    line.search(/\s/);

                const section =
                    firstSpace === -1
                        ? line
                        : line.slice(
                            0,
                            firstSpace
                        );

                const spec =
                    pending.get(section);

                if (!spec) {
                    continue;
                }

                const parts =
                    line.split(/\s+/);

                this.parseProtocolSection(
                    parts,
                    report,
                    spec.protocolKey,
                    spec.mapping
                );

                pending.delete(
                    section
                );

                if (
                    pending.size === 0
                ) {
                    break;
                }
            }

            for (
                const spec
                of pending.values()
            ) {
                report.addNote(
                    `Section ${spec.section} not found in ${resolved}`
                );
            }
        } catch (err) {
            report.addReadSource(
                filePath,
                "unavailable"
            );

            this.logger.debug(
                `Could not load protocol sections from ${filePath}: ${err.message}`
            );
        }
    }

    loadExtendedSectionFiles(report) {
        const grouped =
            new Map();

        for (
            const spec
            of this.protocolRegistry
                .extendedFileSpecs
        ) {
            const filePath =
                this.config[
                    spec.filePathKey
                ];

            if (
                !grouped.has(filePath)
            ) {
                grouped.set(
                    filePath,
                    []
                );
            }

            grouped
                .get(filePath)
                .push(spec);
        }

        for (
            const [filePath, specs]
            of grouped.entries()
        ) {
            this.loadProtocolSectionsFromFile(
                filePath,
                specs,
                report
            );
        }
    }

    countFileEntries(
        filePath,
        skipHeader = true
    ) {
        const { resolved, lines } =
            this.fileReader.readLines(
                filePath
            );

        let count = 0;
        let first = true;

        for (const raw of lines) {
            if (
                this.shutdownRequested
            ) {
                break;
            }

            if (
                first &&
                skipHeader
            ) {
                first = false;
                continue;
            }

            if (raw.trim()) {
                count += 1;
            }
        }

        return {
            resolved,
            count
        };
    }

    setProtocolCountFromFile(
        report,
        protocolKey,
        filePath,
        skipHeader = true
    ) {
        try {
            const {
                resolved,
                count
            } =
                this.countFileEntries(
                    filePath,
                    skipHeader
                );

            report.addReadSource(
                resolved,
                "ok"
            );

            const proto =
                report.tryGetProtocol(
                    protocolKey
                );

            if (proto) {
                proto.set(
                    "in_use",
                    count
                );
            }
        } catch (err) {
            report.addReadSource(
                filePath,
                "unavailable"
            );

            this.logger.debug(
                `Could not load ${protocolKey} info: ${err.message}`
            );
        }
    }

    loadSnmpSection(
        filePath,
        targetSection
    ) {
        const { resolved, lines } =
            this.fileReader.readLines(
                filePath
            );

        for (
            let i = 0;
            i < lines.length - 1;
            i += 1
        ) {
            if (
                this.shutdownRequested
            ) {
                break;
            }

            const head =
                lines[i].trim();

            const data =
                lines[i + 1].trim();

            if (
                !head.startsWith(
                    targetSection
                ) ||
                !data.startsWith(
                    targetSection
                )
            ) {
                continue;
            }

            const headParts =
                head.split(/\s+/);

            const dataParts =
                data.split(/\s+/);

            const mapping = {};

            for (
                let j = 1;
                j < headParts.length &&
                j < dataParts.length;
                j += 1
            ) {
                mapping[
                    headParts[j]
                ] =
                    this.parseInt(
                        dataParts[j]
                    );
            }

            return {
                resolved,
                mapping
            };
        }

        return {
            resolved,
            mapping: {}
        };
    }

    loadSnmp6Section(
        filePath,
        prefix
    ) {
        const { resolved, lines } =
            this.fileReader.readLines(
                filePath
            );

        const mapping = {};

        for (const raw of lines) {
            if (
                this.shutdownRequested
            ) {
                break;
            }

            const line =
                raw.trim();

            if (!line) {
                continue;
            }

            const parts =
                line.split(/\s+/);

            if (parts.length !== 2) {
                continue;
            }

            const key =
                parts[0];

            if (
                !key.startsWith(prefix)
            ) {
                continue;
            }

            const field =
                key.slice(
                    prefix.length
                );

            if (!field) {
                continue;
            }

            mapping[field] =
                this.parseInt(
                    parts[1]
                );
        }

        return {
            resolved,
            mapping
        };
    }

    setProtocolMetrics(
        report,
        protocolKey,
        mapping
    ) {
        const proto =
            report.tryGetProtocol(
                protocolKey
            );

        if (!proto) {
            return;
        }

        for (
            const [key, value]
            of Object.entries(
                mapping || {}
            )
        ) {
            proto.set(
                key,
                value
            );
        }
    }

    loadIcmpMetrics(report) {
        try {
            const {
                resolved,
                mapping
            } =
                this.loadSnmpSection(
                    this.config.snmpPath,
                    "Icmp:"
                );

            report.addReadSource(
                resolved,
                "ok"
            );

            this.setProtocolMetrics(
                report,
                "icmp",
                mapping
            );
        } catch (err) {
            report.addReadSource(
                this.config.snmpPath,
                "unavailable"
            );

            this.logger.debug(
                `Could not load ICMP metrics: ${err.message}`
            );
        }
    }

    loadIcmp6Metrics(report) {
        try {
            const {
                resolved,
                mapping
            } =
                this.loadSnmp6Section(
                    this.config.snmp6Path,
                    "Icmp6"
                );

            report.addReadSource(
                resolved,
                "ok"
            );

            this.setProtocolMetrics(
                report,
                "icmp6",
                mapping
            );
        } catch (err) {
            report.addReadSource(
                this.config.snmp6Path,
                "unavailable"
            );

            this.logger.debug(
                `Could not load ICMP6 metrics: ${err.message}`
            );
        }
    }

    parseTcpExtPairs(line) {
        const parts =
            line
                .trim()
                .split(/\s+/);

        if (
            parts.length < 3 ||
            parts[0] !== "TcpExt:"
        ) {
            return {};
        }

        const out = {};

        for (
            let i = 1;
            i < parts.length;
            i += 2
        ) {
            if (
                i + 1 >= parts.length
            ) {
                break;
            }

            out[parts[i]] =
                this.parseInt(
                    parts[i + 1]
                );
        }

        return out;
    }

    loadNetstat(report) {
        try {
            const {
                resolved,
                lines
            } =
                this.fileReader.readLines(
                    this.config.netstatPath
                );

            report.addReadSource(
                resolved,
                "ok"
            );

            for (
                let i = 0;
                i < lines.length - 1;
                i += 1
            ) {
                if (
                    this.shutdownRequested
                ) {
                    break;
                }

                const head =
                    lines[i].trim();

                const data =
                    lines[i + 1].trim();

                if (
                    !head.startsWith(
                        "TcpExt:"
                    ) ||
                    !data.startsWith(
                        "TcpExt:"
                    )
                ) {
                    continue;
                }

                const headParts =
                    head.split(/\s+/);

                const dataParts =
                    data.split(/\s+/);

                const values = {};

                for (
                    let j = 1;
                    j < headParts.length &&
                    j < dataParts.length;
                    j += 1
                ) {
                    values[
                        headParts[j]
                    ] =
                        this.parseInt(
                            dataParts[j]
                        );
                }

                report.setTcpExt(
                    values
                );

                return;
            }

        } catch (err) {
            report.addReadSource(
                this.config.netstatPath,
                "unavailable"
            );

            this.logger.debug(
                `Could not read netstat data: ${err.message}`
            );
        }
    }
	    loadExtendedProtocolInfo(report) {
        if (!this.config.extended) {
            return;
        }

        this.loadExtendedSectionFiles(report);

        this.setProtocolCountFromFile(
            report,
            "unix",
            this.config.unixPath,
            true
        );

        this.setProtocolCountFromFile(
            report,
            "netlink",
            this.config.netlinkPath,
            true
        );

        this.setProtocolCountFromFile(
            report,
            "packet",
            this.config.packetPath,
            true
        );

        this.loadIcmpMetrics(report);
        this.loadIcmp6Metrics(report);
        this.loadNetstat(report);
    }

    buildOutput(report) {
        const metrics =
            this.config.showPerformance
                ? this.metrics.toJSON()
                : null;

        if (this.config.jsonOutput) {
            const payload =
                report.toJSONObject(
                    this.config.includeZeros
                );

            if (metrics) {
                payload.performance =
                    metrics;
            }

            return (
                (
                    this.config.compactJson
                        ? JSON.stringify(
                            payload
                        )
                        : JSON.stringify(
                            payload,
                            null,
                            2
                        )
                ) +
                "\n"
            );
        }

        return new TerminalFormatter(
            this.config
        ).outputHumanReadable(
            report,
            metrics
        );
    }

    writeOutput(output) {
        if (this.config.outputFile) {
            fs.writeFileSync(
                this.config.outputFile,
                output,
                "utf8"
            );

            if (!this.config.quiet) {
                process.stdout.write(
                    `Wrote output to ${this.config.outputFile}\n`
                );
            }

            return;
        }

        if (!this.config.quiet) {
            process.stdout.write(
                output
            );
        }
    }

    showVersion() {
        process.stdout.write(
            `Socket Statistics Tool JS ${VERSION}\n`
        );

        process.stdout.write(
            `Node ${process.version}\n`
        );
    }

    showHelp() {
        const scriptName =
            path.basename(
                process.argv[1] ||
                "main.js"
            );

        process.stdout.write(
            [
                `Socket Statistics Tool JS ${VERSION}`,
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
                "  --tcp-states            Inspect TCP connection states",
                "  --processes             Find processes owning sockets",
                "  --process-limit N       Maximum displayed processes",
                "  --watch                 Sample continuously",
                "  --interval SECONDS      Sampling interval",
                "  --count N               Number of samples; 0 means unlimited",
                "  --csv                   Write CSV samples",
                "  --threshold-tcp N       Alert when TCP in-use exceeds N",
                "  --threshold-established N  Alert on established TCP count",
                "  --threshold-timewait N  Alert on TIME_WAIT count",
                "  --threshold-orphan N    Alert on orphan count",
                "  --threshold-retrans N   Alert on retransmits per second",
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
            ].join("\n")
        );
    }

    async execute() {
        this.loadConfigFile();
        this.validateConfig();
        if (this.config.help) {
            this.showHelp();
            return 0;
        }
        if (this.config.version) {
            this.showVersion();
            return 0;
        }
        const session = new MonitoringSession(this);
        this.session = session;
        await session.run();
        return this.shutdownRequested ? 130 : 0;
    }

    async run() {
        this.installSignalHandlers();
        try {
            this.parseArgs();
            process.exitCode = await this.execute();
        } catch (err) {
            this.metrics.stop();
            this.logger.error(err && err.message ? err.message : String(err));
            process.exitCode = 1;
        }
    }

}

if (require.main === module) {
    process.stdout.on("error", err => {
        if (err.code === "EPIPE") {
            process.exit(0);
        }
        process.stderr.write(`${err.message}\n`);
        process.exitCode = 1;
    });
    new SocketStatsTool().run();
}
