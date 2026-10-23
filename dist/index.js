import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { request as httpRequest } from "node:http";
import { BlockList, isIP } from "node:net";
import path from "node:path";
import { Client } from "ssh2";
import { Type } from "typebox";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { readWebhookBodyOrReject } from "openclaw/plugin-sdk/webhook-request-guards";
import { AccessVault, buildApiBasicAccount, buildApiTokenAccount, buildWebHttpsAccount, buildWebViaSshAccount, isHttpPathAllowed, normalizeHttpPath, requireAccessName, } from "./access.js";
import { parseSmartAccessInput } from "./smart-import.js";
import { executeSshCommand, validateExecInput } from "./ssh-exec.js";
import { createRemoteFile, createRemoteDirectory, moveRemoteFile } from "./file-ops.js";
const DEFAULT_READY_TIMEOUT_MS = 15_000;
const DEFAULT_MAX_FILE_BYTES = 1024 * 1024;
const DEFAULT_CREDENTIAL_TTL_SECONDS = 24 * 60 * 60;
const DEFAULT_TICKET_TTL_SECONDS = 10 * 60;
const DEFAULT_TUNNEL_STARTUP_TIMEOUT_MS = 25_000;
const DISK_AUDIT_TIMEOUT_MS = 180_000;
const MAX_REMOTE_COMMAND_OUTPUT_BYTES = 1024 * 1024;
export const ACCESS_BROKER_VERSION = "0.8.2";
const SSH_STAGE_PATH_PREFIX = "/access-broker/ssh/";
const ACCESS_PATH_PREFIX = "/access-broker/credential/";
const ACCOUNT_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/i;
const USERNAME_PATTERN = /^[a-z0-9._-]{1,128}$/i;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const BLOCKED_SSH_DESTINATIONS = new BlockList();
BLOCKED_SSH_DESTINATIONS.addSubnet("0.0.0.0", 8, "ipv4");
BLOCKED_SSH_DESTINATIONS.addSubnet("127.0.0.0", 8, "ipv4");
BLOCKED_SSH_DESTINATIONS.addSubnet("169.254.0.0", 16, "ipv4");
BLOCKED_SSH_DESTINATIONS.addSubnet("224.0.0.0", 4, "ipv4");
BLOCKED_SSH_DESTINATIONS.addAddress("::", "ipv6");
BLOCKED_SSH_DESTINATIONS.addAddress("::1", "ipv6");
BLOCKED_SSH_DESTINATIONS.addSubnet("fe80::", 10, "ipv6");
BLOCKED_SSH_DESTINATIONS.addSubnet("ff00::", 8, "ipv6");
function requireString(value, label) {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error(`${label} must be a non-empty string`);
    }
    return value;
}
function requireInteger(value, label, min, max) {
    if (!Number.isInteger(value) || value < min || value > max) {
        throw new Error(`${label} must be an integer from ${min} to ${max}`);
    }
    return value;
}
function optionalHttpsOrigin(value, label) {
    if (value === undefined) {
        return undefined;
    }
    const text = requireString(value, label).trim();
    let parsed;
    try {
        parsed = new URL(text);
    }
    catch {
        throw new Error(`${label} must be an HTTPS origin`);
    }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
        throw new Error(`${label} must be a bare HTTPS origin`);
    }
    return parsed.origin;
}
function requireParamsRecord(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("tool parameters must be an object");
    }
    return value;
}
export function normalizeHostKeySha256(value) {
    const trimmed = value.trim();
    if (/^[a-f0-9]{64}$/i.test(trimmed)) {
        return trimmed.toLowerCase();
    }
    if (/^SHA256:[A-Za-z0-9+/]+={0,2}$/.test(trimmed)) {
        const decoded = Buffer.from(trimmed.slice("SHA256:".length), "base64");
        if (decoded.length === 32) {
            return decoded.toString("hex");
        }
    }
    throw new Error("hostKeySha256 must be a 64-character hex digest or OpenSSH SHA256: fingerprint");
}
export function normalizeRemotePath(value) {
    if (!value.startsWith("/") || value.includes("\0")) {
        throw new Error("remote path must be absolute and contain no NUL bytes");
    }
    return path.posix.normalize(value);
}
export function isPathWithinRoots(candidate, roots) {
    const normalized = normalizeRemotePath(candidate);
    return roots.some((root) => {
        const normalizedRoot = normalizeRemotePath(root);
        return normalized === normalizedRoot || normalized.startsWith(`${normalizedRoot}/`);
    });
}
function comparableSshHost(value) {
    return value.trim().replace(/^\[|\]$/g, "").toLowerCase();
}
export function resolveConfiguredSshImport(imported, accounts) {
    const named = accounts[imported.name];
    if (named)
        return { name: imported.name, account: named };
    const matches = Object.entries(accounts).filter(([, account]) => comparableSshHost(imported.host) === comparableSshHost(account.host) &&
        imported.port === account.port &&
        imported.username === account.username);
    if (matches.length > 1) {
        throw new Error("Найдено несколько SSH-профилей с такими хостом, портом и логином. Укажите ID подключения.");
    }
    const match = matches[0];
    return match ? { name: match[0], account: match[1] } : undefined;
}
export function assertConfiguredSshImportMatches(imported, configured) {
    if (comparableSshHost(imported.host) !== comparableSshHost(configured.host) ||
        imported.port !== configured.port ||
        imported.username !== configured.username) {
        throw new Error("Этот ID уже закреплён за другим SSH-хостом, портом или логином.");
    }
    for (const root of imported.allowedRoots) {
        if (!isPathWithinRoots(root, configured.allowedRoots)) {
            throw new Error("Указанный каталог выходит за разрешённые корни настроенного SSH-подключения.");
        }
    }
    if (imported.expectedFingerprint &&
        normalizeHostKeySha256(imported.expectedFingerprint) !== configured.hostKeySha256Hex) {
        throw new Error("Указанный SSH-отпечаток не совпадает с закреплённым отпечатком подключения.");
    }
}
export function replaceExactlyOnce(content, find, replacement) {
    if (find.length === 0) {
        throw new Error("find text must not be empty");
    }
    const first = content.indexOf(find);
    if (first < 0) {
        throw new Error("find text does not occur in the remote file");
    }
    if (content.indexOf(find, first + find.length) >= 0) {
        throw new Error("find text occurs more than once in the remote file");
    }
    return content.slice(0, first) + replacement + content.slice(first + find.length);
}
function parseAccount(name, value) {
    const rootsRaw = value.allowedRoots;
    if (!Array.isArray(rootsRaw) || rootsRaw.length === 0 || rootsRaw.length > 16) {
        throw new Error(`accounts.${name}.allowedRoots must contain 1-16 paths`);
    }
    const allowedRoots = [...new Set(rootsRaw.map((entry, index) => {
            const root = normalizeRemotePath(requireString(entry, `accounts.${name}.allowedRoots[${index}]`));
            if (root === "/") {
                throw new Error(`accounts.${name}.allowedRoots must not contain /`);
            }
            return root.replace(/\/$/, "");
        }))];
    return {
        host: requireString(value.host, `accounts.${name}.host`),
        port: requireInteger(value.port, `accounts.${name}.port`, 1, 65_535),
        username: requireString(value.username, `accounts.${name}.username`),
        configuredPassword: value.password === undefined
            ? undefined
            : requireString(value.password, `accounts.${name}.password`),
        hostKeySha256Hex: normalizeHostKeySha256(requireString(value.hostKeySha256, `accounts.${name}.hostKeySha256`)),
        allowedRoots,
        readyTimeoutMs: value.readyTimeoutMs === undefined
            ? DEFAULT_READY_TIMEOUT_MS
            : requireInteger(value.readyTimeoutMs, `accounts.${name}.readyTimeoutMs`, 1000, 60_000),
        maxFileBytes: value.maxFileBytes === undefined
            ? DEFAULT_MAX_FILE_BYTES
            : requireInteger(value.maxFileBytes, `accounts.${name}.maxFileBytes`, 1024, 8 * 1024 * 1024),
    };
}
export function normalizeDynamicHost(value) {
    const host = value.trim().replace(/^\[|\]$/g, "").toLowerCase();
    if (!host || host.includes("://") || /[\s/@\\]/.test(host)) {
        throw new Error("SSH host must be a hostname or IP address without scheme, path, or credentials");
    }
    if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
        throw new Error("loopback and local-only SSH hosts are not allowed");
    }
    const ipVersion = isIP(host);
    if (ipVersion === 4) {
        if (BLOCKED_SSH_DESTINATIONS.check(host, "ipv4")) {
            throw new Error("loopback, link-local, unspecified, and multicast SSH hosts are not allowed");
        }
        return host;
    }
    if (ipVersion === 6) {
        if (host.startsWith("::ffff:") || BLOCKED_SSH_DESTINATIONS.check(host, "ipv6")) {
            throw new Error("loopback, link-local, unspecified, and multicast SSH hosts are not allowed");
        }
        return host;
    }
    if (/^[0-9.]+$/.test(host)) {
        throw new Error("non-canonical numeric SSH hosts are not allowed");
    }
    if (!HOSTNAME_PATTERN.test(host)) {
        throw new Error("SSH host is not a valid hostname or IP address");
    }
    return host;
}
export function buildDynamicAccount(input) {
    const username = input.username.trim();
    if (!USERNAME_PATTERN.test(username)) {
        throw new Error("SSH username may contain only letters, digits, dot, underscore, and hyphen");
    }
    const allowedRoots = [...new Set(input.allowedRoots.map((entry) => {
            const normalized = normalizeRemotePath(entry.trim());
            if (normalized === "/") {
                throw new Error("allowed root must not be /");
            }
            const root = normalized.replace(/\/$/, "");
            if (root === "/") {
                throw new Error("allowed root must not be /");
            }
            return root;
        }))];
    if (allowedRoots.length < 1 || allowedRoots.length > 16) {
        throw new Error("allowedRoots must contain 1-16 absolute paths");
    }
    return {
        host: normalizeDynamicHost(input.host),
        port: requireInteger(input.port, "port", 1, 65_535),
        username,
        hostKeySha256Hex: normalizeHostKeySha256(input.hostKeySha256),
        allowedRoots,
        readyTimeoutMs: DEFAULT_READY_TIMEOUT_MS,
        maxFileBytes: DEFAULT_MAX_FILE_BYTES,
    };
}
function parseConfig(value) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("plugin config must be an object");
    }
    const raw = value;
    const rawAccounts = raw.accounts;
    if (rawAccounts !== undefined && (!rawAccounts || typeof rawAccounts !== "object" || Array.isArray(rawAccounts))) {
        throw new Error("accounts must be an object");
    }
    const entries = Object.entries((rawAccounts ?? {}));
    const accounts = {};
    for (const [name, account] of entries) {
        if (!ACCOUNT_NAME_PATTERN.test(name)) {
            throw new Error(`invalid account name: ${name}`);
        }
        accounts[name] = parseAccount(name, account);
    }
    let quickTunnelRaw = {};
    if (raw.quickTunnel !== undefined) {
        if (!raw.quickTunnel || typeof raw.quickTunnel !== "object" || Array.isArray(raw.quickTunnel)) {
            throw new Error("quickTunnel must be an object");
        }
        quickTunnelRaw = raw.quickTunnel;
    }
    const quickTunnelEnabled = quickTunnelRaw.enabled === undefined ? false : quickTunnelRaw.enabled;
    if (typeof quickTunnelEnabled !== "boolean") {
        throw new Error("quickTunnel.enabled must be boolean");
    }
    const executable = quickTunnelRaw.executable === undefined
        ? undefined
        : requireString(quickTunnelRaw.executable, "quickTunnel.executable");
    if (executable !== undefined && !path.isAbsolute(executable)) {
        throw new Error("quickTunnel.executable must be an absolute path");
    }
    return {
        accounts,
        allowDynamicAccounts: raw.allowDynamicAccounts === undefined
            ? false
            : (() => {
                if (typeof raw.allowDynamicAccounts !== "boolean") {
                    throw new Error("allowDynamicAccounts must be boolean");
                }
                return raw.allowDynamicAccounts;
            })(),
        publicBaseUrl: optionalHttpsOrigin(raw.publicBaseUrl, "publicBaseUrl"),
        quickTunnel: {
            enabled: quickTunnelEnabled,
            executable,
            startupTimeoutMs: quickTunnelRaw.startupTimeoutMs === undefined
                ? DEFAULT_TUNNEL_STARTUP_TIMEOUT_MS
                : requireInteger(quickTunnelRaw.startupTimeoutMs, "quickTunnel.startupTimeoutMs", 5000, 60_000),
        },
        credentialTtlSeconds: raw.credentialTtlSeconds === undefined
            ? DEFAULT_CREDENTIAL_TTL_SECONDS
            : requireInteger(raw.credentialTtlSeconds, "credentialTtlSeconds", 60, 7 * 24 * 60 * 60),
        ticketTtlSeconds: raw.ticketTtlSeconds === undefined
            ? DEFAULT_TICKET_TTL_SECONDS
            : requireInteger(raw.ticketTtlSeconds, "ticketTtlSeconds", 60, 1800),
    };
}
function sha256(buffer) {
    return createHash("sha256").update(buffer).digest("hex");
}
function requireAccountName(value) {
    const name = requireString(value, "account").trim();
    if (!ACCOUNT_NAME_PATTERN.test(name)) {
        throw new Error("account must start with a letter and contain only letters, digits, underscore, or hyphen");
    }
    return name;
}
const MODERN_SERVER_HOST_KEY_ALGORITHMS = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
];
function displayHostKeyFingerprint(hexDigest) {
    return `SHA256:${Buffer.from(hexDigest, "hex").toString("base64").replace(/=+$/, "")}`;
}
async function connect(account, password, signal) {
    const client = new Client();
    const expected = Buffer.from(account.hostKeySha256Hex, "hex");
    const connection = new Promise((resolve, reject) => {
        const cleanup = () => {
            client.off("ready", onReady);
            client.off("error", onError);
            signal?.removeEventListener("abort", onAbort);
        };
        const onReady = () => {
            cleanup();
            resolve(client);
        };
        const onError = (error) => {
            cleanup();
            reject(error);
        };
        const onAbort = () => {
            cleanup();
            client.end();
            reject(new Error("SSH operation aborted"));
        };
        client.once("ready", onReady);
        client.once("error", onError);
        signal?.addEventListener("abort", onAbort, { once: true });
    });
    const options = {
        host: account.host,
        port: account.port,
        username: account.username,
        password,
        readyTimeout: account.readyTimeoutMs,
        algorithms: {
            serverHostKey: [...MODERN_SERVER_HOST_KEY_ALGORITHMS],
        },
        hostHash: "sha256",
        hostVerifier(hashedKey) {
            if (!/^[a-f0-9]{64}$/i.test(hashedKey)) {
                return false;
            }
            const actual = Buffer.from(hashedKey, "hex");
            return actual.length === expected.length && timingSafeEqual(actual, expected);
        },
        tryKeyboard: false,
    };
    client.connect(options);
    return await connection;
}
export function assertDiskAuditAccount(account) {
    if (account.username !== "root") {
        throw new Error("disk audit requires an SSH connection authenticated as root");
    }
}
export function buildDiskAuditCommand() {
    return [
        "export LC_ALL=C",
        "printf '__FILESYSTEM_BYTES__\\n'",
        "df -B1 -T / 2>&1",
        "printf '__FILESYSTEM_INODES__\\n'",
        "df -i / 2>&1",
        "printf '__ROOT_MOUNT__\\n'",
        "findmnt -no SOURCE,FSTYPE,OPTIONS / 2>&1 || true",
        "printf '__DIRECTORY_USAGE_BYTES__\\n'",
        "du -x -B1 --max-depth=2 / 2>/dev/null | sort -nr | head -200",
        "printf '__LARGEST_FILES_BYTES__\\n'",
        "find / -xdev -type f -size +52428800c -printf '%s\\t%p\\n' 2>/dev/null | sort -nr | head -120",
        "printf '__DELETED_OPEN_FILES__\\n'",
        "if command -v lsof >/dev/null 2>&1; then lsof -nP +L1 2>/dev/null | head -120; else printf 'lsof unavailable\\n'; fi",
    ].join("; ");
}
async function executeFixedRemoteCommand(client, command, signal) {
    return await new Promise((resolve, reject) => {
        let channel;
        let settled = false;
        let bytes = 0;
        let truncated = false;
        const stdout = [];
        const stderr = [];
        const append = (target, chunk) => {
            const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            const remaining = MAX_REMOTE_COMMAND_OUTPUT_BYTES - bytes;
            if (remaining <= 0) {
                truncated = true;
                return;
            }
            target.push(data.subarray(0, remaining));
            bytes += Math.min(data.length, remaining);
            if (data.length > remaining) {
                truncated = true;
            }
        };
        const cleanup = () => {
            clearTimeout(timer);
            signal?.removeEventListener("abort", onAbort);
        };
        const finish = (error, report) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            if (error)
                reject(error);
            else
                resolve({ report: report, truncated });
        };
        const onAbort = () => {
            channel?.close();
            finish(new Error("SSH disk audit aborted"));
        };
        const timer = setTimeout(() => {
            channel?.close();
            finish(new Error("SSH disk audit timed out"));
        }, DISK_AUDIT_TIMEOUT_MS);
        signal?.addEventListener("abort", onAbort, { once: true });
        client.exec(command, (error, stream) => {
            if (error) {
                finish(error);
                return;
            }
            channel = stream;
            stream.on("data", (chunk) => append(stdout, chunk));
            stream.stderr.on("data", (chunk) => append(stderr, chunk));
            stream.once("error", (streamError) => finish(streamError));
            stream.once("close", (code, remoteSignal) => {
                const out = Buffer.concat(stdout).toString("utf8");
                const err = Buffer.concat(stderr).toString("utf8");
                if (code !== 0) {
                    finish(new Error(`SSH disk audit failed (code ${code ?? "unknown"}, signal ${remoteSignal ?? "none"}): ${err.slice(0, 4096)}`));
                    return;
                }
                finish(undefined, err ? `${out}\\n__STDERR__\\n${err}` : out);
            });
        });
    });
}
export async function scanHostKey(host, port, timeoutMs = DEFAULT_READY_TIMEOUT_MS) {
    const client = new Client();
    return await new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error, digest) => {
            if (settled) {
                return;
            }
            settled = true;
            clearTimeout(timer);
            if (error) {
                reject(error);
            }
            else {
                resolve(digest);
            }
            // ssh2 raises its expected "Host denied" error after hostVerifier
            // returns false. Keep the error listener installed until that event has
            // been consumed and close only after the verifier stack unwinds.
            setImmediate(() => client.end());
        };
        const timer = setTimeout(() => finish(new Error("SSH host-key scan timed out")), timeoutMs);
        client.on("error", (error) => {
            if (!settled) {
                finish(new Error(`SSH host-key scan failed: ${error.message}`));
            }
        });
        client.connect({
            host,
            port,
            username: "openclaw-host-key-probe",
            readyTimeout: timeoutMs,
            algorithms: { serverHostKey: [...MODERN_SERVER_HOST_KEY_ALGORITHMS] },
            hostHash: "sha256",
            hostVerifier(hashedKey) {
                if (!/^[a-f0-9]{64}$/i.test(hashedKey)) {
                    finish(new Error("SSH server returned an invalid host-key digest"));
                    return false;
                }
                finish(undefined, hashedKey.toLowerCase());
                return false;
            },
        });
    });
}
const MAX_ACTIVE_FORM_NONCES = 8;
const activeExec = new Set();
function requireSessionKey(value) {
    if (typeof value !== "string" || value.length === 0) {
        throw new Error("Access Broker requires an active bound session; use /accesslogin in this conversation first");
    }
    return value;
}
function credentialKey(account, sessionKey) {
    return `${sessionKey}\0${account}`;
}
export class RuntimeCredentialVault {
    credentialTtlSeconds;
    ticketTtlSeconds;
    credentials = new Map();
    tickets = new Map();
    constructor(credentialTtlSeconds, ticketTtlSeconds) {
        this.credentialTtlSeconds = credentialTtlSeconds;
        this.ticketTtlSeconds = ticketTtlSeconds;
    }
    sweep(now = Date.now()) {
        for (const [name, credential] of this.credentials) {
            if (credential.expiresAt <= now) {
                this.credentials.delete(name);
            }
        }
        for (const [token, ticket] of this.tickets) {
            if (ticket.expiresAt <= now) {
                this.tickets.delete(token);
            }
        }
    }
    createTicket(accountName, sessionKey, presetAccount) {
        this.sweep();
        for (const [token, ticket] of this.tickets) {
            if (ticket.accountName === accountName && ticket.sessionKey === sessionKey) {
                this.tickets.delete(token);
            }
        }
        const token = randomBytes(32).toString("hex");
        const expiresAt = Date.now() + this.ticketTtlSeconds * 1000;
        this.tickets.set(token, { accountName, presetAccount, expiresAt, sessionKey });
        return { token, expiresAt };
    }
    ticket(token) {
        this.sweep();
        return this.tickets.get(token);
    }
    issueFormNonce(token) {
        this.sweep();
        const ticket = this.tickets.get(token);
        if (!ticket) {
            throw new Error("SSH login ticket is invalid or expired");
        }
        const nonce = randomBytes(32).toString("hex");
        const hashes = ticket.formNonceSha256s ?? [];
        hashes.push(sha256(Buffer.from(nonce, "utf8")));
        ticket.formNonceSha256s = hashes.slice(-MAX_ACTIVE_FORM_NONCES);
        return nonce;
    }
    verifyFormNonce(token, nonce) {
        this.sweep();
        const ticket = this.tickets.get(token);
        const expectedHashes = ticket?.formNonceSha256s;
        if (!expectedHashes?.length || !/^[a-f0-9]{64}$/.test(nonce)) {
            return false;
        }
        const actual = Buffer.from(sha256(Buffer.from(nonce, "utf8")), "hex");
        const matchIndex = expectedHashes.findIndex((expectedHex) => {
            const expected = Buffer.from(expectedHex, "hex");
            return actual.length === expected.length && timingSafeEqual(actual, expected);
        });
        if (matchIndex >= 0 && ticket) {
            expectedHashes.splice(matchIndex, 1);
            if (expectedHashes.length === 0)
                ticket.formNonceSha256s = undefined;
        }
        return matchIndex >= 0;
    }
    stageDynamic(token, name, account, password, discoverHome = false) {
        this.sweep();
        const ticket = this.tickets.get(token);
        if (!ticket || ticket.accountName || ticket.presetAccount) {
            throw new Error("dynamic SSH login ticket is invalid or expired");
        }
        ticket.stagedDynamic = { name, account, ...(discoverHome ? { discoverHome: true } : {}) };
        if (password !== undefined) {
            if (!password || password.length > 4096)
                throw new Error("SSH password is empty or too long");
            ticket.stagedPassword = password;
        }
    }
    stagePresetPassword(token, password) {
        this.sweep();
        const ticket = this.tickets.get(token);
        if (!ticket?.accountName || !ticket.presetAccount || ticket.stagedDynamic) {
            throw new Error("configured SSH login ticket is invalid or expired");
        }
        if (!password || password.length > 4096) {
            throw new Error("SSH password is empty or too long");
        }
        ticket.stagedPassword = password;
    }
    submit(token, password, execEnabled = false) {
        this.sweep();
        const ticket = this.tickets.get(token);
        if (!ticket) {
            throw new Error("login ticket is invalid or expired");
        }
        const accountName = ticket.stagedDynamic?.name ?? ticket.accountName;
        const account = ticket.stagedDynamic?.account ?? ticket.presetAccount;
        if (!accountName || !account) {
            throw new Error("SSH connection details must be confirmed before submitting a password");
        }
        const resolvedPassword = password ?? ticket.stagedPassword;
        if (!resolvedPassword || resolvedPassword.length > 4096) {
            throw new Error("SSH password is empty or too long");
        }
        this.tickets.delete(token);
        const expiresAt = Date.now() + this.credentialTtlSeconds * 1000;
        this.credentials.set(credentialKey(accountName, ticket.sessionKey), {
            password: resolvedPassword,
            expiresAt,
            sessionKey: ticket.sessionKey,
            account,
            dynamic: Boolean(ticket.stagedDynamic),
            execEnabled: execEnabled === true,
        });
        return { account: accountName, expiresAt };
    }
    resolve(accountName, configuredAccount, sessionKey) {
        this.sweep();
        if (configuredAccount?.configuredPassword !== undefined && !this.credentials.has(credentialKey(accountName, sessionKey))) {
            return {
                password: configuredAccount.configuredPassword,
                expiresAt: Number.MAX_SAFE_INTEGER,
                sessionKey,
                account: configuredAccount,
                dynamic: false,
            };
        }
        const credential = this.credentials.get(credentialKey(accountName, sessionKey));
        if (!credential) {
            const known = configuredAccount ? "credential is not loaded" : "temporary connection is unknown or expired";
            throw new Error(`SSH ${known} for account ${accountName}; use /accesslogin in this conversation first`);
        }
        return credential;
    }
    status(accountName, configuredAccount, sessionKey) {
        this.sweep();
        if (configuredAccount?.configuredPassword !== undefined && !this.credentials.has(credentialKey(accountName, sessionKey))) {
            return { ready: true, dynamic: false };
        }
        const credential = this.credentials.get(credentialKey(accountName, sessionKey));
        return credential
            ? { ready: true, expiresAt: credential.expiresAt, dynamic: credential.dynamic, execEnabled: credential.execEnabled === true }
            : { ready: false };
    }
    list(configuredAccounts, sessionKey) {
        this.sweep();
        const summaries = new Map();
        for (const [accountName, account] of Object.entries(configuredAccounts)) {
            const status = this.status(accountName, account, sessionKey);
            summaries.set(accountName, {
                account: accountName,
                host: account.host,
                port: account.port,
                username: account.username,
                allowedRoots: account.allowedRoots,
                dynamic: false,
                ready: status.ready,
                execEnabled: status.execEnabled === true,
                ...(status.expiresAt ? { expiresAt: status.expiresAt } : {}),
            });
        }
        for (const [key, credential] of this.credentials) {
            if (credential.sessionKey !== sessionKey || !credential.dynamic) {
                continue;
            }
            const accountName = key.slice(sessionKey.length + 1);
            if (!accountName || summaries.has(accountName)) {
                continue;
            }
            summaries.set(accountName, {
                account: accountName,
                host: credential.account.host,
                port: credential.account.port,
                username: credential.account.username,
                allowedRoots: credential.account.allowedRoots,
                dynamic: true,
                ready: true,
                execEnabled: credential.execEnabled === true,
                expiresAt: credential.expiresAt,
            });
        }
        return [...summaries.values()].sort((a, b) => a.account.localeCompare(b.account));
    }
    forget(accountName, sessionKey) {
        const removed = this.credentials.delete(credentialKey(accountName, sessionKey));
        for (const [token, ticket] of this.tickets) {
            if (ticket.sessionKey === sessionKey &&
                (ticket.accountName === accountName || ticket.stagedDynamic?.name === accountName)) {
                this.tickets.delete(token);
            }
        }
        return removed;
    }
    clear() {
        this.credentials.clear();
        this.tickets.clear();
    }
}
/**
 * Plugin command and agent-tool registries can coexist as separate runtime
 * generations. Keep their short-lived credentials in one process-local vault
 * while preserving the existing per-session keys inside each vault.
 */
export function getSharedCredentialVaults(credentialTtlSeconds, ticketTtlSeconds) {
    const root = globalThis;
    const current = root.__openclawAccessBrokerSharedVaultsV1;
    if (current && current.schemaVersion === 2 &&
        current.credentialTtlSeconds === credentialTtlSeconds &&
        current.ticketTtlSeconds === ticketTtlSeconds) {
        return current;
    }
    if (current) {
        clearInterval(current.sweepTimer);
        current.vault.clear();
        current.accessVault.clear();
    }
    const vault = new RuntimeCredentialVault(credentialTtlSeconds, ticketTtlSeconds);
    const accessVault = new AccessVault(credentialTtlSeconds, ticketTtlSeconds);
    const state = {
        schemaVersion: 2,
        credentialTtlSeconds,
        ticketTtlSeconds,
        vault,
        accessVault,
        sweepTimer: setInterval(() => {
            vault.sweep();
            accessVault.sweep();
        }, 30_000),
    };
    state.sweepTimer.unref();
    root.__openclawAccessBrokerSharedVaultsV1 = state;
    return state;
}
function resolveConnection(config, vault, accountName, sessionKey) {
    const credential = vault.resolve(accountName, config.accounts[accountName], sessionKey);
    return { account: credential.account, password: credential.password };
}
class QuickTunnelManager {
    configuredOrigin;
    config;
    localGatewayOrigin;
    process;
    origin;
    starting;
    constructor(configuredOrigin, config, localGatewayOrigin) {
        this.configuredOrigin = configuredOrigin;
        this.config = config;
        this.localGatewayOrigin = localGatewayOrigin;
    }
    async ensure() {
        if (this.configuredOrigin) {
            return this.configuredOrigin;
        }
        if (this.origin && this.process?.exitCode === null) {
            return this.origin;
        }
        if (this.starting) {
            return await this.starting;
        }
        if (!this.config.enabled || !this.config.executable) {
            throw new Error("no HTTPS publicBaseUrl is configured and quickTunnel is disabled");
        }
        this.starting = this.start();
        try {
            return await this.starting;
        }
        finally {
            this.starting = undefined;
        }
    }
    async start() {
        const child = spawn(this.config.executable, [
            "tunnel",
            "--no-autoupdate",
            "--protocol",
            "http2",
            "--url",
            this.localGatewayOrigin,
        ], {
            stdio: ["ignore", "pipe", "pipe"],
            env: { PATH: process.env.PATH ?? "/usr/bin:/bin" },
        });
        this.process = child;
        return await new Promise((resolve, reject) => {
            let settled = false;
            let observed = "";
            const finish = (error, origin) => {
                if (settled) {
                    return;
                }
                settled = true;
                clearTimeout(timer);
                child.stdout?.off("data", onData);
                child.stderr?.off("data", onData);
                child.off("error", onError);
                child.off("exit", onExitBeforeReady);
                if (error) {
                    child.kill("SIGTERM");
                    this.process = undefined;
                    reject(error);
                    return;
                }
                this.origin = origin;
                child.once("exit", () => {
                    if (this.process === child) {
                        this.process = undefined;
                        this.origin = undefined;
                    }
                });
                resolve(origin);
            };
            const onData = (chunk) => {
                observed = (observed + chunk.toString()).slice(-16_384);
                const match = observed.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/i);
                if (match) {
                    finish(undefined, match[0].toLowerCase());
                }
            };
            const onError = (error) => finish(new Error(`quick tunnel failed to start: ${error.message}`));
            const onExitBeforeReady = (code) => finish(new Error(`quick tunnel exited before publishing HTTPS (code ${code ?? "unknown"})`));
            const timer = setTimeout(() => finish(new Error("quick tunnel did not publish HTTPS before timeout")), this.config.startupTimeoutMs);
            child.stdout?.on("data", onData);
            child.stderr?.on("data", onData);
            child.once("error", onError);
            child.once("exit", onExitBeforeReady);
        });
    }
    async stop() {
        const child = this.process;
        this.process = undefined;
        this.origin = undefined;
        if (!child || child.exitCode !== null) {
            return;
        }
        child.kill("SIGTERM");
        await new Promise((resolve) => {
            const timer = setTimeout(() => {
                child.kill("SIGKILL");
                resolve();
            }, 2000);
            child.once("exit", () => {
                clearTimeout(timer);
                resolve();
            });
        });
    }
}
async function openSftp(client) {
    return await new Promise((resolve, reject) => {
        client.sftp((error, sftp) => {
            if (error) {
                reject(error);
                return;
            }

            // ssh2 может отдельно эмитить ошибку самого SFTP-канала.
            // Без listener EventEmitter завершает весь процесс Node.js.
            // Ошибки конкретных SFTP-запросов при этом по-прежнему
            // передаются их callback-ам и обрабатываются вызывающим кодом.
            sftp.on("error", () => {});

            resolve(sftp);
        });
    });
}
async function sftpRealpath(sftp, remotePath) {
    return await new Promise((resolve, reject) => {
        sftp.realpath(remotePath, (error, resolved) => error ? reject(error) : resolve(resolved));
    });
}
async function sftpReadFile(sftp, remotePath) {
    return await new Promise((resolve, reject) => {
        sftp.readFile(remotePath, (error, data) => error ? reject(error) : resolve(data));
    });
}
async function sftpWriteFile(sftp, remotePath, data, options = {}) {
    return await new Promise((resolve, reject) => {
        sftp.writeFile(remotePath, data, options, (error) => error ? reject(error) : resolve());
    });
}
async function sftpLstat(sftp, remotePath) {
    return await new Promise((resolve, reject) => {
        sftp.lstat(remotePath, (error, attrs) => {
            if (error) {
                reject(error);
                return;
            }
            resolve({ mode: attrs.mode, size: attrs.size });
        });
    });
}
async function sftpChmod(sftp, remotePath, mode) {
    return await new Promise((resolve, reject) => {
        sftp.chmod(remotePath, mode, (error) => error ? reject(error) : resolve());
    });
}
async function sftpReaddir(sftp, remotePath) {
    return await new Promise((resolve, reject) => {
        sftp.readdir(remotePath, (error, entries) => {
            if (error) {
                reject(error);
                return;
            }
            resolve(entries.map((entry) => ({
                name: entry.filename,
                mode: entry.attrs.mode,
                size: entry.attrs.size,
            })));
        });
    });
}
async function resolveAllowedPath(sftp, account, requestedPath) {
    const normalized = normalizeRemotePath(requestedPath);
    if (!isPathWithinRoots(normalized, account.allowedRoots)) {
        throw new Error("remote path is outside configured allowed roots");
    }
    const [resolved, ...resolvedRoots] = await Promise.all([
        sftpRealpath(sftp, normalized),
        ...account.allowedRoots.map((root) => sftpRealpath(sftp, root)),
    ]);
    if (!isPathWithinRoots(resolved, resolvedRoots)) {
        throw new Error("remote path resolves outside configured allowed roots");
    }
    return resolved;
}
async function withSftp(account, password, signal, run) {
    const client = await connect(account, password, signal);
    try {
        const sftp = await openSftp(client);
        try {
            return await run(sftp);
        }
        finally {
            sftp.end();
        }
    }
    finally {
        client.end();
    }
}
export async function discoverSshRoots(account, password, requestedRoots, signal) {
    const candidates = requestedRoots.length > 0 ? requestedRoots : ["."];
    const resolved = await withSftp(account, password, signal, async (sftp) => (await Promise.all(candidates.map((candidate) => sftpRealpath(sftp, candidate)))));
    const roots = [...new Set(resolved.map((candidate) => normalizeRemotePath(candidate).replace(/\/$/, "")))];
    if (roots.length === 0 || roots.length > 16 || roots.some((root) => root === "" || root === "/")) {
        throw new Error("SSH home resolved to an unsafe root; specify a narrower absolute directory");
    }
    return roots;
}
function textResult(details) {
    return {
        content: [{ type: "text", text: JSON.stringify(details) }],
        details,
    };
}
function remoteEntryType(mode) {
    switch (mode & 0o170000) {
        case 0o100000:
            return "file";
        case 0o040000:
            return "directory";
        case 0o120000:
            return "symlink";
        default:
            return "other";
    }
}
function escapeHtml(value) {
    return value
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#39;");
}
function sendHtml(res, statusCode, body) {
    res.statusCode = statusCode;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.end(body);
}
function loginPage(body) {
    return `<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access Broker</title><style>
body{font-family:system-ui,sans-serif;background:#111827;color:#f9fafb;margin:0;padding:20px}main{max-width:560px;margin:4vh auto;background:#1f2937;padding:24px;border-radius:16px}label{display:block;margin:18px 0 7px;font-weight:650}input,textarea,select,button{box-sizing:border-box;width:100%;font:inherit;padding:13px;border-radius:10px}input,textarea,select{border:1px solid #4b5563;background:#111827;color:#fff}textarea{min-height:88px;resize:vertical}button{margin-top:20px;border:0;background:#22c55e;color:#052e16;font-weight:750}small,.muted{color:#9ca3af}.card{background:#111827;padding:14px;border-radius:10px;overflow-wrap:anywhere}.fingerprint{font-family:ui-monospace,monospace;font-size:13px;color:#86efac}.version{margin-top:24px;text-align:center;color:#6b7280;font-size:12px}</style></head>
<body><main>${body}<footer class="version">Access Broker v${ACCESS_BROKER_VERSION}</footer></main></body></html>`;
}
export function parseExecConsent(form) {
    const values = form.getAll("sshExec");
    if (values.length === 0)
        return false;
    if (values.length !== 1 || values[0] !== "allow")
        throw new Error("Invalid SSH command permission");
    return true;
}
export function sshExecConsentHtml() {
    return `<label><input style="width:auto" type="checkbox" name="sshExec" value="allow"> Разрешить выполнение SSH-команд в этой сессии</label><small>По умолчанию выключено. Команды выполняются с полными правами указанного SSH-пользователя. Каталоги SFTP не ограничивают shell. Для разработки рекомендуется отдельный непривилегированный пользователь. Вывод команд будет виден агенту; не выводите секреты. Разрешение истекает вместе с доступом; повторный вход без флажка отзывает его.</small>`;
}
function presetLoginFormHtml(accountName, account, formNonce) {
    return loginPage(`<h1>Безопасный SSH-вход</h1><p><b>${escapeHtml(accountName)}</b><br><small>${escapeHtml(account.username)}@${escapeHtml(account.host)}:${account.port}</small></p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="save"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}"><label for="password">Пароль SSH</label><input id="password" name="password" type="password" minlength="1" maxlength="4096" required autofocus autocomplete="current-password">${sshExecConsentHtml()}<button type="submit">Передать SSH Broker</button></form>
<p><small>Пароль не отправляется в Telegram и не передаётся модели. Он хранится только в памяти Gateway ограниченное время.</small></p>`);
}
function dynamicTargetFormHtml(formNonce) {
    return loginPage(`<h1>Новое SSH-подключение</h1><p class="muted">Укажите сервер. Сначала будет показан SSH-отпечаток; после ввода пароля Broker проверит вход и сам определит домашний каталог.</p>
<form method="post" autocomplete="off">
<input name="action" type="hidden" value="prepare"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="name">ID подключения</label><input id="name" name="name" pattern="[A-Za-z][A-Za-z0-9_-]{0,63}" maxlength="64" placeholder="my-site" required autocapitalize="none" spellcheck="false">
<label for="host">SSH-хост или IP</label><input id="host" name="host" maxlength="253" placeholder="example.com" required autocapitalize="none" spellcheck="false">
<label for="port">SSH-порт</label><input id="port" name="port" type="number" min="1" max="65535" value="22" required inputmode="numeric">
<label for="username">SSH-логин</label><input id="username" name="username" maxlength="128" placeholder="site_user" required autocapitalize="none" spellcheck="false">
<label for="roots">Разрешённые каталоги (необязательно)</label><textarea id="roots" name="roots" maxlength="8192" placeholder="Определятся автоматически; при необходимости укажите один путь на строку" autocapitalize="none" spellcheck="false"></textarea><small>Если поле пустое, будет использован фактический домашний каталог SFTP. Корень / запрещён.</small>
<label for="fingerprint">Ожидаемый SSH-отпечаток (необязательно)</label><input id="fingerprint" name="fingerprint" maxlength="71" placeholder="SHA256:…" autocapitalize="none" spellcheck="false"><small>Если известен заранее, несовпадение остановит подключение.</small>
<button type="submit">Проверить сервер</button></form>`);
}
function dynamicPasswordFormHtml(accountName, account, formNonce, discoverHome = false) {
    const roots = discoverHome
        ? "Будет определён автоматически после проверки пароля"
        : account.allowedRoots.map((root) => escapeHtml(root)).join("<br>");
    return loginPage(`<h1>Подтвердите сервер</h1><div class="card"><b>${escapeHtml(accountName)}</b><br>${escapeHtml(account.username)}@${escapeHtml(account.host)}:${account.port}<br><br><span class="fingerprint">${escapeHtml(displayHostKeyFingerprint(account.hostKeySha256Hex))}</span><br><br><small>Разрешённые каталоги:</small><br>${roots}</div>
<p class="muted">Сверьте отпечаток с панелью хостинга, если он у вас есть. После сохранения он будет закреплён до истечения подключения.</p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="save"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}"><label for="password">Пароль SSH</label><input id="password" name="password" type="password" minlength="1" maxlength="4096" required autofocus autocomplete="current-password">${sshExecConsentHtml()}<button type="submit">Подтвердить и передать пароль</button></form>
<p><small>Параметры подключения и пароль хранятся только в памяти Gateway и автоматически удаляются.</small></p>`);
}
function importedSshConfirmHtml(accountName, account, formNonce) {
    const roots = account.allowedRoots.map((root) => escapeHtml(root)).join("<br>");
    return loginPage(`<h1>SSH распознан</h1><div class="card"><b>${escapeHtml(accountName)}</b><br>${escapeHtml(account.username)}@${escapeHtml(account.host)}:${account.port}<br><br><span class="fingerprint">${escapeHtml(displayHostKeyFingerprint(account.hostKeySha256Hex))}</span><br><br><small>Разрешённые каталоги:</small><br>${roots}</div>
<p class="muted">Пароль распознан и уже находится только в памяти Gateway. Он не выводится обратно в страницу.</p>
<form method="post"><input name="action" type="hidden" value="confirm"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">${sshExecConsentHtml()}<button type="submit">Подтвердить SSH‑доступ</button></form>`);
}
function accessKindFormHtml(formNonce) {
    return loginPage(`<h1>Новое подключение</h1><p class="muted">Вставьте весь набор данных одним блоком — Broker распознает SSH, админку или API‑ключ и покажет результат перед сохранением.</p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="import"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="bundle">Данные доступа</label><textarea id="bundle" name="bundle" maxlength="16384" required autofocus autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="example.com&#10;логин: site_user&#10;пароль: …&#10;путь: /home/site_user/public_html"></textarea>
<small>Поддерживаются строки вида «поле: значение», SSH URL/команда и URL с подписями login/password/api_key/token. Неоднозначные наборы не сохраняются.</small>
<button type="submit">Распознать данные</button></form>
<p class="muted">Или заполните вручную:</p>
<form method="post"><input name="action" type="hidden" value="choose"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="kind">Тип доступа</label><select id="kind" name="kind" required><option value="ssh">SSH / SFTP</option><option value="api-basic">HTTPS API · Basic Auth</option><option value="api-token">HTTPS API · Token / API key</option><option value="web-https">HTTPS веб‑админка</option><option value="web-via-ssh">HTTP веб‑админка через SSH‑туннель</option></select>
<button type="submit">Продолжить</button></form>
<p><small>Прямой ввод пароля на незашифрованный HTTP‑сайт запрещён. Для такой админки используется зашифрованный SSH‑туннель.</small></p>`);
}
function apiBasicTargetFormHtml(formNonce) {
    return loginPage(`<h1>HTTPS API · Basic Auth</h1><p class="muted">Подходит для InSales и других API с идентификатором и паролем. Credentials в URL не используются.</p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="prepare"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="name">ID подключения</label><input id="name" name="name" pattern="[A-Za-z][A-Za-z0-9_-]{0,63}" maxlength="64" placeholder="ifloors-api" required autocapitalize="none" spellcheck="false">
<label for="origin">HTTPS origin</label><input id="origin" name="origin" type="url" maxlength="2048" placeholder="https://myshop-xxxx.myinsales.ru" required autocapitalize="none" spellcheck="false">
<label for="paths">Разрешённые пути API</label><textarea id="paths" name="paths" maxlength="8192" placeholder="/admin/" required autocapitalize="none" spellcheck="false">/admin/</textarea><small>Один абсолютный префикс пути на строку.</small>
<button type="submit">Проверить параметры</button></form>`);
}
function apiTokenTargetFormHtml(formNonce) {
    return loginPage(`<h1>HTTPS API · Token</h1><p class="muted">Токен будет добавляться только в выбранный заголовок и только для разрешённых путей этого HTTPS origin.</p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="prepare"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="name">ID подключения</label><input id="name" name="name" pattern="[A-Za-z][A-Za-z0-9_-]{0,63}" maxlength="64" placeholder="service-api" required autocapitalize="none" spellcheck="false">
<label for="origin">HTTPS origin</label><input id="origin" name="origin" type="url" maxlength="2048" placeholder="https://api.example.com" required autocapitalize="none" spellcheck="false">
<label for="authMode">Способ авторизации</label><select id="authMode" name="authMode"><option value="bearer">Authorization: Bearer</option><option value="x-api-key">X-API-Key</option></select>
<label for="paths">Разрешённые пути API</label><textarea id="paths" name="paths" maxlength="8192" placeholder="/v1/" required autocapitalize="none" spellcheck="false">/</textarea><small>Один абсолютный префикс пути на строку.</small>
<button type="submit">Проверить параметры</button></form>`);
}
function webHttpsTargetFormHtml(formNonce) {
    return loginPage(`<h1>HTTPS веб‑админка</h1><p class="muted">Подходит для обычной JSON или form‑авторизации по HTTPS. Сложные JS/MFA‑формы могут потребовать отдельного адаптера.</p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="prepare"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="name">ID подключения</label><input id="name" name="name" pattern="[A-Za-z][A-Za-z0-9_-]{0,63}" maxlength="64" placeholder="cms-admin" required autocapitalize="none" spellcheck="false">
<label for="origin">HTTPS origin</label><input id="origin" name="origin" type="url" maxlength="2048" placeholder="https://admin.example.com" required autocapitalize="none" spellcheck="false">
<label for="loginPath">Login endpoint</label><input id="loginPath" name="loginPath" maxlength="2048" value="/login" required autocapitalize="none" spellcheck="false">
<label for="bodyMode">Формат входа</label><select id="bodyMode" name="bodyMode"><option value="form">HTML form</option><option value="json">JSON API</option></select>
<label for="usernameField">Поле логина</label><input id="usernameField" name="usernameField" maxlength="128" value="login" required autocapitalize="none" spellcheck="false">
<label for="passwordField">Поле пароля</label><input id="passwordField" name="passwordField" maxlength="128" value="password" required autocapitalize="none" spellcheck="false">
<label for="paths">Разрешённые пути</label><textarea id="paths" name="paths" maxlength="8192" required autocapitalize="none" spellcheck="false">/</textarea>
<button type="submit">Проверить параметры</button></form>`);
}
function webViaSshTargetFormHtml(formNonce) {
    return loginPage(`<h1>Веб‑админка через SSH</h1><p class="muted">HTTP‑запросы к админке пойдут внутри уже подтверждённого SSH‑подключения.</p>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="prepare"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="name">ID подключения</label><input id="name" name="name" pattern="[A-Za-z][A-Za-z0-9_-]{0,63}" maxlength="64" placeholder="cms-admin" required autocapitalize="none" spellcheck="false">
<label for="sshAccount">ID SSH‑подключения</label><input id="sshAccount" name="sshAccount" maxlength="64" placeholder="server95" required autocapitalize="none" spellcheck="false"><small>SSH‑подключение должно быть передано через универсальный /accesslogin под этим ID.</small>
<label for="targetHost">HTTP host на сервере</label><input id="targetHost" name="targetHost" maxlength="64" value="127.0.0.1" required autocapitalize="none" spellcheck="false">
<label for="targetPort">HTTP port на сервере</label><input id="targetPort" name="targetPort" type="number" min="1" max="65535" value="8080" required>
<label for="loginPath">JSON login endpoint</label><input id="loginPath" name="loginPath" maxlength="2048" value="/api/admin/auth/login" required autocapitalize="none" spellcheck="false">
<label for="usernameField">Поле логина в JSON</label><input id="usernameField" name="usernameField" maxlength="128" value="login" required autocapitalize="none" spellcheck="false">
<label for="passwordField">Поле пароля в JSON</label><input id="passwordField" name="passwordField" maxlength="128" value="password" required autocapitalize="none" spellcheck="false">
<label for="bodyMode">Формат входа</label><select id="bodyMode" name="bodyMode"><option value="json">JSON API</option><option value="form">HTML form</option></select>
<label for="paths">Разрешённые пути</label><textarea id="paths" name="paths" maxlength="8192" required autocapitalize="none" spellcheck="false">/admin/\n/api/admin/</textarea>
<button type="submit">Проверить параметры</button></form>`);
}
function accessSecretFormHtml(name, account, formNonce, importedCredential = false) {
    const endpoint = account.kind === "web-via-ssh"
        ? `SSH ${account.sshAccount} → http://${account.targetHost}:${account.targetPort}${account.loginPath}`
        : account.kind === "web-https"
            ? `${account.origin}${account.loginPath}`
            : account.origin;
    const usernameLabel = account.kind === "api-basic" ? "API‑идентификатор" : "Логин веб‑админки";
    const passwordLabel = account.kind === "api-basic" ? "Пароль API" : "Пароль веб‑админки";
    if (importedCredential) {
        return loginPage(`<h1>Данные распознаны</h1><div class="card"><b>${escapeHtml(name)}</b><br>${escapeHtml(endpoint)}<br><small>Тип: ${escapeHtml(account.kind)}</small></div>
<p class="muted">Секрет распознан и уже находится только в памяти Gateway. Он не выводится обратно в страницу.</p>
<form method="post"><input name="action" type="hidden" value="save"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}"><button type="submit">Подтвердить и сохранить</button></form>`);
    }
    if (account.kind === "api-token") {
        return loginPage(`<h1>Передать API‑ключ</h1><div class="card"><b>${escapeHtml(name)}</b><br>${escapeHtml(endpoint)}<br><small>${escapeHtml(account.authHeader)}${account.authPrefix ? `: ${escapeHtml(account.authPrefix)} …` : ""}</small></div>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="save"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="password">API key / token</label><input id="password" name="password" type="password" minlength="1" maxlength="4096" required autofocus autocomplete="off">
<button type="submit">Передать Access Broker</button></form><p><small>Ключ хранится только в памяти Gateway и автоматически удаляется.</small></p>`);
    }
    return loginPage(`<h1>Передать секреты</h1><div class="card"><b>${escapeHtml(name)}</b><br>${escapeHtml(endpoint)}<br><small>Тип: ${escapeHtml(account.kind)}</small></div>
<form method="post" autocomplete="off"><input name="action" type="hidden" value="save"><input name="csrf" type="hidden" value="${escapeHtml(formNonce)}">
<label for="username">${usernameLabel}</label><input id="username" name="username" maxlength="4096" required autofocus autocomplete="username" autocapitalize="none" spellcheck="false">
<label for="password">${passwordLabel}</label><input id="password" name="password" type="password" minlength="1" maxlength="4096" required autocomplete="current-password">
<button type="submit">Передать Access Broker</button></form><p><small>Значения хранятся только в памяти Gateway, привязаны к этой Telegram‑сессии и автоматически удаляются.</small></p>`);
}
export function isTrustedFormPost(expectedOrigin, originHeader, secFetchSite) {
    const origin = originHeader.trim();
    if (origin && origin !== "null") {
        try {
            if (new URL(origin).origin !== new URL(expectedOrigin).origin) {
                return false;
            }
        }
        catch {
            return false;
        }
    }
    const fetchSite = secFetchSite.trim().toLowerCase();
    return fetchSite !== "cross-site";
}
function loginResultHtml(ok, message) {
    return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Broker</title><style>body{font-family:system-ui,sans-serif;background:#111827;color:#f9fafb;margin:0;padding:24px}main{max-width:520px;margin:12vh auto;background:#1f2937;padding:24px;border-radius:16px}a{color:#86efac}.version{margin-top:24px;text-align:center;color:#6b7280;font-size:12px}</style></head><body><main><h1>${ok ? "Готово" : "Ошибка"}</h1><p>${escapeHtml(message)}</p><p>Можно закрыть это окно и вернуться в Telegram.</p><footer class="version">Access Broker v${ACCESS_BROKER_VERSION}</footer></main></body></html>`;
}
async function readFetchBody(response, maxBytes) {
    const reader = response.body?.getReader();
    if (!reader)
        return "";
    const chunks = [];
    let total = 0;
    while (true) {
        const next = await reader.read();
        if (next.done)
            break;
        total += next.value.byteLength;
        if (total > maxBytes) {
            await reader.cancel();
            throw new Error(`HTTP response exceeds ${maxBytes} bytes`);
        }
        chunks.push(Buffer.from(next.value));
    }
    return Buffer.concat(chunks).toString("utf8");
}
async function requestApiBasic(account, username, password, method, requestPath, body, contentType, signal) {
    const normalizedPath = normalizeHttpPath(requestPath);
    if (!isHttpPathAllowed(normalizedPath, account.allowedPathPrefixes)) {
        throw new Error("HTTP path is outside allowed API prefixes");
    }
    const url = new URL(normalizedPath, account.origin);
    if (url.origin !== account.origin)
        throw new Error("HTTP request origin changed unexpectedly");
    const headers = new Headers({
        Accept: "application/json, text/plain;q=0.9, */*;q=0.1",
        Authorization: `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`,
        "User-Agent": `OpenClaw-Access-Broker/${ACCESS_BROKER_VERSION}`,
    });
    if (body !== undefined)
        headers.set("Content-Type", contentType ?? "application/json; charset=utf-8");
    const response = await fetch(url, {
        method,
        headers,
        body,
        redirect: "manual",
        signal,
    });
    return {
        status: response.status,
        contentType: response.headers.get("content-type") ?? "",
        ...(response.headers.get("location") ? { location: response.headers.get("location") } : {}),
        body: await readFetchBody(response, account.maxResponseBytes),
        setCookies: [],
    };
}
function fetchSetCookies(response) {
    const headers = response.headers;
    if (typeof headers.getSetCookie === "function")
        return headers.getSetCookie();
    const single = response.headers.get("set-cookie");
    return single ? [single] : [];
}
async function requestHttpsScoped(origin, allowedPathPrefixes, maxResponseBytes, method, requestPath, headers, body, signal) {
    const normalizedPath = normalizeHttpPath(requestPath);
    if (!isHttpPathAllowed(normalizedPath, allowedPathPrefixes)) {
        throw new Error("HTTP path is outside allowed prefixes");
    }
    const url = new URL(normalizedPath, origin);
    if (url.origin !== origin)
        throw new Error("HTTP request origin changed unexpectedly");
    const response = await fetch(url, { method, headers, body, redirect: "manual", signal });
    return {
        status: response.status,
        contentType: response.headers.get("content-type") ?? "",
        ...(response.headers.get("location") ? { location: response.headers.get("location") } : {}),
        body: await readFetchBody(response, maxResponseBytes),
        setCookies: fetchSetCookies(response),
    };
}
async function requestApiToken(account, token, method, requestPath, body, contentType, signal) {
    const headers = new Headers({
        Accept: "application/json, text/plain;q=0.9, */*;q=0.1",
        "User-Agent": `OpenClaw-Access-Broker/${ACCESS_BROKER_VERSION}`,
    });
    headers.set(account.authHeader, account.authPrefix ? `${account.authPrefix} ${token}` : token);
    if (body !== undefined)
        headers.set("Content-Type", contentType ?? "application/json; charset=utf-8");
    return requestHttpsScoped(account.origin, account.allowedPathPrefixes, account.maxResponseBytes, method, requestPath, headers, body, signal);
}
function buildWebLoginPayload(account, username, password) {
    if (account.bodyMode === "form") {
        const form = new URLSearchParams({
            [account.usernameField]: username,
            [account.passwordField]: password,
        });
        return { body: form.toString(), contentType: "application/x-www-form-urlencoded; charset=utf-8" };
    }
    return {
        body: JSON.stringify({
            [account.usernameField]: username,
            [account.passwordField]: password,
        }),
        contentType: "application/json; charset=utf-8",
    };
}
async function requestWebHttps(account, method, requestPath, headers, body, signal) {
    return requestHttpsScoped(account.origin, account.allowedPathPrefixes, account.maxResponseBytes, method, requestPath, headers, body, signal);
}
async function requestWebViaSsh(sshAccount, sshPassword, webAccount, method, requestPath, headers, body, signal) {
    const normalizedPath = normalizeHttpPath(requestPath);
    if (!isHttpPathAllowed(normalizedPath, webAccount.allowedPathPrefixes)) {
        throw new Error("HTTP path is outside allowed web prefixes");
    }
    const client = await connect(sshAccount, sshPassword, signal);
    try {
        const channel = await new Promise((resolve, reject) => {
            client.forwardOut("127.0.0.1", 0, webAccount.targetHost, webAccount.targetPort, (error, stream) => {
                if (error)
                    reject(error);
                else
                    resolve(stream);
            });
        });
        return await new Promise((resolve, reject) => {
            let settled = false;
            const finish = (error, result) => {
                if (settled)
                    return;
                settled = true;
                signal?.removeEventListener("abort", onAbort);
                if (error)
                    reject(error);
                else
                    resolve(result);
            };
            const onAbort = () => {
                channel.destroy();
                finish(new Error("web request aborted"));
            };
            signal?.addEventListener("abort", onAbort, { once: true });
            const request = httpRequest({
                method,
                host: webAccount.targetHost,
                port: webAccount.targetPort,
                path: normalizedPath,
                headers: {
                    Host: `${webAccount.targetHost}:${webAccount.targetPort}`,
                    Connection: "close",
                    ...headers,
                },
                agent: false,
                createConnection: () => channel,
            }, (response) => {
                const chunks = [];
                let total = 0;
                response.on("data", (chunk) => {
                    total += chunk.length;
                    if (total > webAccount.maxResponseBytes) {
                        request.destroy(new Error(`HTTP response exceeds ${webAccount.maxResponseBytes} bytes`));
                        return;
                    }
                    chunks.push(Buffer.from(chunk));
                });
                response.once("error", (error) => finish(error));
                response.once("end", () => {
                    const rawCookies = response.headers["set-cookie"];
                    finish(undefined, {
                        status: response.statusCode ?? 0,
                        contentType: String(response.headers["content-type"] ?? ""),
                        ...(response.headers.location ? { location: response.headers.location } : {}),
                        body: Buffer.concat(chunks).toString("utf8"),
                        setCookies: Array.isArray(rawCookies) ? rawCookies : (rawCookies ? [rawCookies] : []),
                    });
                });
            });
            request.once("error", (error) => finish(error));
            if (body !== undefined)
                request.write(body, "utf8");
            request.end();
        });
    }
    finally {
        client.end();
    }
}
export function createAccessLoginCommandHandler(createLogin) {
    return async (context) => {
        const login = await createLogin(requireSessionKey(context.sessionKey));
        return {
            text: `Access Broker v${ACCESS_BROKER_VERSION}. Откройте универсальную защищённую форму. Ссылка одноразовая и действует до ${login.expiresAt}.`,
            presentation: {
                blocks: [{
                        type: "buttons",
                        buttons: [{ label: "Передать доступ", action: { type: "web-app", url: login.url } }],
                    }],
            },
        };
    };
}
export function formatCredentialTtlRu(seconds) {
    if (seconds === 24 * 60 * 60)
        return "24 часа";
    if (seconds % (60 * 60) === 0)
        return `${seconds / (60 * 60)} ч.`;
    return `${Math.ceil(seconds / 60)} мин.`;
}
export default definePluginEntry({
    id: "ssh-broker",
    name: "Access Broker",
    description: "Runs pinned SSH/SFTP, HTTPS API key/Basic, and HTTPS or SSH-tunneled web-admin operations without exposing credentials to the model.",
    register(api) {
        const config = parseConfig(api.pluginConfig);
        const gatewayPort = typeof api.config.gateway?.port === "number" ? api.config.gateway.port : 18_789;
        const { vault, accessVault } = getSharedCredentialVaults(config.credentialTtlSeconds, config.ticketTtlSeconds);
        const tunnel = new QuickTunnelManager(config.publicBaseUrl, config.quickTunnel, `http://127.0.0.1:${gatewayPort}`);
        const createAccessLogin = async (sessionKey) => {
            const origin = await tunnel.ensure();
            const ticket = accessVault.createTicket(sessionKey);
            return {
                url: `${origin}${ACCESS_PATH_PREFIX}${ticket.token}`,
                expiresAt: new Date(ticket.expiresAt).toISOString(),
            };
        };
        api.registerService({
            id: "ssh-broker-runtime",
            start: async () => { },
            stop: async () => {
                vault.sweep();
                accessVault.sweep();
                await tunnel.stop();
            },
        });
        api.registerHttpRoute({
            path: SSH_STAGE_PATH_PREFIX,
            auth: "plugin",
            match: "prefix",
            handler: async (req, res) => {
                const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
                const token = requestUrl.pathname.slice(SSH_STAGE_PATH_PREFIX.length);
                if (!/^[a-f0-9]{64}$/.test(token) || requestUrl.pathname !== `${SSH_STAGE_PATH_PREFIX}${token}`) {
                    sendHtml(res, 404, loginResultHtml(false, "Ссылка недействительна."));
                    return true;
                }
                const ticket = vault.ticket(token);
                if (!ticket) {
                    sendHtml(res, 410, loginResultHtml(false, "Ссылка уже использована или истекла."));
                    return true;
                }
                if (req.method === "GET") {
                    const nonce = vault.issueFormNonce(token);
                    if (ticket.stagedDynamic) {
                        sendHtml(res, 200, ticket.stagedPassword
                            ? importedSshConfirmHtml(ticket.stagedDynamic.name, ticket.stagedDynamic.account, nonce)
                            : dynamicPasswordFormHtml(ticket.stagedDynamic.name, ticket.stagedDynamic.account, nonce, ticket.stagedDynamic.discoverHome));
                    }
                    else if (ticket.accountName && ticket.presetAccount) {
                        sendHtml(res, 200, ticket.stagedPassword
                            ? importedSshConfirmHtml(ticket.accountName, ticket.presetAccount, nonce)
                            : presetLoginFormHtml(ticket.accountName, ticket.presetAccount, nonce));
                    }
                    else if (config.allowDynamicAccounts) {
                        sendHtml(res, 200, dynamicTargetFormHtml(nonce));
                    }
                    else {
                        sendHtml(res, 410, loginResultHtml(false, "Ссылка больше не соответствует доступному подключению."));
                    }
                    return true;
                }
                if (req.method !== "POST") {
                    res.setHeader("Allow", "GET, POST");
                    sendHtml(res, 405, loginResultHtml(false, "Метод не разрешён."));
                    return true;
                }
                const publicOrigin = await tunnel.ensure();
                const originHeader = typeof req.headers.origin === "string" ? req.headers.origin : "";
                const secFetchSite = typeof req.headers["sec-fetch-site"] === "string" ? req.headers["sec-fetch-site"] : "";
                if (!isTrustedFormPost(publicOrigin, originHeader, secFetchSite)) {
                    sendHtml(res, 403, loginResultHtml(false, "Проверка источника формы не пройдена."));
                    return true;
                }
                const contentType = String(req.headers["content-type"] ?? "").toLowerCase();
                if (!contentType.startsWith("application/x-www-form-urlencoded")) {
                    sendHtml(res, 415, loginResultHtml(false, "Неподдерживаемый формат запроса."));
                    return true;
                }
                const body = await readWebhookBodyOrReject({
                    req,
                    res,
                    maxBytes: 16_384,
                    timeoutMs: 5000,
                    invalidBodyMessage: "Invalid form body",
                });
                if (!body.ok) {
                    return true;
                }
                const form = new URLSearchParams(body.value);
                const formNonces = form.getAll("csrf");
                if (formNonces.length !== 1 || !vault.verifyFormNonce(token, formNonces[0])) {
                    sendHtml(res, 403, loginResultHtml(false, "Одноразовая проверка формы не пройдена."));
                    return true;
                }
                const actions = form.getAll("action");
                if (actions.length !== 1 || (actions[0] !== "prepare" && actions[0] !== "save" && actions[0] !== "confirm")) {
                    sendHtml(res, 400, loginResultHtml(false, "Неизвестный этап формы."));
                    return true;
                }
                if (actions[0] === "prepare") {
                    if (!config.allowDynamicAccounts || ticket.accountName || ticket.presetAccount) {
                        sendHtml(res, 403, loginResultHtml(false, "Динамические подключения недоступны для этой ссылки."));
                        return true;
                    }
                    try {
                        const single = (name, required = true) => {
                            const values = form.getAll(name);
                            if (values.length !== 1 || (required && values[0].trim().length === 0)) {
                                throw new Error(`Поле ${name} заполнено неверно.`);
                            }
                            return values[0].trim();
                        };
                        const accountName = requireAccountName(single("name"));
                        if (config.accounts[accountName]) {
                            throw new Error("Этот ID уже занят настроенным подключением. Выберите другой.");
                        }
                        const host = normalizeDynamicHost(single("host"));
                        const port = requireInteger(Number(single("port")), "port", 1, 65_535);
                        const username = single("username");
                        const roots = single("roots", false).split(/\r?\n/).map((root) => root.trim()).filter(Boolean);
                        const expectedFingerprint = single("fingerprint", false);
                        const scannedFingerprint = await scanHostKey(host, port);
                        if (expectedFingerprint && normalizeHostKeySha256(expectedFingerprint) !== scannedFingerprint) {
                            throw new Error("SSH-отпечаток сервера не совпал с указанным ожидаемым значением.");
                        }
                        const account = buildDynamicAccount({
                            host,
                            port,
                            username,
                            hostKeySha256: scannedFingerprint,
                            // A provisional non-root scope is needed only to authenticate.
                            // It is replaced with SFTP realpath(".") after password entry.
                            allowedRoots: roots.length > 0 ? roots : [`/home/${username}`],
                        });
                        vault.stageDynamic(token, accountName, account, undefined, roots.length === 0);
                        sendHtml(res, 200, dynamicPasswordFormHtml(accountName, account, vault.issueFormNonce(token), roots.length === 0));
                    }
                    catch (error) {
                        const message = error instanceof Error ? error.message : "Не удалось проверить SSH-сервер.";
                        sendHtml(res, 400, loginResultHtml(false, message));
                    }
                    return true;
                }
                if (!ticket.presetAccount && !ticket.stagedDynamic) {
                    sendHtml(res, 400, loginResultHtml(false, "Сначала подтвердите параметры SSH-сервера."));
                    return true;
                }
                let submittedPassword;
                if (actions[0] === "save") {
                    const passwords = form.getAll("password");
                    if (passwords.length !== 1 || passwords[0].length < 1 || passwords[0].length > 4096) {
                        sendHtml(res, 400, loginResultHtml(false, "Пароль пустой или слишком длинный."));
                        return true;
                    }
                    submittedPassword = passwords[0];
                }
                else if (!ticket.stagedPassword) {
                    sendHtml(res, 400, loginResultHtml(false, "Импортированный пароль отсутствует."));
                    return true;
                }
                if (ticket.stagedDynamic?.discoverHome) {
                    const password = submittedPassword ?? ticket.stagedPassword;
                    try {
                        if (!password)
                            throw new Error("Пароль SSH отсутствует.");
                        const discoveredRoots = await discoverSshRoots(ticket.stagedDynamic.account, password, []);
                        ticket.stagedDynamic.account = {
                            ...ticket.stagedDynamic.account,
                            allowedRoots: discoveredRoots,
                        };
                        ticket.stagedDynamic.discoverHome = false;
                    }
                    catch (error) {
                        const message = error instanceof Error ? error.message : "Не удалось определить домашний каталог SSH.";
                        sendHtml(res, 400, loginResultHtml(false, message));
                        return true;
                    }
                }
                let execEnabled;
                try {
                    execEnabled = parseExecConsent(form);
                }
                catch {
                    sendHtml(res, 400, loginResultHtml(false, "Неверное разрешение SSH-команд."));
                    return true;
                }
                const saved = vault.submit(token, submittedPassword, execEnabled);
                sendHtml(res, 200, loginResultHtml(true, `Подключение ${saved.account} готово. SSH-команды: ${execEnabled ? "разрешены" : "запрещены"}. Доступ будет удалён из памяти через ${formatCredentialTtlRu(config.credentialTtlSeconds)}.`));
                return true;
            },
        });
        api.registerHttpRoute({
            path: ACCESS_PATH_PREFIX,
            auth: "plugin",
            match: "prefix",
            handler: async (req, res) => {
                const requestUrl = new URL(req.url ?? "/", "http://127.0.0.1");
                const token = requestUrl.pathname.slice(ACCESS_PATH_PREFIX.length);
                if (!/^[a-f0-9]{64}$/.test(token) || requestUrl.pathname !== `${ACCESS_PATH_PREFIX}${token}`) {
                    sendHtml(res, 404, loginResultHtml(false, "Ссылка недействительна."));
                    return true;
                }
                const ticket = accessVault.ticket(token);
                if (!ticket) {
                    sendHtml(res, 410, loginResultHtml(false, "Ссылка уже использована или истекла."));
                    return true;
                }
                const renderCurrent = () => {
                    const nonce = accessVault.issueNonce(token);
                    if (ticket.staged) {
                        return accessSecretFormHtml(ticket.staged.name, ticket.staged.account, nonce, Boolean(ticket.stagedCredential));
                    }
                    if (ticket.selectedKind === "api-basic")
                        return apiBasicTargetFormHtml(nonce);
                    if (ticket.selectedKind === "api-token")
                        return apiTokenTargetFormHtml(nonce);
                    if (ticket.selectedKind === "web-https")
                        return webHttpsTargetFormHtml(nonce);
                    if (ticket.selectedKind === "web-via-ssh")
                        return webViaSshTargetFormHtml(nonce);
                    return accessKindFormHtml(nonce);
                };
                if (req.method === "GET") {
                    sendHtml(res, 200, renderCurrent());
                    return true;
                }
                if (req.method !== "POST") {
                    res.setHeader("Allow", "GET, POST");
                    sendHtml(res, 405, loginResultHtml(false, "Метод не разрешён."));
                    return true;
                }
                const publicOrigin = await tunnel.ensure();
                const originHeader = typeof req.headers.origin === "string" ? req.headers.origin : "";
                const secFetchSite = typeof req.headers["sec-fetch-site"] === "string" ? req.headers["sec-fetch-site"] : "";
                if (!isTrustedFormPost(publicOrigin, originHeader, secFetchSite)) {
                    sendHtml(res, 403, loginResultHtml(false, "Проверка источника формы не пройдена."));
                    return true;
                }
                const contentType = String(req.headers["content-type"] ?? "").toLowerCase();
                if (!contentType.startsWith("application/x-www-form-urlencoded")) {
                    sendHtml(res, 415, loginResultHtml(false, "Неподдерживаемый формат запроса."));
                    return true;
                }
                const body = await readWebhookBodyOrReject({
                    req,
                    res,
                    maxBytes: 16_384,
                    timeoutMs: 5000,
                    invalidBodyMessage: "Invalid form body",
                });
                if (!body.ok)
                    return true;
                const form = new URLSearchParams(body.value);
                const formNonces = form.getAll("csrf");
                if (formNonces.length !== 1 || !accessVault.verifyNonce(token, formNonces[0])) {
                    sendHtml(res, 403, loginResultHtml(false, "Одноразовая проверка формы не пройдена."));
                    return true;
                }
                const one = (name, required = true) => {
                    const values = form.getAll(name);
                    if (values.length !== 1 || (required && values[0].trim().length === 0)) {
                        throw new Error(`Поле ${name} заполнено неверно.`);
                    }
                    return values[0].trim();
                };
                try {
                    const action = one("action");
                    if (action === "import") {
                        const imported = parseSmartAccessInput(one("bundle"));
                        if (imported.kind === "ssh") {
                            if (!config.allowDynamicAccounts)
                                throw new Error("Динамические SSH-подключения выключены.");
                            const sessionKey = ticket.sessionKey;
                            const configuredMatch = resolveConfiguredSshImport(imported, config.accounts);
                            const accountName = configuredMatch?.name ?? imported.name;
                            const configuredAccount = configuredMatch?.account;
                            const existingAccess = accessVault.status(accountName, sessionKey).ready;
                            if (existingAccess) {
                                throw new Error("Этот ID уже занят активным подключением в Access Broker.");
                            }
                            if (configuredAccount) {
                                assertConfiguredSshImportMatches(imported, configuredAccount);
                                const scannedFingerprint = await scanHostKey(configuredAccount.host, configuredAccount.port);
                                if (scannedFingerprint !== configuredAccount.hostKeySha256Hex) {
                                    throw new Error("SSH-отпечаток сервера не совпал с закреплённым отпечатком подключения.");
                                }
                                accessVault.choose(token, "ssh");
                                const consumedSessionKey = accessVault.consumeForSsh(token);
                                const sshTicket = vault.createTicket(accountName, consumedSessionKey, configuredAccount);
                                vault.stagePresetPassword(sshTicket.token, imported.password);
                                res.statusCode = 303;
                                res.setHeader("Location", `${SSH_STAGE_PATH_PREFIX}${sshTicket.token}`);
                                res.setHeader("Cache-Control", "no-store, max-age=0");
                                res.end();
                                return true;
                            }
                            const scannedFingerprint = await scanHostKey(normalizeDynamicHost(imported.host), imported.port);
                            if (imported.expectedFingerprint && normalizeHostKeySha256(imported.expectedFingerprint) !== scannedFingerprint) {
                                throw new Error("SSH-отпечаток сервера не совпал с указанным ожидаемым значением.");
                            }
                            const provisionalAccount = buildDynamicAccount({
                                host: imported.host,
                                port: imported.port,
                                username: imported.username,
                                hostKeySha256: scannedFingerprint,
                                allowedRoots: imported.allowedRoots.length > 0
                                    ? imported.allowedRoots
                                    : ["/__openclaw_sftp_home_probe__"],
                            });
                            const allowedRoots = await discoverSshRoots(provisionalAccount, imported.password, imported.allowedRoots);
                            const account = { ...provisionalAccount, allowedRoots };
                            accessVault.choose(token, "ssh");
                            const consumedSessionKey = accessVault.consumeForSsh(token);
                            const sshTicket = vault.createTicket(undefined, consumedSessionKey);
                            vault.stageDynamic(sshTicket.token, imported.name, account, imported.password);
                            res.statusCode = 303;
                            res.setHeader("Location", `${SSH_STAGE_PATH_PREFIX}${sshTicket.token}`);
                            res.setHeader("Cache-Control", "no-store, max-age=0");
                            res.end();
                            return true;
                        }
                        if (vault.list(config.accounts, ticket.sessionKey).some((entry) => entry.account === imported.name)) {
                            throw new Error("Этот ID уже занят подключением в Access Broker.");
                        }
                        accessVault.choose(token, imported.kind);
                        if (imported.kind === "api-basic") {
                            accessVault.stage(token, imported.name, buildApiBasicAccount({ origin: imported.origin, allowedPathPrefixes: imported.allowedPathPrefixes }), { username: imported.username, password: imported.password });
                        }
                        else if (imported.kind === "api-token") {
                            accessVault.stage(token, imported.name, buildApiTokenAccount({
                                origin: imported.origin,
                                authHeader: imported.authHeader,
                                authPrefix: imported.authPrefix,
                                allowedPathPrefixes: imported.allowedPathPrefixes,
                            }), { username: "", password: imported.token });
                        }
                        else if (imported.kind === "web-https") {
                            accessVault.stage(token, imported.name, buildWebHttpsAccount({
                                origin: imported.origin,
                                loginPath: imported.loginPath,
                                usernameField: imported.usernameField,
                                passwordField: imported.passwordField,
                                bodyMode: imported.bodyMode,
                                allowedPathPrefixes: imported.allowedPathPrefixes,
                            }), { username: imported.username, password: imported.password });
                        }
                        else {
                            accessVault.stage(token, imported.name, buildWebViaSshAccount({
                                sshAccount: imported.sshAccount,
                                targetHost: imported.targetHost,
                                targetPort: imported.targetPort,
                                loginPath: imported.loginPath,
                                usernameField: imported.usernameField,
                                passwordField: imported.passwordField,
                                bodyMode: imported.bodyMode,
                                allowedPathPrefixes: imported.allowedPathPrefixes,
                            }), { username: imported.username, password: imported.password });
                        }
                        sendHtml(res, 200, renderCurrent());
                        return true;
                    }
                    if (action === "choose") {
                        const kind = one("kind");
                        if (kind !== "ssh" && kind !== "api-basic" && kind !== "api-token" && kind !== "web-https" && kind !== "web-via-ssh") {
                            throw new Error("Неизвестный тип подключения.");
                        }
                        accessVault.choose(token, kind);
                        if (kind === "ssh") {
                            if (!config.allowDynamicAccounts)
                                throw new Error("Динамические SSH-подключения выключены.");
                            const sessionKey = accessVault.consumeForSsh(token);
                            const sshTicket = vault.createTicket(undefined, sessionKey);
                            res.statusCode = 303;
                            res.setHeader("Location", `${SSH_STAGE_PATH_PREFIX}${sshTicket.token}`);
                            res.setHeader("Cache-Control", "no-store, max-age=0");
                            res.end();
                            return true;
                        }
                        sendHtml(res, 200, renderCurrent());
                        return true;
                    }
                    if (action === "prepare") {
                        const name = requireAccessName(one("name"));
                        if (vault.list(config.accounts, ticket.sessionKey).some((entry) => entry.account === name)) {
                            throw new Error("Этот ID уже занят активным временным подключением.");
                        }
                        const paths = one("paths").split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
                        if (ticket.selectedKind === "api-basic") {
                            accessVault.stage(token, name, buildApiBasicAccount({ origin: one("origin"), allowedPathPrefixes: paths }));
                        }
                        else if (ticket.selectedKind === "api-token") {
                            const authMode = one("authMode");
                            if (authMode !== "bearer" && authMode !== "x-api-key")
                                throw new Error("Неизвестный способ API-авторизации.");
                            accessVault.stage(token, name, buildApiTokenAccount({
                                origin: one("origin"),
                                authHeader: authMode === "bearer" ? "Authorization" : "X-API-Key",
                                authPrefix: authMode === "bearer" ? "Bearer" : "",
                                allowedPathPrefixes: paths,
                            }));
                        }
                        else if (ticket.selectedKind === "web-https") {
                            accessVault.stage(token, name, buildWebHttpsAccount({
                                origin: one("origin"),
                                loginPath: one("loginPath"),
                                usernameField: one("usernameField"),
                                passwordField: one("passwordField"),
                                bodyMode: one("bodyMode"),
                                allowedPathPrefixes: paths,
                            }));
                        }
                        else if (ticket.selectedKind === "web-via-ssh") {
                            accessVault.stage(token, name, buildWebViaSshAccount({
                                sshAccount: one("sshAccount"),
                                targetHost: one("targetHost"),
                                targetPort: Number(one("targetPort")),
                                loginPath: one("loginPath"),
                                usernameField: one("usernameField"),
                                passwordField: one("passwordField"),
                                bodyMode: one("bodyMode"),
                                allowedPathPrefixes: paths,
                            }));
                        }
                        else {
                            throw new Error("Сначала выберите тип подключения.");
                        }
                        sendHtml(res, 200, renderCurrent());
                        return true;
                    }
                    if (action === "save") {
                        const saved = ticket.stagedCredential
                            ? accessVault.submit(token)
                            : ticket.staged?.account.kind === "api-token"
                                ? accessVault.submit(token, "", one("password", false))
                                : accessVault.submit(token, one("username"), one("password", false));
                        sendHtml(res, 200, loginResultHtml(true, `Подключение ${saved.account} готово и будет удалено из памяти через ${formatCredentialTtlRu(config.credentialTtlSeconds)}.`));
                        return true;
                    }
                    throw new Error("Неизвестный этап формы.");
                }
                catch (error) {
                    const message = error instanceof Error ? error.message : "Не удалось сохранить подключение.";
                    sendHtml(res, 400, loginResultHtml(false, message));
                    return true;
                }
            },
        });
        api.registerCommand({
            name: "accesslogin",
            description: "Open a one-time smart-import form for SSH, HTTPS API, or web-admin access.",
            acceptsArgs: false,
            requiredScopes: ["operator.admin"],
            handler: createAccessLoginCommandHandler(createAccessLogin),
        });
        api.registerTool((context) => ({
            name: "ssh_broker_exec",
            label: "SSH broker execute command",
            description: "Execute a bounded non-interactive command on a session-bound SSH connection explicitly granted command permission by its owner in /accesslogin. Runs as SSH user, NOT sandboxed by SFTP roots. No credentials in arguments. Requires remote POSIX sh and GNU timeout. No interactive stdin or detached jobs.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                command: Type.String({ minLength: 1, maxLength: 32768 }),
                cwd: Type.String({ minLength: 1, maxLength: 4096 }),
                timeoutSeconds: Type.Optional(Type.Integer({ minimum: 1, maximum: 300 })),
            }, { additionalProperties: false }),
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const sessionKey = requireSessionKey(context.sessionKey);
                const credential = vault.resolve(accountName, config.accounts[accountName], sessionKey);
                if (credential.execEnabled !== true)
                    throw new Error("SSH command permission is not granted; owner must enable it in /accesslogin");
                const input = validateExecInput(params);
                if (credential.expiresAt - Date.now() < (input.timeoutSeconds + 10) * 1000)
                    throw new Error("SSH permission expires before command deadline; renew via /accesslogin");
                const busyKey = credentialKey(accountName, sessionKey);
                if (activeExec.has(busyKey) || activeExec.size >= 4)
                    throw new Error("SSH command already running or concurrency limit reached");
                activeExec.add(busyKey);
                let client;
                const controller = new AbortController();
                const abort = () => controller.abort();
                signal?.addEventListener("abort", abort, { once: true });
                if (signal?.aborted)
                    controller.abort();
                const watcher = setInterval(() => {
                    try {
                        if (vault.resolve(accountName, config.accounts[accountName], sessionKey) !== credential)
                            controller.abort();
                    }
                    catch {
                        controller.abort();
                    }
                }, 250);
                try {
                    if (controller.signal.aborted)
                        throw new Error("SSH command aborted");
                    client = await connect(credential.account, credential.password, controller.signal);
                    return textResult(await executeSshCommand(client, input, credential.password, controller.signal));
                }
                finally {
                    clearInterval(watcher);
                    signal?.removeEventListener("abort", abort);
                    client?.end();
                    activeExec.delete(busyKey);
                }
            },
        }), { name: "ssh_broker_exec", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_list_connections",
            label: "SSH broker list connections",
            description: "List configured and session-bound temporary SSH connections without exposing passwords.",
            parameters: Type.Object({}, { additionalProperties: false }),
            outputSchema: Type.Object({
                connections: Type.Array(Type.Object({
                    account: Type.String(),
                    host: Type.String(),
                    port: Type.Integer(),
                    username: Type.String(),
                    allowedRoots: Type.Array(Type.String()),
                    dynamic: Type.Boolean(),
                    ready: Type.Boolean(),
                    execEnabled: Type.Optional(Type.Boolean()),
                    expiresAt: Type.Optional(Type.String()),
                }, { additionalProperties: false })),
            }, { additionalProperties: false }),
            async execute(_id, rawParams) {
                requireParamsRecord(rawParams);
                const connections = vault.list(config.accounts, requireSessionKey(context.sessionKey)).map((entry) => ({
                    ...entry,
                    ...(entry.expiresAt ? { expiresAt: new Date(entry.expiresAt).toISOString() } : {}),
                }));
                return textResult({ connections });
            },
        }), { name: "ssh_broker_list_connections", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_credential_status",
            label: "SSH broker credential status",
            description: "Report whether an in-memory credential is ready without exposing it.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                ready: Type.Boolean(),
                execEnabled: Type.Optional(Type.Boolean()),
                expiresAt: Type.Optional(Type.String()),
            }, { additionalProperties: false }),
            async execute(_id, rawParams) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const status = vault.status(accountName, config.accounts[accountName], requireSessionKey(context.sessionKey));
                return textResult({
                    account: accountName,
                    ready: status.ready,
                    execEnabled: status.execEnabled === true,
                    ...(status.expiresAt ? { expiresAt: new Date(status.expiresAt).toISOString() } : {}),
                });
            },
        }), { name: "ssh_broker_credential_status", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_forget_credential",
            label: "SSH broker forget credential",
            description: "Immediately delete an SSH credential and any unused login ticket from Gateway memory.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                removed: Type.Boolean(),
            }, { additionalProperties: false }),
            executionMode: "sequential",
            async execute(_id, rawParams) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                return textResult({
                    account: accountName,
                    removed: vault.forget(accountName, requireSessionKey(context.sessionKey)),
                });
            },
        }), { name: "ssh_broker_forget_credential", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_probe",
            label: "SSH broker probe",
            description: "Verify a configured or temporary SSH connection using its pinned host key without exposing credentials.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                host: Type.String(),
                port: Type.Integer(),
                username: Type.String(),
                verifiedHostKey: Type.Boolean(),
            }, { additionalProperties: false }),
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                const client = await connect(account, connection.password, signal);
                client.end();
                return textResult({
                    account: accountName,
                    host: account.host,
                    port: account.port,
                    username: account.username,
                    verifiedHostKey: true,
                });
            },
        }), { name: "ssh_broker_probe", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_disk_audit",
            label: "SSH broker read-only disk audit",
            description: "Run a fixed, host-wide, read-only disk audit over a root SSH connection. It reports filesystem usage, directory sizes, large files, and deleted-but-open files; arbitrary commands are not accepted.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                report: Type.String(),
                truncated: Type.Boolean(),
            }, { additionalProperties: false }),
            executionMode: "sequential",
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                assertDiskAuditAccount(account);
                const client = await connect(account, connection.password, signal);
                try {
                    const result = await executeFixedRemoteCommand(client, buildDiskAuditCommand(), signal);
                    return textResult({ account: accountName, ...result });
                }
                finally {
                    client.end();
                }
            },
        }), { name: "ssh_broker_disk_audit", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_list_dir",
            label: "SSH broker list directory",
            description: "List one directory under a configured or temporary SSH connection's allowed roots without executing a shell command.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                path: Type.String({ minLength: 2, maxLength: 4096 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                path: Type.String(),
                entries: Type.Array(Type.Object({
                    name: Type.String(),
                    type: Type.Union([
                        Type.Literal("file"),
                        Type.Literal("directory"),
                        Type.Literal("symlink"),
                        Type.Literal("other"),
                    ]),
                    bytes: Type.Integer(),
                }, { additionalProperties: false })),
            }, { additionalProperties: false }),
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const requestedPath = requireString(params.path, "path");
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                return await withSftp(account, connection.password, signal, async (sftp) => {
                    const resolvedPath = await resolveAllowedPath(sftp, account, requestedPath);
                    const attrs = await sftpLstat(sftp, resolvedPath);
                    if ((attrs.mode & 0o170000) !== 0o040000) {
                        throw new Error("remote path is not a directory");
                    }
                    const entries = (await sftpReaddir(sftp, resolvedPath))
                        .filter((entry) => entry.name !== "." && entry.name !== "..")
                        .sort((a, b) => a.name.localeCompare(b.name))
                        .slice(0, 512)
                        .map((entry) => ({
                        name: entry.name,
                        type: remoteEntryType(entry.mode),
                        bytes: entry.size,
                    }));
                    return textResult({ path: resolvedPath, entries });
                });
            },
        }), { name: "ssh_broker_list_dir", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_read_file",
            label: "SSH broker read file",
            description: "Read one UTF-8 file under a configured or temporary SSH connection's allowed roots and return its SHA-256.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                path: Type.String({ minLength: 2, maxLength: 4096 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                path: Type.String(),
                sha256: Type.String(),
                bytes: Type.Integer(),
                content: Type.String(),
            }, { additionalProperties: false }),
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const requestedPath = requireString(params.path, "path");
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                return await withSftp(account, connection.password, signal, async (sftp) => {
                    const resolvedPath = await resolveAllowedPath(sftp, account, requestedPath);
                    const attrs = await sftpLstat(sftp, resolvedPath);
                    if ((attrs.mode & 0o170000) !== 0o100000) {
                        throw new Error("remote path is not a regular file");
                    }
                    if (attrs.size > account.maxFileBytes) {
                        throw new Error(`remote file exceeds maxFileBytes (${account.maxFileBytes})`);
                    }
                    const data = await sftpReadFile(sftp, resolvedPath);
                    if (!Buffer.from(data.toString("utf8"), "utf8").equals(data)) {
                        throw new Error("remote file is not valid UTF-8");
                    }
                    return textResult({
                        path: resolvedPath,
                        sha256: sha256(data),
                        bytes: data.length,
                        content: data.toString("utf8"),
                    });
                });
            },
        }), { name: "ssh_broker_read_file", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_create_file",
            label: "SSH broker create_file",
            description: "Create a new UTF-8 file under allowed SSH roots, exclusively (never overwrite), and verify SHA-256. Maximum 256 KiB; parent must exist. No shell execution.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                path: Type.String({ minLength: 2, maxLength: 4096 }),
                content: Type.String({ maxLength: 262144 }),
            }, { additionalProperties: false }),
            executionMode: "sequential",
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                if (typeof params.content !== "string")
                    throw new Error("content must be a string");
                return await withSftp(account, connection.password, signal, async (sftp) => textResult(await createRemoteFile(sftp, account, requireString(params.path, "path"), params.content)));
            },
        }), { name: "ssh_broker_create_file", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_mkdir",
            label: "SSH broker mkdir",
            description: "Create one directory under allowed SSH roots (parent must exist). Existing real directory succeeds unchanged. Reject symlinks; no shell execution.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                path: Type.String({ minLength: 2, maxLength: 4096 }),
            }, { additionalProperties: false }),
            executionMode: "sequential",
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                return await withSftp(account, connection.password, signal, async (sftp) => textResult(await createRemoteDirectory(sftp, account, requireString(params.path, "path"))));
            },
        }), { name: "ssh_broker_mkdir", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_move_file",
            label: "SSH broker move_file",
            description: "Move one regular file between allowed SSH paths without overwriting. Streams SHA-256 before and after; limit 512 MiB. Optional expectedSha256 guards the source. No directory moves or shell execution.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                source: Type.String({ minLength: 2, maxLength: 4096 }),
                destination: Type.String({ minLength: 2, maxLength: 4096 }),
                expectedSha256: Type.Optional(Type.String({ pattern: "^[a-f0-9]{64}$" })),
            }, { additionalProperties: false }),
            executionMode: "sequential",
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                return await withSftp(account, connection.password, signal, async (sftp) => textResult(await moveRemoteFile(sftp, account, requireString(params.source, "source"), requireString(params.destination, "destination"), params.expectedSha256 === undefined ? undefined : requireString(params.expectedSha256, "expectedSha256"))));
            },
        }), { name: "ssh_broker_move_file", optional: true });
        api.registerTool((context) => ({
            name: "ssh_broker_replace_file",
            label: "SSH broker replace file",
            description: "Replace one exact UTF-8 block in a remote file after SHA-256 verification, creating a same-directory backup first.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                path: Type.String({ minLength: 2, maxLength: 4096 }),
                expectedSha256: Type.String({ pattern: "^[a-f0-9]{64}$" }),
                find: Type.String({ minLength: 1, maxLength: 262144 }),
                replacement: Type.String({ maxLength: 262144 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                path: Type.String(),
                backupPath: Type.String(),
                beforeSha256: Type.String(),
                afterSha256: Type.String(),
                bytesBefore: Type.Integer(),
                bytesAfter: Type.Integer(),
            }, { additionalProperties: false }),
            executionMode: "sequential",
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccountName(params.account);
                const requestedPath = normalizeRemotePath(requireString(params.path, "path"));
                const expectedSha256 = requireString(params.expectedSha256, "expectedSha256");
                const find = requireString(params.find, "find");
                const replacement = typeof params.replacement === "string"
                    ? params.replacement
                    : (() => { throw new Error("replacement must be a string"); })();
                const connection = resolveConnection(config, vault, accountName, requireSessionKey(context.sessionKey));
                const { account } = connection;
                return await withSftp(account, connection.password, signal, async (sftp) => {
                    const requestedAttrs = await sftpLstat(sftp, requestedPath);
                    if ((requestedAttrs.mode & 0o170000) !== 0o100000) {
                        throw new Error("remote target must be a regular file and not a symlink");
                    }
                    const resolvedPath = await resolveAllowedPath(sftp, account, requestedPath);
                    const original = await sftpReadFile(sftp, resolvedPath);
                    if (original.length > account.maxFileBytes) {
                        throw new Error(`remote file exceeds maxFileBytes (${account.maxFileBytes})`);
                    }
                    if (!Buffer.from(original.toString("utf8"), "utf8").equals(original)) {
                        throw new Error("remote file is not valid UTF-8");
                    }
                    const beforeSha256 = sha256(original);
                    if (beforeSha256 !== expectedSha256.toLowerCase()) {
                        throw new Error(`remote file SHA-256 changed: expected ${expectedSha256}, actual ${beforeSha256}`);
                    }
                    const updatedText = replaceExactlyOnce(original.toString("utf8"), find, replacement);
                    const updated = Buffer.from(updatedText, "utf8");
                    if (updated.length > account.maxFileBytes) {
                        throw new Error(`updated file exceeds maxFileBytes (${account.maxFileBytes})`);
                    }
                    const mode = requestedAttrs.mode & 0o777;
                    const stamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
                    const suffix = randomBytes(4).toString("hex");
                    const backupPath = `${resolvedPath}.openclaw-backup-${stamp}-${suffix}`;
                    await sftpWriteFile(sftp, backupPath, original, { flag: "wx", mode });
                    await sftpChmod(sftp, backupPath, mode);
                    try {
                        await sftpWriteFile(sftp, resolvedPath, updated, { flag: "w", mode });
                        await sftpChmod(sftp, resolvedPath, mode);
                        const verified = await sftpReadFile(sftp, resolvedPath);
                        if (!verified.equals(updated)) {
                            throw new Error("post-write verification mismatch");
                        }
                    }
                    catch (error) {
                        await sftpWriteFile(sftp, resolvedPath, original, { flag: "w", mode });
                        await sftpChmod(sftp, resolvedPath, mode);
                        const restored = await sftpReadFile(sftp, resolvedPath);
                        if (!restored.equals(original)) {
                            throw new Error(`remote write failed and rollback verification failed; backup: ${backupPath}`);
                        }
                        throw new Error(`remote write failed and was rolled back; backup: ${backupPath}; cause: ${String(error)}`);
                    }
                    return textResult({
                        path: resolvedPath,
                        backupPath,
                        beforeSha256,
                        afterSha256: sha256(updated),
                        bytesBefore: original.length,
                        bytesAfter: updated.length,
                    });
                });
            },
        }), { name: "ssh_broker_replace_file", optional: true });
        api.registerTool((context) => ({
            name: "access_broker_list_connections",
            label: "Access broker list connections",
            description: "List all SSH, HTTPS API, and web-admin connections available to this session without exposing credentials.",
            parameters: Type.Object({}, { additionalProperties: false }),
            outputSchema: Type.Object({
                connections: Type.Array(Type.Object({
                    account: Type.String(),
                    kind: Type.Union([Type.Literal("ssh"), Type.Literal("api-basic"), Type.Literal("api-token"), Type.Literal("web-https"), Type.Literal("web-via-ssh")]),
                    endpoint: Type.String(),
                    source: Type.Union([Type.Literal("configured"), Type.Literal("temporary")]),
                    ready: Type.Boolean(),
                    execEnabled: Type.Optional(Type.Boolean()),
                    expiresAt: Type.Optional(Type.String()),
                    allowedRoots: Type.Optional(Type.Array(Type.String())),
                }, { additionalProperties: false })),
            }, { additionalProperties: false }),
            async execute(_id, rawParams) {
                requireParamsRecord(rawParams);
                const sessionKey = requireSessionKey(context.sessionKey);
                const sshConnections = vault.list(config.accounts, sessionKey).map((entry) => ({
                    account: entry.account,
                    kind: "ssh",
                    endpoint: `ssh://${entry.username}@${entry.host}:${entry.port}`,
                    source: entry.dynamic ? "temporary" : "configured",
                    ready: entry.ready,
                    allowedRoots: entry.allowedRoots,
                    ...(entry.expiresAt ? { expiresAt: new Date(entry.expiresAt).toISOString() } : {}),
                }));
                const otherConnections = accessVault.list(sessionKey).map((entry) => ({
                    ...entry,
                    source: "temporary",
                    expiresAt: new Date(entry.expiresAt).toISOString(),
                }));
                const connections = [...sshConnections, ...otherConnections]
                    .sort((a, b) => a.account.localeCompare(b.account));
                return textResult({ connections });
            },
        }), { name: "access_broker_list_connections", optional: true });
        api.registerTool((context) => ({
            name: "access_broker_credential_status",
            label: "Access broker credential status",
            description: "Report whether an SSH, API, or web credential is ready without exposing it.",
            parameters: Type.Object({ account: Type.String({ minLength: 1, maxLength: 64 }) }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                ready: Type.Boolean(),
                kind: Type.Optional(Type.Union([Type.Literal("ssh"), Type.Literal("api-basic"), Type.Literal("api-token"), Type.Literal("web-https"), Type.Literal("web-via-ssh")])),
                expiresAt: Type.Optional(Type.String()),
            }, { additionalProperties: false }),
            async execute(_id, rawParams) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccessName(requireString(params.account, "account"));
                const sessionKey = requireSessionKey(context.sessionKey);
                const accessStatus = accessVault.status(accountName, sessionKey);
                const isKnownSsh = vault.list(config.accounts, sessionKey).some((entry) => entry.account === accountName);
                const sshStatus = isKnownSsh
                    ? vault.status(accountName, config.accounts[accountName], sessionKey)
                    : { ready: false };
                const status = accessStatus.ready
                    ? accessStatus
                    : {
                        ready: sshStatus.ready,
                        ...(isKnownSsh ? { kind: "ssh" } : {}),
                        ...(sshStatus.expiresAt ? { expiresAt: sshStatus.expiresAt } : {}),
                    };
                return textResult({
                    account: accountName,
                    ready: status.ready,
                    ...(status.kind ? { kind: status.kind } : {}),
                    ...(status.expiresAt ? { expiresAt: new Date(status.expiresAt).toISOString() } : {}),
                });
            },
        }), { name: "access_broker_credential_status", optional: true });
        api.registerTool((context) => ({
            name: "access_broker_forget_credential",
            label: "Access broker forget credential",
            description: "Immediately delete one SSH, API, or web credential and its cookies from Gateway memory.",
            parameters: Type.Object({ account: Type.String({ minLength: 1, maxLength: 64 }) }, { additionalProperties: false }),
            outputSchema: Type.Object({ account: Type.String(), removed: Type.Boolean() }, { additionalProperties: false }),
            executionMode: "sequential",
            async execute(_id, rawParams) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccessName(requireString(params.account, "account"));
                const sessionKey = requireSessionKey(context.sessionKey);
                const removedAccess = accessVault.forget(accountName, sessionKey);
                const removedSsh = vault.forget(accountName, sessionKey);
                return textResult({
                    account: accountName,
                    removed: removedAccess || removedSsh,
                });
            },
        }), { name: "access_broker_forget_credential", optional: true });
        api.registerTool((context) => ({
            name: "access_broker_http_request",
            label: "Access broker HTTPS API request",
            description: "Send a path-scoped HTTPS API request using in-memory Basic Auth or API token credentials.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                method: Type.Union([Type.Literal("GET"), Type.Literal("POST"), Type.Literal("PUT"), Type.Literal("PATCH"), Type.Literal("DELETE")]),
                path: Type.String({ minLength: 1, maxLength: 4096 }),
                body: Type.Optional(Type.String({ maxLength: 1048576 })),
                contentType: Type.Optional(Type.String({ maxLength: 256 })),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                status: Type.Integer(),
                contentType: Type.String(),
                location: Type.Optional(Type.String()),
                body: Type.String(),
            }, { additionalProperties: false }),
            resultContentSource: "network",
            executionMode: "sequential",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccessName(requireString(params.account, "account"));
                const credential = accessVault.resolve(accountName, requireSessionKey(context.sessionKey));
                if (credential.account.kind !== "api-basic" && credential.account.kind !== "api-token") {
                    throw new Error("connection is not an HTTPS API account");
                }
                const method = requireString(params.method, "method");
                const requestPath = requireString(params.path, "path");
                const requestBody = params.body === undefined ? undefined : requireString(params.body, "body");
                const contentType = params.contentType === undefined ? undefined : requireString(params.contentType, "contentType");
                const response = credential.account.kind === "api-basic"
                    ? await requestApiBasic(credential.account, credential.username, credential.password, method, requestPath, requestBody, contentType, signal)
                    : await requestApiToken(credential.account, credential.password, method, requestPath, requestBody, contentType, signal);
                return textResult({
                    account: accountName,
                    status: response.status,
                    contentType: response.contentType,
                    ...(response.location ? { location: response.location } : {}),
                    body: response.body,
                });
            },
        }), { name: "access_broker_http_request", optional: true });
        api.registerTool((context) => ({
            name: "access_broker_web_login",
            label: "Access broker web login",
            description: "Create an in-memory web session for a scoped HTTPS admin or through a pinned SSH tunnel.",
            parameters: Type.Object({ account: Type.String({ minLength: 1, maxLength: 64 }) }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                authenticated: Type.Boolean(),
                status: Type.Integer(),
                cookiesStored: Type.Integer(),
            }, { additionalProperties: false }),
            resultContentSource: "network",
            executionMode: "sequential",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccessName(requireString(params.account, "account"));
                const sessionKey = requireSessionKey(context.sessionKey);
                const credential = accessVault.resolve(accountName, sessionKey);
                if (credential.account.kind !== "web-https" && credential.account.kind !== "web-via-ssh") {
                    throw new Error("connection is not a web-admin account");
                }
                const payload = buildWebLoginPayload(credential.account, credential.username, credential.password);
                const headers = {
                    Accept: "application/json, text/html;q=0.9, */*;q=0.1",
                    "Content-Type": payload.contentType,
                    "Content-Length": String(Buffer.byteLength(payload.body)),
                    "User-Agent": `OpenClaw-Access-Broker/${ACCESS_BROKER_VERSION}`,
                };
                let response;
                if (credential.account.kind === "web-https") {
                    response = await requestWebHttps(credential.account, "POST", credential.account.loginPath, headers, payload.body, signal);
                }
                else {
                    const webAccount = credential.account;
                    const sshConnection = resolveConnection(config, vault, webAccount.sshAccount, sessionKey);
                    response = await requestWebViaSsh(sshConnection.account, sshConnection.password, webAccount, "POST", webAccount.loginPath, headers, payload.body, signal);
                }
                let explicitlyRejected = false;
                try {
                    const parsed = JSON.parse(response.body);
                    explicitlyRejected = parsed.ok === false;
                }
                catch {
                    explicitlyRejected = false;
                }
                if (response.status < 200 || response.status >= 400 || explicitlyRejected) {
                    throw new Error(`web login was rejected with HTTP ${response.status}`);
                }
                accessVault.setCookies(accountName, sessionKey, response.setCookies);
                return textResult({
                    account: accountName,
                    authenticated: true,
                    status: response.status,
                    cookiesStored: response.setCookies.length,
                });
            },
        }), { name: "access_broker_web_login", optional: true });
        api.registerTool((context) => ({
            name: "access_broker_web_get",
            label: "Access broker web GET",
            description: "Fetch one allowed HTTPS or SSH-tunneled web-admin path using the in-memory cookie session.",
            parameters: Type.Object({
                account: Type.String({ minLength: 1, maxLength: 64 }),
                path: Type.String({ minLength: 1, maxLength: 4096 }),
            }, { additionalProperties: false }),
            outputSchema: Type.Object({
                account: Type.String(),
                status: Type.Integer(),
                contentType: Type.String(),
                location: Type.Optional(Type.String()),
                body: Type.String(),
            }, { additionalProperties: false }),
            resultContentSource: "network",
            async execute(_id, rawParams, signal) {
                const params = requireParamsRecord(rawParams);
                const accountName = requireAccessName(requireString(params.account, "account"));
                const sessionKey = requireSessionKey(context.sessionKey);
                const credential = accessVault.resolve(accountName, sessionKey);
                if (credential.account.kind !== "web-https" && credential.account.kind !== "web-via-ssh") {
                    throw new Error("connection is not a web-admin account");
                }
                if (credential.cookies.length === 0)
                    throw new Error("web session is not authenticated; call access_broker_web_login first");
                const headers = {
                    Accept: "text/html, application/json;q=0.9, */*;q=0.1",
                    Cookie: credential.cookies.join("; "),
                    "User-Agent": `OpenClaw-Access-Broker/${ACCESS_BROKER_VERSION}`,
                };
                const requestPath = requireString(params.path, "path");
                let response;
                if (credential.account.kind === "web-https") {
                    response = await requestWebHttps(credential.account, "GET", requestPath, headers, undefined, signal);
                }
                else {
                    const webAccount = credential.account;
                    const sshConnection = resolveConnection(config, vault, webAccount.sshAccount, sessionKey);
                    response = await requestWebViaSsh(sshConnection.account, sshConnection.password, webAccount, "GET", requestPath, headers, undefined, signal);
                }
                if (response.setCookies.length > 0)
                    accessVault.setCookies(accountName, sessionKey, response.setCookies);
                return textResult({
                    account: accountName,
                    status: response.status,
                    contentType: response.contentType,
                    ...(response.location ? { location: response.location } : {}),
                    body: response.body,
                });
            },
        }), { name: "access_broker_web_get", optional: true });
    },
});
//# sourceMappingURL=index.js.map