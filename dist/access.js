import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
const ACCESS_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,63}$/i;
const FIELD_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_ACTIVE_FORM_NONCES = 8;
function digest(value) {
    return createHash("sha256").update(value, "utf8").digest();
}
export function requireAccessName(value) {
    const name = value.trim();
    if (!ACCESS_NAME_PATTERN.test(name)) {
        throw new Error("ID must start with a letter and contain only letters, digits, underscore, or hyphen");
    }
    return name;
}
export function normalizeHttpsOrigin(value) {
    let url;
    try {
        url = new URL(value.trim());
    }
    catch {
        throw new Error("API origin must be a valid HTTPS URL");
    }
    if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
        throw new Error("API origin must be a bare HTTPS origin without credentials, path, query, or fragment");
    }
    return url.origin;
}
export function normalizeHttpPath(value, label = "path") {
    const text = value.trim();
    if (!text.startsWith("/") || text.startsWith("//") || text.includes("\\") || text.includes("\0")) {
        throw new Error(`${label} must be an absolute HTTP path`);
    }
    const parsed = new URL(text, "https://access-broker.invalid");
    if (parsed.origin !== "https://access-broker.invalid") {
        throw new Error(`${label} must not contain another origin`);
    }
    return `${parsed.pathname}${parsed.search}`;
}
export function normalizePathPrefixes(values) {
    const prefixes = [...new Set(values.map((value) => {
            const normalized = normalizeHttpPath(value, "allowed path prefix");
            if (normalized.includes("?")) {
                throw new Error("allowed path prefixes must not contain a query");
            }
            return normalized;
        }))];
    if (prefixes.length < 1 || prefixes.length > 16) {
        throw new Error("allowed path prefixes must contain 1-16 paths");
    }
    return prefixes;
}
export function isHttpPathAllowed(value, prefixes) {
    const path = normalizeHttpPath(value);
    const pathname = new URL(path, "https://access-broker.invalid").pathname;
    return prefixes.some((prefix) => {
        if (prefix.endsWith("/")) {
            return pathname.startsWith(prefix);
        }
        return pathname === prefix || pathname.startsWith(`${prefix}/`);
    });
}
export function normalizeRemoteWebHost(value) {
    const host = value.trim().toLowerCase();
    if (host === "localhost") {
        return "127.0.0.1";
    }
    if (host !== "127.0.0.1" && host !== "::1") {
        throw new Error("web-over-SSH target host must be localhost/127.0.0.1/::1 on the SSH server");
    }
    return host;
}
export function requireFieldName(value, label) {
    const name = value.trim();
    if (!FIELD_NAME_PATTERN.test(name)) {
        throw new Error(`${label} is not a valid JSON field name`);
    }
    return name;
}
export function buildApiBasicAccount(input) {
    return {
        kind: "api-basic",
        origin: normalizeHttpsOrigin(input.origin),
        allowedPathPrefixes: normalizePathPrefixes(input.allowedPathPrefixes),
        maxResponseBytes: input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    };
}
export function buildApiTokenAccount(input) {
    const authPrefix = (input.authPrefix ?? "").trim();
    if (authPrefix.length > 64 || /[\r\n]/.test(authPrefix)) {
        throw new Error("API auth prefix is invalid");
    }
    return {
        kind: "api-token",
        origin: normalizeHttpsOrigin(input.origin),
        authHeader: input.authHeader,
        authPrefix,
        allowedPathPrefixes: normalizePathPrefixes(input.allowedPathPrefixes),
        maxResponseBytes: input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    };
}
function requireBodyMode(value) {
    if (value !== "json" && value !== "form") {
        throw new Error("login body mode must be json or form");
    }
    return value;
}
function buildWebLoginFields(input) {
    const loginPath = normalizeHttpPath(input.loginPath, "login path");
    const allowedPathPrefixes = normalizePathPrefixes(input.allowedPathPrefixes);
    if (!isHttpPathAllowed(loginPath, allowedPathPrefixes)) {
        throw new Error("login path must be within allowed path prefixes");
    }
    return {
        loginPath,
        usernameField: requireFieldName(input.usernameField, "username field"),
        passwordField: requireFieldName(input.passwordField, "password field"),
        bodyMode: requireBodyMode(input.bodyMode),
        allowedPathPrefixes,
    };
}
export function buildWebHttpsAccount(input) {
    return {
        kind: "web-https",
        origin: normalizeHttpsOrigin(input.origin),
        ...buildWebLoginFields(input),
        maxResponseBytes: input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    };
}
export function buildWebViaSshAccount(input) {
    const sshAccount = requireAccessName(input.sshAccount);
    if (!Number.isInteger(input.targetPort) || input.targetPort < 1 || input.targetPort > 65535) {
        throw new Error("target port must be an integer from 1 to 65535");
    }
    return {
        kind: "web-via-ssh",
        sshAccount,
        targetHost: normalizeRemoteWebHost(input.targetHost),
        targetPort: input.targetPort,
        ...buildWebLoginFields({ ...input, bodyMode: input.bodyMode ?? "json" }),
        maxResponseBytes: input.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    };
}
function key(account, sessionKey) {
    return `${sessionKey}\0${account}`;
}
export class AccessVault {
    credentialTtlSeconds;
    ticketTtlSeconds;
    tickets = new Map();
    credentials = new Map();
    constructor(credentialTtlSeconds, ticketTtlSeconds) {
        this.credentialTtlSeconds = credentialTtlSeconds;
        this.ticketTtlSeconds = ticketTtlSeconds;
    }
    sweep(now = Date.now()) {
        for (const [token, ticket] of this.tickets) {
            if (ticket.expiresAt <= now)
                this.tickets.delete(token);
        }
        for (const [credentialKey, credential] of this.credentials) {
            if (credential.expiresAt <= now)
                this.credentials.delete(credentialKey);
        }
    }
    createTicket(sessionKey) {
        this.sweep();
        const token = randomBytes(32).toString("hex");
        const expiresAt = Date.now() + this.ticketTtlSeconds * 1000;
        this.tickets.set(token, { sessionKey, expiresAt });
        return { token, expiresAt };
    }
    ticket(token) {
        this.sweep();
        return this.tickets.get(token);
    }
    choose(token, kind) {
        const ticket = this.ticket(token);
        if (!ticket || ticket.staged)
            throw new Error("access ticket is invalid or expired");
        ticket.selectedKind = kind;
    }
    consumeForSsh(token) {
        const ticket = this.ticket(token);
        if (!ticket || ticket.selectedKind !== "ssh")
            throw new Error("access ticket is invalid or expired");
        this.tickets.delete(token);
        return ticket.sessionKey;
    }
    stage(token, name, account, credential) {
        const ticket = this.ticket(token);
        if (!ticket || !ticket.selectedKind || ticket.selectedKind === "ssh") {
            throw new Error("access ticket is invalid or expired");
        }
        if (ticket.selectedKind !== account.kind) {
            throw new Error("access account type does not match the selected type");
        }
        ticket.staged = { name: requireAccessName(name), account };
        if (credential) {
            if (credential.username.length > 4096 || !credential.password || credential.password.length > 4096) {
                throw new Error("identifier/login or password is empty or too long");
            }
            ticket.stagedCredential = { username: credential.username.trim(), password: credential.password };
        }
    }
    issueNonce(token) {
        const ticket = this.ticket(token);
        if (!ticket)
            throw new Error("access ticket is invalid or expired");
        const nonce = randomBytes(32).toString("hex");
        const hashes = ticket.formNonceSha256s ?? [];
        hashes.push(digest(nonce).toString("hex"));
        ticket.formNonceSha256s = hashes.slice(-MAX_ACTIVE_FORM_NONCES);
        return nonce;
    }
    verifyNonce(token, nonce) {
        const ticket = this.ticket(token);
        const expectedHashes = ticket?.formNonceSha256s;
        if (!expectedHashes?.length || !/^[a-f0-9]{64}$/.test(nonce))
            return false;
        const actual = digest(nonce);
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
    submit(token, username, password) {
        const ticket = this.ticket(token);
        if (!ticket?.staged)
            throw new Error("connection details must be confirmed before credentials");
        const normalizedUsername = (username ?? ticket.stagedCredential?.username ?? "").trim();
        const normalizedPassword = password ?? ticket.stagedCredential?.password ?? "";
        const needsUsername = ticket.staged.account.kind !== "api-token";
        if ((needsUsername && !normalizedUsername) || normalizedUsername.length > 4096 || !normalizedPassword || normalizedPassword.length > 4096) {
            throw new Error("identifier/login or password is empty or too long");
        }
        const expiresAt = Date.now() + this.credentialTtlSeconds * 1000;
        this.credentials.set(key(ticket.staged.name, ticket.sessionKey), {
            account: ticket.staged.account,
            username: normalizedUsername,
            password: normalizedPassword,
            expiresAt,
            sessionKey: ticket.sessionKey,
            cookies: [],
        });
        this.tickets.delete(token);
        return { account: ticket.staged.name, expiresAt };
    }
    resolve(accountName, sessionKey) {
        this.sweep();
        const credential = this.credentials.get(key(requireAccessName(accountName), sessionKey));
        if (!credential)
            throw new Error(`access credential is unknown or expired for ${accountName}; use /accesslogin`);
        return credential;
    }
    list(sessionKey) {
        this.sweep();
        const out = [];
        for (const [credentialKey, credential] of this.credentials) {
            if (credential.sessionKey !== sessionKey)
                continue;
            const account = credentialKey.slice(sessionKey.length + 1);
            out.push({
                account,
                kind: credential.account.kind,
                endpoint: credential.account.kind === "api-basic" || credential.account.kind === "api-token" || credential.account.kind === "web-https"
                    ? credential.account.origin
                    : `ssh:${credential.account.sshAccount} -> http://${credential.account.targetHost}:${credential.account.targetPort}`,
                ready: true,
                expiresAt: credential.expiresAt,
            });
        }
        return out.sort((a, b) => a.account.localeCompare(b.account));
    }
    status(accountName, sessionKey) {
        this.sweep();
        const credential = this.credentials.get(key(requireAccessName(accountName), sessionKey));
        return credential
            ? { ready: true, kind: credential.account.kind, expiresAt: credential.expiresAt }
            : { ready: false };
    }
    forget(accountName, sessionKey) {
        return this.credentials.delete(key(requireAccessName(accountName), sessionKey));
    }
    setCookies(accountName, sessionKey, cookies) {
        const credential = this.resolve(accountName, sessionKey);
        credential.cookies = cookies.map((cookie) => cookie.split(";", 1)[0]).filter(Boolean).slice(0, 32);
    }
    clear() {
        this.tickets.clear();
        this.credentials.clear();
    }
}
//# sourceMappingURL=access.js.map