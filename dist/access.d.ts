export type AccessKind = "api-basic" | "api-token" | "web-https" | "web-via-ssh";
export type ApiBasicAccount = {
    kind: "api-basic";
    origin: string;
    allowedPathPrefixes: string[];
    maxResponseBytes: number;
};
export type ApiTokenAccount = {
    kind: "api-token";
    origin: string;
    authHeader: "Authorization" | "X-API-Key";
    authPrefix: string;
    allowedPathPrefixes: string[];
    maxResponseBytes: number;
};
export type WebHttpsAccount = {
    kind: "web-https";
    origin: string;
    loginPath: string;
    usernameField: string;
    passwordField: string;
    bodyMode: "json" | "form";
    allowedPathPrefixes: string[];
    maxResponseBytes: number;
};
export type WebViaSshAccount = {
    kind: "web-via-ssh";
    sshAccount: string;
    targetHost: string;
    targetPort: number;
    loginPath: string;
    usernameField: string;
    passwordField: string;
    bodyMode: "json" | "form";
    allowedPathPrefixes: string[];
    maxResponseBytes: number;
};
export type AccessAccount = ApiBasicAccount | ApiTokenAccount | WebHttpsAccount | WebViaSshAccount;
export type AccessCredential = {
    account: AccessAccount;
    username: string;
    password: string;
    expiresAt: number;
    sessionKey: string;
    cookies: string[];
};
type AccessTicket = {
    expiresAt: number;
    sessionKey: string;
    selectedKind?: AccessKind | "ssh";
    staged?: {
        name: string;
        account: AccessAccount;
    };
    stagedCredential?: {
        username: string;
        password: string;
    };
    formNonceSha256s?: string[];
};
export type AccessSummary = {
    account: string;
    kind: AccessKind;
    endpoint: string;
    ready: boolean;
    expiresAt: number;
};
export declare function requireAccessName(value: string): string;
export declare function normalizeHttpsOrigin(value: string): string;
export declare function normalizeHttpPath(value: string, label?: string): string;
export declare function normalizePathPrefixes(values: string[]): string[];
export declare function isHttpPathAllowed(value: string, prefixes: string[]): boolean;
export declare function normalizeRemoteWebHost(value: string): string;
export declare function requireFieldName(value: string, label: string): string;
export declare function buildApiBasicAccount(input: {
    origin: string;
    allowedPathPrefixes: string[];
    maxResponseBytes?: number;
}): ApiBasicAccount;
export declare function buildApiTokenAccount(input: {
    origin: string;
    authHeader: "Authorization" | "X-API-Key";
    authPrefix?: string;
    allowedPathPrefixes: string[];
    maxResponseBytes?: number;
}): ApiTokenAccount;
export declare function buildWebHttpsAccount(input: {
    origin: string;
    loginPath: string;
    usernameField: string;
    passwordField: string;
    bodyMode: "json" | "form";
    allowedPathPrefixes: string[];
    maxResponseBytes?: number;
}): WebHttpsAccount;
export declare function buildWebViaSshAccount(input: {
    sshAccount: string;
    targetHost: string;
    targetPort: number;
    loginPath: string;
    usernameField: string;
    passwordField: string;
    bodyMode?: "json" | "form";
    allowedPathPrefixes: string[];
    maxResponseBytes?: number;
}): WebViaSshAccount;
export declare class AccessVault {
    private readonly credentialTtlSeconds;
    private readonly ticketTtlSeconds;
    private readonly tickets;
    private readonly credentials;
    constructor(credentialTtlSeconds: number, ticketTtlSeconds: number);
    sweep(now?: number): void;
    createTicket(sessionKey: string): {
        token: string;
        expiresAt: number;
    };
    ticket(token: string): AccessTicket | undefined;
    choose(token: string, kind: AccessKind | "ssh"): void;
    consumeForSsh(token: string): string;
    stage(token: string, name: string, account: AccessAccount, credential?: {
        username: string;
        password: string;
    }): void;
    issueNonce(token: string): string;
    verifyNonce(token: string, nonce: string): boolean;
    submit(token: string, username?: string, password?: string): {
        account: string;
        expiresAt: number;
    };
    resolve(accountName: string, sessionKey: string): AccessCredential;
    list(sessionKey: string): AccessSummary[];
    status(accountName: string, sessionKey: string): {
        ready: boolean;
        kind?: AccessKind;
        expiresAt?: number;
    };
    forget(accountName: string, sessionKey: string): boolean;
    setCookies(accountName: string, sessionKey: string, cookies: string[]): void;
    clear(): void;
}
export {};
