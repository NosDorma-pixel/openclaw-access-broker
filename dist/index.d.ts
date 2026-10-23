import { AccessVault } from "./access.js";
import { type SmartAccessImport } from "./smart-import.js";
export type BrokerAccount = {
    host: string;
    port: number;
    username: string;
    configuredPassword?: string;
    hostKeySha256Hex: string;
    allowedRoots: string[];
    readyTimeoutMs: number;
    maxFileBytes: number;
};
export declare const ACCESS_BROKER_VERSION = "0.8.2";
export declare function normalizeHostKeySha256(value: string): string;
export declare function normalizeRemotePath(value: string): string;
export declare function isPathWithinRoots(candidate: string, roots: string[]): boolean;
type ImportedSshAccess = Extract<SmartAccessImport, {
    kind: "ssh";
}>;
export declare function resolveConfiguredSshImport(imported: ImportedSshAccess, accounts: Record<string, BrokerAccount>): {
    name: string;
    account: BrokerAccount;
} | undefined;
export declare function assertConfiguredSshImportMatches(imported: ImportedSshAccess, configured: BrokerAccount): void;
export declare function replaceExactlyOnce(content: string, find: string, replacement: string): string;
export declare function normalizeDynamicHost(value: string): string;
export declare function buildDynamicAccount(input: {
    host: string;
    port: number;
    username: string;
    hostKeySha256: string;
    allowedRoots: string[];
}): BrokerAccount;
export declare function assertDiskAuditAccount(account: BrokerAccount): void;
export declare function buildDiskAuditCommand(): string;
export declare function scanHostKey(host: string, port: number, timeoutMs?: number): Promise<string>;
type RuntimeCredential = {
    password: string;
    expiresAt: number;
    sessionKey: string;
    account: BrokerAccount;
    dynamic: boolean;
    execEnabled?: boolean;
};
type LoginTicket = {
    accountName?: string;
    presetAccount?: BrokerAccount;
    stagedDynamic?: {
        name: string;
        account: BrokerAccount;
        discoverHome?: boolean;
    };
    stagedPassword?: string;
    expiresAt: number;
    sessionKey: string;
    formNonceSha256s?: string[];
};
type ConnectionSummary = {
    account: string;
    host: string;
    port: number;
    username: string;
    allowedRoots: string[];
    dynamic: boolean;
    ready: boolean;
    execEnabled?: boolean;
    expiresAt?: number;
};
export declare class RuntimeCredentialVault {
    private readonly credentialTtlSeconds;
    private readonly ticketTtlSeconds;
    private readonly credentials;
    private readonly tickets;
    constructor(credentialTtlSeconds: number, ticketTtlSeconds: number);
    sweep(now?: number): void;
    createTicket(accountName: string | undefined, sessionKey: string, presetAccount?: BrokerAccount): {
        token: string;
        expiresAt: number;
    };
    ticket(token: string): LoginTicket | undefined;
    issueFormNonce(token: string): string;
    verifyFormNonce(token: string, nonce: string): boolean;
    stageDynamic(token: string, name: string, account: BrokerAccount, password?: string, discoverHome?: boolean): void;
    stagePresetPassword(token: string, password: string): void;
    submit(token: string, password?: string, execEnabled?: boolean): {
        account: string;
        expiresAt: number;
    };
    resolve(accountName: string, configuredAccount: BrokerAccount | undefined, sessionKey: string): RuntimeCredential;
    status(accountName: string, configuredAccount: BrokerAccount | undefined, sessionKey: string): {
        ready: boolean;
        expiresAt?: number;
        dynamic?: boolean;
        execEnabled?: boolean;
    };
    list(configuredAccounts: Record<string, BrokerAccount>, sessionKey: string): ConnectionSummary[];
    forget(accountName: string, sessionKey: string): boolean;
    clear(): void;
}
type SharedCredentialVaultState = {
    schemaVersion?: number;
    credentialTtlSeconds: number;
    ticketTtlSeconds: number;
    vault: RuntimeCredentialVault;
    accessVault: AccessVault;
    sweepTimer: NodeJS.Timeout;
};
/**
 * Plugin command and agent-tool registries can coexist as separate runtime
 * generations. Keep their short-lived credentials in one process-local vault
 * while preserving the existing per-session keys inside each vault.
 */
export declare function getSharedCredentialVaults(credentialTtlSeconds: number, ticketTtlSeconds: number): Pick<SharedCredentialVaultState, "vault" | "accessVault">;
export declare function discoverSshRoots(account: BrokerAccount, password: string, requestedRoots: string[], signal?: AbortSignal): Promise<string[]>;
export declare function parseExecConsent(form: URLSearchParams): boolean;
export declare function sshExecConsentHtml(): string;
export declare function isTrustedFormPost(expectedOrigin: string, originHeader: string, secFetchSite: string): boolean;
export declare function createAccessLoginCommandHandler(createLogin: (sessionKey: string) => Promise<{
    url: string;
    expiresAt: string;
}>): (context: {
    sessionKey?: string;
}) => Promise<{
    text: string;
    presentation: {
        blocks: {
            type: "buttons";
            buttons: {
                label: string;
                action: {
                    type: "web-app";
                    url: string;
                };
            }[];
        }[];
    };
}>;
export declare function formatCredentialTtlRu(seconds: number): string;
declare const _default: Omit<{
    id: string;
    name: string;
    description: string;
    kind?: import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginDefinition["kind"];
    configSchema?: import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginConfigSchema | (() => import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginConfigSchema);
    reload?: import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginDefinition["reload"];
    nodeHostCommands?: import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginDefinition["nodeHostCommands"];
    securityAuditCollectors?: import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginDefinition["securityAuditCollectors"];
    register: NonNullable<import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginDefinition["register"]>;
}, "configSchema"> & {
    configSchema: import("openclaw/plugin-sdk/plugin-entry").OpenClawPluginConfigSchema;
};
export default _default;
