export type SmartAccessImport = {
    kind: "ssh";
    name: string;
    host: string;
    port: number;
    username: string;
    password: string;
    allowedRoots: string[];
    expectedFingerprint?: string;
} | {
    kind: "api-basic";
    name: string;
    origin: string;
    username: string;
    password: string;
    allowedPathPrefixes: string[];
} | {
    kind: "api-token";
    name: string;
    origin: string;
    token: string;
    authHeader: "Authorization" | "X-API-Key";
    authPrefix: string;
    allowedPathPrefixes: string[];
} | {
    kind: "web-https";
    name: string;
    origin: string;
    loginPath: string;
    usernameField: string;
    passwordField: string;
    bodyMode: "json" | "form";
    allowedPathPrefixes: string[];
    username: string;
    password: string;
} | {
    kind: "web-via-ssh";
    name: string;
    sshAccount: string;
    targetHost: string;
    targetPort: number;
    loginPath: string;
    usernameField: string;
    passwordField: string;
    bodyMode: "json" | "form";
    allowedPathPrefixes: string[];
    username: string;
    password: string;
};
export declare function deriveSshAccountName(username: string, host: string, port: number): string;
export declare function parseSmartAccessInput(input: string): SmartAccessImport;
