import type { SFTPWrapper } from 'ssh2';
type Scope = {
    allowedRoots: string[];
    maxFileBytes: number;
};
/** New operations never follow symlinks, including symlinked parent directories. */
export declare function safeFilePath(s: SFTPWrapper, scope: Scope, value: string): Promise<string>;
export declare function createRemoteFile(s: SFTPWrapper, scope: Scope, requested: string, content: string): Promise<{
    created: boolean;
    sha256: string;
    bytes: number;
    path: string;
}>;
export declare function createRemoteDirectory(s: SFTPWrapper, scope: Scope, requested: string): Promise<{
    path: string;
    created: boolean;
}>;
export declare function moveRemoteFile(s: SFTPWrapper, scope: Scope, from: string, to: string, expectedSha256?: string): Promise<{
    moved: boolean;
    sha256: string;
    bytes: number;
    source: string;
    destination: string;
}>;
export {};
