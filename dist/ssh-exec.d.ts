import type { Client } from "ssh2";
export type ExecInput = {
    command: string;
    cwd: string;
    timeoutSeconds: number;
};
export type ExecResult = {
    stdout: string;
    stderr: string;
    exitCode: number | null;
    signal: string | null;
    truncated: boolean;
    timedOut: boolean;
};
export declare function validateExecInput(raw: Record<string, unknown>): ExecInput;
export declare function shellQuote(value: string): string;
export declare function buildExecCommand(input: ExecInput): string;
export declare function executeSshCommand(client: Client, input: ExecInput, password: string, abort?: AbortSignal): Promise<ExecResult>;
