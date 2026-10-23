const MAX_OUTPUT = 256 * 1024;
export function validateExecInput(raw) {
    const { command, cwd } = raw;
    const timeoutSeconds = raw.timeoutSeconds ?? 120;
    if (typeof command !== "string" || !command.trim() || command.length > 32768 || command.includes("\0"))
        throw new Error("Invalid command");
    if (typeof cwd !== "string" || !cwd.startsWith("/") || cwd.length > 4096 || /[\0\r\n]/.test(cwd))
        throw new Error("cwd must be an absolute path");
    if (!Number.isInteger(timeoutSeconds) || timeoutSeconds < 1 || timeoutSeconds > 300)
        throw new Error("timeoutSeconds must be 1..300");
    return { command, cwd, timeoutSeconds: timeoutSeconds };
}
export function shellQuote(value) { return "'" + value.replaceAll("'", "'\\''") + "'"; }
export function buildExecCommand(input) {
    // GNU timeout supervises the process group independently of the SSH client.
    // cwd is starting location, deliberately NOT claimed as a security boundary.
    return `exec timeout --signal=TERM --kill-after=5s ${input.timeoutSeconds}s sh -c ${shellQuote(`cd -- ${shellQuote(input.cwd)} && {\n${input.command}\n}`)}`;
}
export async function executeSshCommand(client, input, password, abort) {
    if (abort?.aborted)
        throw new Error("SSH command aborted");
    return await new Promise((resolve, reject) => {
        let channel;
        let settled = false;
        let bytes = 0;
        let truncated = false;
        const stdout = [], stderr = [];
        const redact = (s) => password ? s.split(password).join("[REDACTED]") : s;
        const append = (target, chunk) => {
            const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            const take = Math.max(0, Math.min(data.length, MAX_OUTPUT - bytes));
            if (take)
                target.push(data.subarray(0, take));
            bytes += take;
            if (take < data.length)
                truncated = true;
        };
        const finish = (error, result) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timer);
            abort?.removeEventListener("abort", onAbort);
            client.off("error", onClientError);
            client.off("close", onClientClose);
            if (error)
                reject(new Error(redact(error.message)));
            else
                resolve(result);
        };
        const stop = () => { try {
            channel?.signal("TERM");
        }
        catch { } channel?.close(); };
        const onAbort = () => { stop(); finish(new Error("SSH command aborted; remote timeout remains the fallback deadline")); };
        const onClientError = (err) => finish(err);
        const onClientClose = () => finish(new Error("SSH connection closed before command completion; remote outcome unknown"));
        const timer = setTimeout(() => { stop(); finish(new Error("SSH command transport deadline exceeded; remote outcome unknown")); }, (input.timeoutSeconds + 10) * 1000);
        abort?.addEventListener("abort", onAbort, { once: true });
        client.on("error", onClientError);
        client.on("close", onClientClose);
        client.exec(buildExecCommand(input), (error, stream) => {
            if (settled) {
                if (stream) {
                    try {
                        stream.signal("TERM");
                    }
                    catch { }
                    stream.close();
                }
                return;
            }
            if (error) {
                finish(error);
                return;
            }
            channel = stream;
            stream.on("data", (chunk) => append(stdout, chunk));
            stream.stderr.on("data", (chunk) => append(stderr, chunk));
            stream.once("error", (err) => finish(err));
            stream.once("close", (code, signal) => {
                // Drop a trailing partial secret at the bounded-output boundary.
                const output = (chunks) => {
                    let value = Buffer.concat(chunks).toString("utf8");
                    if (truncated && password)
                        for (let n = Math.min(password.length - 1, value.length); n > 0; n--) {
                            if (value.endsWith(password.slice(0, n))) {
                                value = value.slice(0, -n) + "[REDACTED]";
                                break;
                            }
                        }
                    return redact(value);
                };
                finish(undefined, { stdout: output(stdout), stderr: output(stderr), exitCode: typeof code === "number" ? code : null, signal: signal ?? null, truncated, timedOut: code === 124 });
            });
            stream.end(); // Explicit EOF: non-interactive commands cannot wait for input.
        });
    });
}
//# sourceMappingURL=ssh-exec.js.map