import { createHash } from 'node:crypto';
import path from 'node:path';
const TYPE = 0o170000, FILE = 0o100000, DIR = 0o040000;
const MAX_MOVE_BYTES = 512 * 1024 * 1024;
const hash = (data) => createHash('sha256').update(data).digest('hex');
const within = (p, roots) => roots.some(r => p === r || p.startsWith(r + '/'));
const stat = (s, p) => new Promise((resolve, reject) => s.lstat(p, (e, a) => e ? reject(e) : resolve(a)));
const real = (s, p) => new Promise((resolve, reject) => s.realpath(p, (e, a) => e ? reject(e) : resolve(a)));
async function absent(s, p) {
    try {
        await stat(s, p);
    }
    catch (e) {
        if (e.code === 2)
            return;
        throw e;
    }
    throw new Error('destination already exists; refusing overwrite: ' + p);
}
/** New operations never follow symlinks, including symlinked parent directories. */
export async function safeFilePath(s, scope, value) {
    if (!value.startsWith('/') || value.includes('\0') || value.split('/').includes('..'))
        throw new Error('path must be absolute, without NUL or parent traversal');
    const p = path.posix.normalize(value);
    const roots = scope.allowedRoots.map(r => path.posix.normalize(r).replace(/\/$/, ''));
    if (!within(p, roots) || roots.includes(p))
        throw new Error('path must be below an allowed root');
    const parent = path.posix.dirname(p);
    let current = '';
    for (const part of parent.split('/').filter(Boolean)) {
        current += '/' + part;
        if (((await stat(s, current)).mode & TYPE) !== DIR)
            throw new Error('parent must be a directory, not a symlink: ' + current);
    }
    const [canonical, ...canonicalRoots] = await Promise.all([real(s, parent), ...roots.map(r => real(s, r))]);
    if (!within(canonical, canonicalRoots.map(r => r.replace(/\/$/, ''))))
        throw new Error('parent resolves outside allowed roots');
    return path.posix.join(canonical, path.posix.basename(p));
}
async function streamHash(s, p, limit) {
    const stream = s.createReadStream(p, { highWaterMark: 64 * 1024 });

    // Оставляем защитный listener на всё время жизни ReadStream.
    // Async iterator продолжает получать ошибку операции, но поздний
    // error при закрытии SFTP-канала больше не становится fatal для Gateway.
    stream.on("error", () => {});

    const digest = createHash('sha256');
    let bytes = 0;
    const timeout = setTimeout(() => stream.destroy(new Error('SFTP file verification timed out')), 120_000);
    timeout.unref();
    try {
        for await (const chunk of stream) {
            const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            bytes += data.length;
            if (bytes > limit)
                throw new Error('file exceeds byte limit');
            digest.update(data);
        }
    }
    finally {
        clearTimeout(timeout);
        stream.destroy();
    }
    return { sha256: digest.digest('hex'), bytes };
}
export async function createRemoteFile(s, scope, requested, content) {
    const data = Buffer.from(content, 'utf8');
    if (data.toString('utf8') !== content)
        throw new Error('content contains invalid Unicode');
    if (data.length > Math.min(scope.maxFileBytes, 262144))
        throw new Error('content exceeds maxFileBytes');
    const p = await safeFilePath(s, scope, requested);
    await absent(s, p);
    // SSH_FXF_EXCL atomically refuses a concurrently created target (including symlinks).
    await new Promise((resolve, reject) => s.writeFile(p, data, { flag: 'wx', mode: 0o600 }, e => e ? reject(e) : resolve()));
    const verified = await streamHash(s, p, data.length);
    if (verified.sha256 !== hash(data) || verified.bytes !== data.length)
        throw new Error('file created but verification failed; inspect before retrying: ' + p);
    return { path: p, ...verified, created: true };
}
export async function createRemoteDirectory(s, scope, requested) {
    const p = await safeFilePath(s, scope, requested);
    try {
        const attrs = await stat(s, p);
        if ((attrs.mode & TYPE) !== DIR)
            throw new Error('destination is not a directory');
        return { path: p, created: false };
    }
    catch (e) {
        if (e.code !== 2)
            throw e;
    }
    await new Promise((resolve, reject) => s.mkdir(p, { mode: 0o700 }, e => e ? reject(e) : resolve()));
    if (((await stat(s, p)).mode & TYPE) !== DIR)
        throw new Error('directory verification failed');
    return { path: p, created: true };
}
export async function moveRemoteFile(s, scope, from, to, expectedSha256) {
    if (expectedSha256 !== undefined && !/^[a-f0-9]{64}$/.test(expectedSha256))
        throw new Error('invalid expectedSha256');
    const source = await safeFilePath(s, scope, from);
    const destination = await safeFilePath(s, scope, to);
    if (source === destination)
        throw new Error('source and destination must differ');
    const attrs = await stat(s, source);
    if ((attrs.mode & TYPE) !== FILE)
        throw new Error('source must be a regular file, not a symlink');
    if (attrs.size > MAX_MOVE_BYTES)
        throw new Error('move limit is 512 MiB');
    await absent(s, destination);
    const before = await streamHash(s, source, MAX_MOVE_BYTES);
    if (expectedSha256 && before.sha256 !== expectedSha256)
        throw new Error('source SHA-256 changed');
    const latest = await stat(s, source);
    if ((latest.mode & TYPE) !== FILE || latest.size !== before.bytes)
        throw new Error('source changed during verification');
    await absent(s, destination);
    // Standard SFTP v3 RENAME forbids overwriting. Do NOT use posix-rename extension.
    // No copy/delete fallback across filesystems: failed rename preserves source.
    await new Promise((resolve, reject) => s.rename(source, destination, e => e ? reject(e) : resolve()));
    try {
        if (((await stat(s, destination)).mode & TYPE) !== FILE)
            throw new Error('destination is not a regular file');
        const after = await streamHash(s, destination, MAX_MOVE_BYTES);
        if (before.sha256 !== after.sha256 || before.bytes !== after.bytes)
            throw new Error('content changed');
        return { source, destination, ...after, moved: true };
    }
    catch (e) {
        throw new Error('rename completed but verification failed; inspect destination before retrying: ' + destination + '; ' + String(e));
    }
}
//# sourceMappingURL=file-ops.js.map