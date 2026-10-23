import { createHash } from "node:crypto";
const KEY_ALIASES = {
    type: "type",
    kind: "type",
    тип: "type",
    name: "name",
    id: "name",
    имя: "name",
    название: "name",
    identifier: "apiKey",
    идентификатор: "apiKey",
    url: "url",
    uri: "url",
    origin: "url",
    endpoint: "url",
    address: "url",
    адрес: "url",
    ссылка: "url",
    example_url: "url",
    url_example: "url",
    пример_url: "url",
    пример_ссылки: "url",
    host: "host",
    hostname: "host",
    server: "host",
    ip: "host",
    ip_address: "host",
    ip_адрес: "host",
    адрес_ip: "host",
    айпи: "host",
    айпи_адрес: "host",
    хост: "host",
    сервер: "host",
    port: "port",
    порт: "port",
    user: "username",
    username: "username",
    user_name: "username",
    login: "username",
    имя_пользователя: "username",
    логин: "username",
    пользователь: "username",
    password: "password",
    pass: "password",
    пароль: "password",
    api_key: "apiKey",
    apikey: "apiKey",
    api_id: "apiKey",
    key: "apiKey",
    ключ: "apiKey",
    token: "token",
    bearer: "token",
    токен: "token",
    secret: "password",
    api_secret: "password",
    api_password: "password",
    секрет: "password",
    root: "paths",
    roots: "paths",
    path: "paths",
    paths: "paths",
    directory: "paths",
    directories: "paths",
    каталог: "paths",
    каталоги: "paths",
    путь: "paths",
    пути: "paths",
    fingerprint: "fingerprint",
    host_key: "fingerprint",
    отпечаток: "fingerprint",
    ssh: "sshAccount",
    ssh_id: "sshAccount",
    ssh_account: "sshAccount",
    ssh_connection: "sshAccount",
    username_field: "usernameField",
    login_field: "usernameField",
    поле_логина: "usernameField",
    password_field: "passwordField",
    поле_пароля: "passwordField",
    login_path: "loginPath",
    login_endpoint: "loginPath",
    путь_входа: "loginPath",
    body: "bodyMode",
    body_mode: "bodyMode",
    encoding: "bodyMode",
    format: "bodyMode",
    формат: "bodyMode",
    auth: "auth",
    authorization: "auth",
    header: "auth",
    заголовок: "auth",
};
function normalizedKey(value) {
    return value.trim().toLowerCase().replace(/[\s.-]+/g, "_");
}
function parseFields(input) {
    const fields = {};
    const freeLines = [];
    const rawLines = input.split(/\r?\n/);
    for (let index = 0; index < rawLines.length; index += 1) {
        const rawLine = rawLines[index];
        const line = rawLine.trim();
        if (!line)
            continue;
        if (/^(?:ssh|sftp|https?):\/\//i.test(line)) {
            freeLines.push(line);
            continue;
        }
        const standaloneAlias = KEY_ALIASES[normalizedKey(line)];
        if (standaloneAlias) {
            let valueIndex = index + 1;
            while (valueIndex < rawLines.length && !rawLines[valueIndex].trim())
                valueIndex += 1;
            const value = rawLines[valueIndex]?.trim();
            if (value) {
                (fields[standaloneAlias] ??= []).push(value);
                index = valueIndex;
                continue;
            }
        }
        const match = /^([^:=]{1,48})\s*[:=]\s*(.*)$/.exec(line);
        const alias = match ? KEY_ALIASES[normalizedKey(match[1])] : undefined;
        if (!match || !alias) {
            freeLines.push(line);
            continue;
        }
        const value = match[2].trim();
        if (!value)
            continue;
        (fields[alias] ??= []).push(value);
    }
    return { fields, freeLines };
}
function first(fields, name) {
    return fields[name]?.[0]?.trim() || undefined;
}
function required(value, label) {
    if (!value)
        throw new Error(`Не удалось распознать ${label}. Добавьте строку «${label}: …».`);
    return value;
}
function slug(value, fallback) {
    const ascii = value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "");
    const candidate = /^[a-z]/.test(ascii) ? ascii : `${fallback}-${ascii}`;
    return (candidate || fallback).slice(0, 64).replace(/-+$/g, "") || fallback;
}
function normalizedSshIdentityHost(value) {
    return value.trim().replace(/^\[|\]$/g, "").toLowerCase();
}
export function deriveSshAccountName(username, host, port) {
    const normalizedHost = normalizedSshIdentityHost(host);
    const identity = `ssh\0${username}\0${normalizedHost}\0${port}`;
    const digest = createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 16);
    const readable = slug(`ssh-${username}-${normalizedHost}-p${port}`, "ssh");
    const maxReadableLength = 64 - digest.length - 1;
    const prefix = readable.slice(0, maxReadableLength).replace(/[-_]+$/g, "") || "ssh";
    return `${prefix}-${digest}`;
}
function splitValues(values) {
    return (values ?? [])
        .flatMap((value) => value.split(/\s*[,;]\s*/))
        .map((value) => value.trim())
        .filter(Boolean);
}
function findUrl(fields, freeLines) {
    const explicit = first(fields, "url");
    if (explicit)
        return explicit;
    for (const line of freeLines) {
        const match = /(?:ssh|sftp|https?):\/\/[^\s]+/i.exec(line);
        if (match)
            return match[0];
    }
    return undefined;
}
function findBareSshTarget(freeLines) {
    for (const line of freeLines) {
        const candidate = line.trim();
        if (!candidate || /[\s/@?#]/.test(candidate))
            continue;
        try {
            const url = new URL(`ssh://${candidate}`);
            const hostname = url.hostname.replace(/^\[|\]$/g, "");
            const looksLikeNetworkHost = hostname === "localhost" || hostname.includes(".") || hostname.includes(":");
            if (!looksLikeNetworkHost || url.username || url.password || url.pathname !== "" || url.search || url.hash)
                continue;
            return { host: hostname, ...(url.port ? { port: url.port } : {}) };
        }
        catch {
            // Ignore ordinary free text; only an unambiguous bare host is an SSH signal.
        }
    }
    return undefined;
}
function parseUrl(value, label) {
    try {
        return new URL(value);
    }
    catch {
        throw new Error(`${label} должен быть полным URL со схемой.`);
    }
}
function pathPrefix(pathname) {
    if (!pathname || pathname === "/")
        return "/";
    if (pathname.endsWith("/"))
        return pathname;
    const slash = pathname.lastIndexOf("/");
    return slash <= 0 ? "/" : pathname.slice(0, slash + 1);
}
function detectType(fields, freeLines, urlText) {
    const explicit = first(fields, "type")?.toLowerCase() ?? "";
    if (/ssh|sftp|ссш/.test(explicit))
        return "ssh";
    if (/basic/.test(explicit))
        return "api-basic";
    if (/token|bearer|api.?key|ключ|токен/.test(explicit))
        return "api-token";
    if (/^(?:api|апи)$/.test(explicit))
        return first(fields, "token") || (first(fields, "apiKey") && !first(fields, "password")) ? "api-token" : "api-basic";
    if (/admin|web|cms|админ/.test(explicit))
        return first(fields, "sshAccount") ? "web-via-ssh" : "web-https";
    if (urlText && /^(ssh|sftp):/i.test(urlText))
        return "ssh";
    if (freeLines.some((line) => /^ssh\s+(?:-[^\s]+\s+)*[^\s@]+@[^\s]+/i.test(line)))
        return "ssh";
    if (first(fields, "host") && !urlText)
        return "ssh";
    if (!urlText && first(fields, "username") && first(fields, "password") && findBareSshTarget(freeLines))
        return "ssh";
    if (first(fields, "token"))
        return "api-token";
    if (/^bearer\s+\S+/i.test(first(fields, "auth") ?? ""))
        return "api-token";
    if (first(fields, "apiKey"))
        return first(fields, "password") ? "api-basic" : "api-token";
    if (first(fields, "sshAccount"))
        return "web-via-ssh";
    if (urlText) {
        const url = parseUrl(urlText, "URL");
        if (/myinsales\./i.test(url.hostname))
            return "api-basic";
        return "web-https";
    }
    throw new Error("Тип доступа не распознан. Укажите «type: ssh», «type: admin» или «type: api-key».");
}
function parseSsh(fields, freeLines, urlText) {
    let host = first(fields, "host");
    let portText = first(fields, "port");
    let username = first(fields, "username");
    let password = first(fields, "password");
    const paths = splitValues(fields.paths);
    if (urlText && /^(ssh|sftp):/i.test(urlText)) {
        const url = parseUrl(urlText, "SSH URL");
        host ??= url.hostname;
        portText ??= url.port || "22";
        username ??= decodeURIComponent(url.username);
        password ??= url.password ? decodeURIComponent(url.password) : undefined;
        if (url.pathname && url.pathname !== "/")
            paths.push(decodeURIComponent(url.pathname));
        for (const root of url.searchParams.getAll("root"))
            paths.push(root);
    }
    const command = freeLines.map((line) => /(?:^|\s)ssh\s+(?:(?:-p\s+(\d+))\s+)?([^\s@]+)@([^\s:]+)(?::(\d+))?/i.exec(line)).find(Boolean);
    if (command) {
        portText ??= command[1] || command[4] || "22";
        username ??= command[2];
        host ??= command[3];
    }
    const bareTarget = findBareSshTarget(freeLines);
    if (bareTarget) {
        host ??= bareTarget.host;
        portText ??= bareTarget.port;
    }
    const finalHost = required(host, "host");
    const finalUsername = required(username, "login");
    const port = Number(portText ?? 22);
    if (!Number.isInteger(port))
        throw new Error("SSH port должен быть целым числом.");
    return {
        kind: "ssh",
        // The automatic ID is scoped to the SSH endpoint and login, with a stable
        // hash suffix so punctuation normalization and truncation cannot silently
        // merge different endpoints. Callers can still provide a readable alias
        // explicitly with `name:` / `id:`; occupied aliases are rejected later.
        name: first(fields, "name")
            ? slug(first(fields, "name"), "ssh")
            : deriveSshAccountName(finalUsername, finalHost, port),
        host: finalHost,
        port,
        username: finalUsername,
        password: required(password, "password"),
        // Do not guess /home/<login>. Shared hosting often maps the authenticated
        // account to a different absolute home. The broker discovers it over the
        // authenticated SFTP session before storing the connection.
        allowedRoots: paths,
        ...(first(fields, "fingerprint") ? { expectedFingerprint: first(fields, "fingerprint") } : {}),
    };
}
function parseHttpUrl(fields, freeLines, urlText) {
    const url = parseUrl(required(urlText ?? findUrl(fields, freeLines), "url"), "URL");
    if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new Error("Для API или админки нужен HTTP(S) URL.");
    }
    const username = url.username ? decodeURIComponent(url.username) : undefined;
    const password = url.password ? decodeURIComponent(url.password) : undefined;
    url.username = "";
    url.password = "";
    return { url, username, password };
}
function parseBodyMode(value, pathname) {
    const normalized = value?.toLowerCase() ?? "";
    if (/form|urlencoded|форма/.test(normalized))
        return "form";
    if (/json/.test(normalized))
        return "json";
    return /(?:^|\/)api(?:\/|$)/i.test(pathname) ? "json" : "form";
}
function parseApiBasic(fields, freeLines, urlText) {
    const parsed = parseHttpUrl(fields, freeLines, urlText);
    if (parsed.url.protocol !== "https:")
        throw new Error("Basic API разрешён только по HTTPS.");
    const username = first(fields, "apiKey") ?? first(fields, "username") ?? parsed.username;
    const password = first(fields, "password") ?? parsed.password;
    const paths = splitValues(fields.paths);
    if (paths.length === 0)
        paths.push(parsed.url.pathname === "/" && /myinsales\./i.test(parsed.url.hostname) ? "/admin/" : pathPrefix(parsed.url.pathname));
    const origin = parsed.url.origin;
    return {
        kind: "api-basic",
        name: slug(first(fields, "name") ?? parsed.url.hostname.split(".")[0] ?? "api", "api"),
        origin,
        username: required(username, "api_key/login"),
        password: required(password, "password/secret"),
        allowedPathPrefixes: paths,
    };
}
function parseApiToken(fields, freeLines, urlText) {
    const parsed = parseHttpUrl(fields, freeLines, urlText);
    if (parsed.url.protocol !== "https:")
        throw new Error("API token разрешён только по HTTPS.");
    const tokenFromAuth = first(fields, "auth")?.match(/^bearer\s+(.+)$/i)?.[1];
    const token = first(fields, "token") ?? first(fields, "apiKey") ?? tokenFromAuth ?? parsed.password;
    const auth = first(fields, "auth")?.toLowerCase() ?? "";
    const useApiKeyHeader = /x-api-key|api.?key|ключ/.test(auth) || Boolean(first(fields, "apiKey") && !first(fields, "token"));
    const paths = splitValues(fields.paths);
    if (paths.length === 0)
        paths.push(pathPrefix(parsed.url.pathname));
    return {
        kind: "api-token",
        name: slug(first(fields, "name") ?? parsed.url.hostname.split(".")[0] ?? "api", "api"),
        origin: parsed.url.origin,
        token: required(token, "api_key/token"),
        authHeader: useApiKeyHeader ? "X-API-Key" : "Authorization",
        authPrefix: useApiKeyHeader ? "" : "Bearer",
        allowedPathPrefixes: paths,
    };
}
function parseWeb(fields, freeLines, urlText, viaSsh) {
    const parsed = parseHttpUrl(fields, freeLines, urlText);
    const username = first(fields, "username") ?? parsed.username;
    const password = first(fields, "password") ?? parsed.password;
    const loginPath = first(fields, "loginPath") ?? `${parsed.url.pathname}${parsed.url.search}`;
    const paths = splitValues(fields.paths);
    if (paths.length === 0)
        paths.push(pathPrefix(parsed.url.pathname));
    const common = {
        name: slug(first(fields, "name") ?? parsed.url.hostname.split(".")[0] ?? "admin", "admin"),
        loginPath,
        usernameField: first(fields, "usernameField") ?? "login",
        passwordField: first(fields, "passwordField") ?? "password",
        bodyMode: parseBodyMode(first(fields, "bodyMode"), parsed.url.pathname),
        allowedPathPrefixes: paths,
        username: required(username, "login"),
        password: required(password, "password"),
    };
    if (viaSsh) {
        return {
            kind: "web-via-ssh",
            ...common,
            sshAccount: required(first(fields, "sshAccount"), "ssh_account"),
            targetHost: parsed.url.hostname,
            targetPort: Number(parsed.url.port || (parsed.url.protocol === "https:" ? 443 : 80)),
        };
    }
    if (parsed.url.protocol !== "https:") {
        throw new Error("Прямая веб-админка должна использовать HTTPS; для HTTP добавьте ssh_account.");
    }
    return {
        kind: "web-https",
        ...common,
        origin: parsed.url.origin,
    };
}
export function parseSmartAccessInput(input) {
    const text = input.trim();
    if (!text || text.length > 16_384) {
        throw new Error("Блок доступа пустой или длиннее 16 КБ.");
    }
    const { fields, freeLines } = parseFields(text);
    const urlText = findUrl(fields, freeLines);
    const kind = detectType(fields, freeLines, urlText);
    if (kind === "ssh")
        return parseSsh(fields, freeLines, urlText);
    if (kind === "api-basic")
        return parseApiBasic(fields, freeLines, urlText);
    if (kind === "api-token")
        return parseApiToken(fields, freeLines, urlText);
    return parseWeb(fields, freeLines, urlText, kind === "web-via-ssh");
}
//# sourceMappingURL=smart-import.js.map