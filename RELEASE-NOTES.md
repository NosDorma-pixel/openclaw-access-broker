# Access Broker 0.8.1 installation distribution

Assembled 2026-10-23 from the installed @local/openclaw-ssh-broker 0.8.1 runtime. Plugin id remains ssh-broker.

- Runtime JS, declarations, source maps and plugin manifest copied byte-for-byte. HTML/CSS forms are embedded; no additional static files are referenced.
- Original TypeScript checkout, tsconfig, lockfile and original source tests are not present in the installed input. Compiled test files are deliberately excluded. No TypeScript source was fabricated.
- Staging metadata removes unusable build/test scripts and devDependencies; direct runtime dependencies pin the observed installed versions 1.17.0 and 1.3.16 instead of an ssh2 range. Existing private:true, entry, peer/API compatibility and version are preserved.
- Public README replaces installed local documentation. SSH notes are rewritten without local host/project details or historical unverified test claims.
- No configuration, credentials, environment, deployment data, logs, private certificates or node_modules are copied. Only whitelisted public package files are included. Pattern inspection is a bounded review, not a formal secret/security audit.
- install.sh delegates to documented npm-pack install; no auto-force, capability acceptance, config replacement, sudo, restart, remote script download or global install. Explicit --force permits OpenClaw replacement and source trust.
- SHA256SUMS covers all release files except itself. It is an integrity list, not a signature.
- Verification scope: isolated installer scenario with a fake CLI and temporary HOME; archive manifest/runtime integrity. Not a real Gateway installation or live Telegram/SSH/API test.

License decision and real-site domain/TLS/Telegram/tool policy remain operator-owned. This distribution does not claim offline reproducibility or compatibility with every OpenClaw release.
