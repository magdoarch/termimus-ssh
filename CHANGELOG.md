# Changelog

## Unreleased

### New
- **VNC and RDP remote desktops** in tabs, optionally through an SSH jump host; RDP shares the text clipboard.
- **Two-factor login**: keyboard-interactive prompts (OTP, Duo, PAM questions) are answered in a dialog, for terminals, SFTP, tunnels and jump hosts alike.
- **TOTP autofill**: save a host's 2FA secret (base32 or `otpauth://` URI) and the code is filled in at login; "Copy 2FA Code" in the host menu.
- **Asked when needed**: hosts without a saved password, and encrypted keys without a saved passphrase, ask at login.
- **Import `~/.ssh/config`**: hosts, keys (into the Keychain), ProxyJump chains and `~/.ssh/known_hosts` host keys, with a preview.
- **Jump host chains**: a jump host can have its own jump host (up to 8 hops).
- **Shared connections** (ControlMaster-style): one SSH connection per host for tabs, SFTP, tunnels and jump hops; falls back to a separate connection at the server's `MaxSessions`. Can be turned off.
- **Port forwarding**: remote (`-R`) and dynamic SOCKS4/4a/5 (`-D`) forwards next to local (`-L`).
- **Server dashboard**: live CPU, load, memory, swap, disks, network and uptime.
- **Docker panel**: containers with state and resource use; start/stop/restart/pause/remove, logs, and a shell tab via `docker exec`.
- **Auto-reconnect**: a dropped SSH tab reconnects in place with backoff; `exit` still closes it.
- **Reopen tabs at startup** (opt-in).
- **Session recording** to asciinema `.cast` with an in-app player and export.
- **Snippet variables** (`{{name}}`, `{{name:default}}`).
- **Install SSH key on a host** (like `ssh-copy-id`) from the Keychain or the host menu.
- **Clickable links** (Ctrl/Cmd+click) and a confirmation before multi-line pastes that would run immediately.
- **Light mode** (Dark / Light / System).
- Settings → **SSH & Sessions** for the connection and terminal options above.

### Changed
- russh upgraded from 0.50 to 0.55 (fixes connections dropping on messages for already-closed channels; adds ML-KEM key exchange).
- Connections ask the server for the host key type that is already pinned, as OpenSSH does.
- SFTP reports a server without an SFTP subsystem instead of timing out.

### Fixed
- Security: SFTP download path traversal, TOFU now fails closed, sync secrets kept in the OS keyring, stricter CSP, safer sync server defaults.
- Sync: atomic restore, credential merge, conflict detection on push.
- Jump hosts are honored for SFTP and tunnels; terminal remount and SFTP races; vault hardening; tunnel lifecycle; non-blocking crypto and PTY work; several UI fixes.
