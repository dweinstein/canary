# canary

A filesystem honeypot for macOS. Plants fake secret files (`.env`, `id_rsa`, `credentials.json`, etc.) at mount points you choose. Any process that reads these files triggers an immediate alert — because nothing legitimate should ever touch them.

The idea: if malware, a rogue script, or an attacker with shell access starts scanning your home directory for credentials, the canary trips before they find anything real.

![Canary demo — left terminal shows alerts firing as the right terminal reads fake secret files, with a macOS notification in the top-right corner](demo.png)

## How it works

The tool runs a small server (WebDAV or NFS) that serves a virtual directory of fake-but-realistic secret files. It mounts this directory at a path you specify (e.g., `~/.secrets.d`). Every file access passes through the server, which logs the operation and fires a macOS notification.

There are no real files on disk. The mount point is a virtual filesystem backed by your server process. Nothing persists if the server stops.

## Install

Download the binary (macOS arm64):

```
curl -sL https://github.com/dweinstein/canary/releases/download/v0.1.0/canary -o /usr/local/bin/canary && chmod +x /usr/local/bin/canary
```

Or build from source:

```
go install github.com/dweinstein/canary@latest
```

## Quick start

```
canary ~/.secrets.d
```

That's it. The directory `~/.secrets.d` now contains bait files. Open another terminal and try:

```
ls ~/.secrets.d/
cat ~/.secrets.d/.env
```

You'll see alerts in the canary terminal and get a macOS notification with a sound.

Ctrl+C to stop. The mount is removed automatically.

## Two modes

| | WebDAV (default) | NFS |
|---|---|---|
| Root required | No | Yes |
| Mount type in `mount` output | `webdav` | `nfs` (blends in) |
| Server visible to attacker | Yes (same UID) | No (runs as root) |
| Attacker can kill/unmount | Yes | No |
| Multiple mount points | Yes | One per instance |

### WebDAV mode (default)

No root required. Runs entirely as your user — no sudo, no kernel extensions, no FUSE. Mounts via `mount_webdav`, which ships with macOS. Good for quick setup.

```
./canary ~/.secrets.d ~/.aws-backup ~/old-creds
```

Supports multiple mount points in one process.

**Limitation:** an attacker with the same UID can see the server process, read its logs, kill it, or unmount the filesystem.

### NFS mode

Requires root. The server and logs are invisible to unprivileged users. The mount shows up as a plain `nfs` type in `mount` output, which is unremarkable.

```
sudo ./canary -mode nfs -log /var/log/canary.log ~/.secrets.d
```

An attacker with your user account cannot:
- see the server process (owned by root)
- read the log file (0600, owned by root)
- kill the server
- unmount the filesystem

One mount point per instance. Run multiple instances for multiple directories.

### When to use which

Use WebDAV for low-friction canaries you can spin up anywhere. Use NFS for canaries that need to survive an attacker who has your user shell and is looking around.

## Flags

```
-mode webdav|nfs    Server mode (default: webdav)
-port N             Server port, 0 for random (default: 0)
-notify             macOS notifications on alerts (default: true)
-log PATH           Log to file instead of stderr
-v                  Verbose — show suppressed duplicate alerts
```

## What gets planted

The default tree in `tree.go`:

```
.env                  AWS keys, database URL, Stripe key
id_rsa                Fake SSH private key
credentials.json      GCP service account
.npmrc                npm + GitHub package tokens
.git-credentials      GitHub and GitLab PATs
config/kubeconfig     Kubernetes cluster config
config/database.yml   Rails-style database credentials
backup.sql.gz         Looks like a database dump
token.txt             Slack bot token
```

All contain obviously fake values with "canary" markers embedded. They look real enough to trigger automated credential scrapers but are clearly fake on inspection.

A `.metadata_never_index` file is included to prevent Spotlight from indexing the mount.

## Alerts

Alerts go to stderr (or `-log` file) and optionally macOS notifications.

```
[CRITICAL] READ ~/.secrets.d/.env - canary file read: /.env
[CRITICAL] READ ~/.secrets.d/id_rsa - canary file read: /id_rsa
[INFO]     READDIR ~/.secrets.d/ - directory enumeration
[CRITICAL] WRITE ~/.secrets.d/foo - write attempt on canary: /foo
```

Severity levels:
- **CRITICAL** — a file was read or a write was attempted
- **WARNING** — lower-value file accessed (e.g., `backup.sql.gz`)
- **INFO** — directory listing

Duplicate alerts for the same path+operation are suppressed for 30 seconds.

When an alert fires, `lsof` runs in the background to try to identify the accessing process (best-effort — the process may have already closed the file).

## Customizing

### Adding canary files

Edit `DefaultTree()` in `tree.go`. Adding a file is one line:

```go
File(".docker/config.json", t, SevCritical, `{"auths":{"registry.example.com":{"auth":"Y2FuYXJ5"}}}`),
```

Rebuild with `go build`.

### Adding alert outputs

Edit `alert.go`. The `Alert` method receives every alert after deduplication. Add a webhook call, write to syslog, send to a SIEM — whatever you need.

### Changing noise filters

macOS system processes probe mounted filesystems (`.DS_Store`, Spotlight, etc.). The `isNoise()` function in `server.go` filters these out. Edit it if you're getting false positives.

## Running as a launchd service

For NFS mode, a launchd plist keeps the canary running across reboots:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.local.canary</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/canary</string>
        <string>-mode</string>
        <string>nfs</string>
        <string>-log</string>
        <string>/var/log/canary.log</string>
        <string>/Users/you/.secrets.d</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

```
sudo cp com.local.canary.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.local.canary.plist
```

## Implementation

~1400 lines of Go. Zero third-party dependencies — only the standard library. Compiles to a single 8MB binary.

- `main.go` — CLI, mount/unmount lifecycle, signal handling
- `server.go` — WebDAV protocol handler (PROPFIND, GET, LOCK, etc.)
- `tree.go` — virtual file tree and default canary files
- `alert.go` — deduplication, logging, macOS notifications, process identification
- `rpc.go` — Sun RPC and XDR encoding for the NFS mode
- `nfs.go` — NFSv3 and MOUNT protocol handler

The WebDAV mode uses `net/http`. The NFS mode implements the NFSv3 wire protocol directly (Sun RPC framing, XDR serialization, MOUNT and NFS program handlers) — no libfuse, no macFUSE, no FUSE-T, no kernel extensions.
