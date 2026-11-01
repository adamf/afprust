# afprust

An AFP file server for classic Mac OS, written in Rust. `afprustd` speaks
AFP 2.2 over TCP/IP (AppleShare IP), the protocol used by Mac OS 8.1–9.2.2
(AppleShare Client 3.7 and later). It targets Linux, in particular a
Raspberry Pi 5 running Raspberry Pi OS Bookworm, and runs as a systemd service.

It reads **netatalk configuration files** (netatalk 3/4 `afp.conf`, and
netatalk 2 `afpd.conf` + `AppleVolumes.default`) and stores Mac metadata the
way netatalk does. You can point it at an existing netatalk setup and the
volumes keep their Finder info, comments and resource forks.

## Features

- AFP 2.2 over DSI/TCP: volumes, directories, files, data and resource
  forks, Finder info, comments, byte-range locks, deny modes, server-side
  copy (`FPCopyFile`), safe save (`FPExchangeFiles`), desktop database
  (icons, application mappings), login and server messages.
- Logins: **DHCAST128** (encrypted, Mac OS 9.0.4+ / AppleShare Client
  3.8.4+), **Cleartxt Passwrd** (older clients), **guest**. Passwords are
  checked through PAM against the normal Linux accounts.
- Home directories (`[Homes]`), per-volume `valid users`, `invalid users`,
  `rolist`, `rwlist`, `read only`, `hosts allow`/`hosts deny`, volume
  passwords, `file perm`/`directory perm`/`umask`, `veto files`,
  `invisible dots`, `vol size limit`, `follow symlinks`.
- Metadata compatible with netatalk:
  - `appledouble = ea` (the default): `user.org.netatalk.Metadata` extended
    attribute plus `._name` resource fork files (also understood by
    Mac OS X and Samba's vfs_fruit);
  - `appledouble = v2`: netatalk 2 `.AppleDouble/` directories;
  - automatic fallback to `.AppleDouble` on filesystems without xattrs
    (FAT/exFAT USB disks).
- MacRoman ↔ UTF-8 file name conversion (`/` in Mac names is stored as `:`),
  case-insensitive lookups like HFS, and netatalk-style mangling
  (`Long name#1A2B.txt`) for names that are too long or not representable
  in MacRoman.
- Type/creator from file extensions for files without Finder info
  (`extmap.conf`, netatalk format).
- Optional **AppleTalk presence**, so the server appears in the Chooser.
  It answers NBP lookups and ASP GetStatus through the Linux kernel's DDP
  stack, and the Mac then connects over TCP/IP.
- Server icon in the Chooser, stable server signature, systemd `Type=notify`
  with reload on `SIGHUP`.

## Install on a Raspberry Pi (Bookworm)

### Option A: build a .deb on the Pi

```sh
sudo apt install build-essential libpam0g-dev curl
curl https://sh.rustup.rs -sSf | sh -s -- -y && . ~/.cargo/env
cargo install cargo-deb
git clone https://github.com/adamf/afprust.git && cd afprust
cargo deb
sudo apt install ./target/debian/afprust_*_arm64.deb
```

### Option B: build the .deb elsewhere with Docker

On any machine with Docker (Apple Silicon Macs build arm64 natively):

```sh
docker build --platform linux/arm64 -f packaging/docker/Dockerfile.build -t afprust-build .
docker run --rm --platform linux/arm64 -v "$PWD":/src afprust-build cargo deb
scp target/debian/afprust_*_arm64.deb pi@raspberrypi.local:
ssh pi@raspberrypi.local sudo apt install ./afprust_*_arm64.deb
```

The package installs:

| Path | Purpose |
| --- | --- |
| `/usr/sbin/afprustd` | the server |
| `/etc/afprust/afp.conf` | configuration (netatalk format) |
| `/etc/afprust/extmap.conf` | extension → type/creator map |
| `/etc/pam.d/afprust` | PAM service (`common-auth`, `common-account`) |
| `/etc/default/afprustd` | extra command line options |
| `afprustd.service` | systemd unit (enabled and started) |

```sh
sudo afprustd -t                 # check the configuration
sudo systemctl reload afprustd   # apply changes (SIGHUP)
journalctl -u afprustd -f        # logs
```

### Using an existing netatalk configuration

Set `AFPRUSTD_OPTS="-F /etc/netatalk/afp.conf"` in `/etc/default/afprustd`,
or `-F /etc/netatalk/afpd.conf` for netatalk 2. Stop netatalk first; both
servers want port 548. `afprustd -t` lists the options it ignores.

## Connecting from Mac OS 9

1. Open the **Chooser** and select **AppleShare**.
2. Click **Server IP Address…** and enter the Pi's IP address or host name.
   With `appletalk = yes` the server is listed directly; just double-click it.
3. Log in with a Linux user name and password. Your home directory appears as
   *"<user>'s home"*, alongside any configured volumes.

From the Network Browser you can also open `afp://<address>/`.

The default configuration offers only DHCAST128. For Mac OS 8.x or
Mac OS 9.0–9.0.3, which lack it, add `uams_clrtxt.so` to `uam list`, and be
aware that those passwords cross the network in the clear.

### AppleTalk (Chooser browsing)

```ini
[Global]
appletalk = yes
ddp interface = eth0     ; default: the first wired Ethernet interface
```

The kernel module `appletalk` is loaded automatically when the server opens
its first AppleTalk socket (check with `lsmod | grep appletalk`). The server
assumes a network without an AppleTalk router (the usual home setup): the
Pi takes a node address in the startup range and appears as
`<server name>:AFPServer@*`. AFP itself always runs over TCP/IP; Macs
without TCP/IP configured cannot connect.

## Configuration

See **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** for every option,
recipes (sharing a folder, group shares, guest access, AppleTalk), metadata
storage, file names, migrating from netatalk, and troubleshooting.

A minimal volume:

```ini
[OS 9]
path = /srv/os9
valid users = @macusers
```

## Security

Netatalk's history of pre-authentication memory-safety bugs (for example
CVE-2018-1160 in DSI session setup, and the 2022–2024 AppleDouble and UAM
parsing CVEs) is what this design addresses:

- **Memory safety.** All protocol parsing is safe Rust with bounds-checked
  readers. A malformed packet produces an AFP error, never an out-of-bounds
  access. `unsafe` is limited to syscall wrappers.
- **Small pre-auth surface.** Before login a session accepts only DSI
  framing, FPGetSrvrInfo, FPLogin and FPLoginCont. Frames are limited to
  4 KiB, reads have deadlines, and login must finish within 60 s.
- **Process separation.** Each client gets its own process. After
  authentication it calls `setgroups`/`setgid`/`setuid` to the user (or the
  guest account), verifies that root cannot be regained, and becomes
  non-dumpable. All file access then happens with the user's own
  permissions. Root logins are refused.
- **Kernel-enforced confinement.** Every file system operation resolves
  paths with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` relative to the
  volume root and acts through directory descriptors (`*at` syscalls). A
  client cannot leave its volume, not even when a local user swaps a
  directory for a symlink in the middle of a request (the race behind
  Samba's CVE-2017-2619). Client names are validated: no `.`, `..`, `/` or
  NUL, and no metadata names (`._*`, `.AppleDouble`, …). Symlinks are
  hidden unless `follow symlinks = yes`, and even then must stay inside
  the volume. Devices, FIFOs and sockets are never exposed.
- **Brute-force and DoS limits.** 2 s delay after a failed login,
  disconnect after 3 failures, a 15-minute block for an address after 10
  failures, a global and a per-address connection limit, a bounded ID cache,
  and capped reply sizes. Passwords are scrubbed from memory after use and
  never logged; client-supplied strings are sanitized before logging.
- **systemd sandbox.** The unit has a minimal capability bounding set,
  `NoNewPrivileges`, `ProtectSystem=full`, a syscall filter, restricted
  address families, `MemoryDenyWriteExecute`, and more. The AppleTalk helper
  drops to `nobody` after binding its sockets.

Limits of the protocol itself, which no AFP 2.x server can fix:

- DHCAST128 uses a 128-bit Diffie-Hellman group and CAST-128, which a
  determined attacker who records the login can break. Cleartext login is
  cleartext. File data is never encrypted. **Use afprustd on a trusted LAN
  only; do not expose port 548 to the internet.**
- Volume passwords are 8-byte plaintext secrets, as in AppleShare.

## Not implemented

- AFP 3.x (Mac OS X clients). Use netatalk for those.
- AFP over ASP/AppleTalk sessions (very old Macs without Open Transport
  TCP/IP). AppleTalk is used for discovery only.
- Randnum UAMs, password changes over AFP, FPCatSearch (Sherlock falls back
  to browsing), persistent file IDs (`FPCreateID`/`FPResolveID`; aliases
  fall back to paths). Directory IDs are inode numbers, so they stay stable
  across sessions.
- Spotlight, Time Machine, ACLs, extended attributes for clients.

## Development

```sh
cargo test                       # unit tests
scripts/integration-test.sh      # unit + end-to-end tests in a Debian
                                 # bookworm arm64 container (needs Docker)
cargo run --example smoke -- 548 <user> <password>   # smoke test a server
```

The end-to-end test starts a real server as root, logs in through PAM with
DHCAST128, cleartext and guest, and exercises volumes, forks, metadata,
renames, copies, exchange, the desktop database, share modes and byte-range
locks across two sessions, the `.AppleDouble` backend, path-traversal and
symlink-escape attempts, oversized pre-auth frames, and checks that sessions
run as the user.

Source layout:

| Path | Contents |
| --- | --- |
| `src/master.rs` | listener, limits, fork per connection, reload |
| `src/dsi.rs` | DSI framing |
| `src/afp/` | AFP session, login, command handlers, parameter packing, server info |
| `src/auth/` | UAMs (DHCAST128, cleartext, guest) and PAM |
| `src/vfs/` | volume model, ID map, confined file system access, AppleDouble formats, forks and locks, desktop database |
| `src/config/` | afp.conf and netatalk 2 parsers, extension map |
| `src/atalk.rs` | AppleTalk NBP/ASP-GetStatus responder |
| `packaging/` | systemd unit, default configuration, PAM, man page, Dockerfiles |

## License

MIT, see [LICENSE](LICENSE). afprust is an independent implementation; it
contains no netatalk code (netatalk was used as a protocol reference only).
