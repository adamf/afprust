# Configuring afprustd

afprustd reads a netatalk-style `afp.conf`. Edit `/etc/afprust/afp.conf`,
check it, and apply it without dropping connected Macs:

```sh
sudo afprustd -t                 # parse, print a summary, list ignored options
sudo systemctl reload afprustd   # new sessions use the new configuration
```

Changes to `afp listen`/`afp port` need `sudo systemctl restart afprustd`.

- [Where the configuration comes from](#where-the-configuration-comes-from)
- [File format](#file-format)
- [Recipes](#recipes)
- [Global options](#global-options)
- [Volume options](#volume-options)
- [Home directories](#home-directories)
- [Variables](#variables)
- [Users, permissions and guests](#users-permissions-and-guests)
- [Authentication methods](#authentication-methods)
- [Network: addresses, interfaces and AppleTalk](#network-addresses-interfaces-and-appletalk)
- [Mac metadata storage](#mac-metadata-storage)
- [File names](#file-names)
- [Extension mapping](#extension-mapping)
- [Using netatalk configurations](#using-netatalk-configurations)
- [Logging](#logging)
- [Troubleshooting](#troubleshooting)

## Where the configuration comes from

Without `-F`, afprustd uses the first of these that exists:

1. `/etc/afprust/afp.conf`
2. `/etc/netatalk/afp.conf` (netatalk 3/4)
3. `/etc/netatalk/afpd.conf` + `/etc/netatalk/AppleVolumes.default` (netatalk 2)

`-F <file>` selects a file explicitly. A file named `afpd.conf` is read as
netatalk 2 format, with `AppleVolumes.default` and `AppleVolumes.system` from
the same directory. For the systemd service, put the option in
`/etc/default/afprustd`:

```sh
AFPRUSTD_OPTS="-F /etc/netatalk/afp.conf"
```

## File format

```ini
; comment
# also a comment
[Global]
server name = Raspberry Pi

[Section Name]          ; any section with "path" is a volume
path = /srv/mac
valid users = alice @staff
```

- Option names are case-insensitive, and repeated spaces inside them don't
  matter (`Valid  Users` = `valid users`).
- Section names keep their case and become volume names. Lookups ignore case.
- A value may be wrapped in double quotes. Outside quotes, ` ;` or ` #` starts
  a trailing comment.
- A trailing `\` continues the line.
- Booleans: `yes`/`no`, `true`/`false`, `on`/`off`, `1`/`0`.
- Lists (users, hosts, UAMs) are separated by spaces and/or commas.
- `[Global]` holds server options and, optionally, defaults for every
  volume.
- `[Homes]` defines the per-user home volume.
- A section **without** `path` is a template. Volumes inherit its options
  with `vol preset = <section>`.

For each volume option the order is: the volume's section, then its
`vol preset` (or the preset named in `[Global]`), then `[Global]`, then the
built-in default.

## Recipes

### Share one folder, for one user

Share `/home/dorothy/os9` with Dorothy:

```ini
[Global]
uam list = uams_dhx.so

[OS 9]
path = /home/dorothy/os9
valid users = dorothy
```

- The server listens on every IPv4 interface by default (Ethernet, Wi-Fi,
  …), so no network option is needed. Mac OS 9 only speaks IPv4.
- If the Mac runs Mac OS 8.x or 9.0–9.0.3, use
  `uam list = uams_dhx.so uams_clrtxt.so`. See
  [Authentication methods](#authentication-methods).
- The default configuration also has a `[Homes]` section, which gives
  Dorothy a second volume, "dorothy's home", with her whole home directory.
  Delete or comment out `[Homes]` if `OS 9` should be the only volume.

In the Chooser, Dorothy picks **AppleShare → Server IP Address…**, enters
the Pi's address, logs in as `dorothy` with her Linux password, and selects
**OS 9**.

### A folder several people share

```sh
sudo groupadd macusers
sudo usermod -aG macusers dorothy
sudo usermod -aG macusers toto
sudo mkdir -p /srv/os9
sudo chgrp macusers /srv/os9
sudo chmod 2775 /srv/os9      # setgid: new files belong to the group
```

```ini
[OS 9 Shared]
path = /srv/os9
valid users = @macusers
file perm = 0660
directory perm = 0770
```

Keep shared folders out of home directories. On Raspberry Pi OS, `adduser`
creates homes with mode 0700, so other users cannot even enter them.

### Read-only software library, open to guests

```ini
[Global]
uam list = uams_dhx.so uams_guest.so
guest account = nobody

[Software]
path = /srv/os9-software
read only = yes
```

The files must be readable by the guest account:
`sudo chmod -R a+rX /srv/os9-software`.

### Different access per person

```ini
[Projects]
path = /srv/projects
valid users = @staff
rolist = intern            ; read-only for these
rwlist = @staff            ; when set, everyone not listed is read-only
invalid users = mallory    ; never allowed, even if in valid users
hosts allow = 192.168.1.0/24
```

### Show up in the Chooser automatically

```ini
[Global]
appletalk = yes
ddp interface = eth0
```

See [AppleTalk](#appletalk).

## Global options

| Option | Default | Meaning |
| --- | --- | --- |
| `server name` | host name | Name shown in the Chooser (up to 31 MacRoman characters). |
| `hostname` | system host name | Used for `$h`, and as the server name if `server name` is unset. |
| `afp listen` | `0.0.0.0` | Space-separated addresses to listen on, optionally with `:port` (`192.168.1.10`, `[::1]:5480`). See [Network](#network-addresses-interfaces-and-appletalk). |
| `afp port` | `548` | Port for `afp listen` entries without a port. |
| `uam list` | `uams_dhx.so` | Authentication methods: `uams_dhx.so`, `uams_clrtxt.so`, `uams_guest.so`. netatalk aliases (`uams_dhx_pam.so`, `uams_pam.so`, …) are accepted; Mac OS X-only UAMs (`uams_dhx2.so`, …) are skipped with a warning. |
| `guest account` | `nobody` | Account used for guest logins. Must not be root. |
| `login message` | none | Message the Mac shows after login (up to 199 characters). |
| `save password` | `yes` | Whether the Mac may offer to save the password in the keychain. |
| `max connections` | `200` | Total simultaneous sessions. |
| `max connections per ip` | `16` | Sessions per client address. *(afprust)* |
| `login timeout` | `60` | Seconds a client has to finish logging in. *(afprust)* |
| `tickleval` | `30` | Seconds between keep-alive tickles. |
| `timeout` | `4` | A client is dropped after this many missed tickle intervals. |
| `server quantum` | `1048576` | Largest read/write per request, in bytes (32000–8388608). |
| `log level` | `default:info` | `error`, `warn`, `note`, `info`, `debug`, `maxdebug`; netatalk's `type:level` syntax is accepted. |
| `log file` | none | Log to this file instead of the systemd journal. |
| `signature` | generated | Up to 16 characters identifying the server to clients. By default a random signature is generated once and kept in the state directory. |
| `state directory` | `/var/lib/afprust` | Where the server signature is stored. *(afprust)* |
| `pam service` | `afprust` | PAM service name (`/etc/pam.d/<name>`). *(afprust)* |
| `extmap file` | `/etc/afprust/extmap.conf` | Extension → type/creator map. |
| `mac charset` | `MAC_ROMAN` | Only MacRoman is supported. |
| `appletalk` | `no` | Announce the server over AppleTalk. |
| `ddp interface` | first wired Ethernet | Interface for AppleTalk. *(afprust)* |
| `ddp address` | random | AppleTalk address as `net.node`, e.g. `65280.42`. |
| `ddp zone` | none | AppleTalk zone to answer for. |
| `vol preset` | none | Template section applied to every volume. |

Every [volume option](#volume-options) may also appear in `[Global]` as a
default for all volumes.

*(afprust)* marks options netatalk does not have.

## Volume options

| Option | Default | Meaning |
| --- | --- | --- |
| `path` | *(required)* | Directory to share. Variables are expanded. |
| `volume name` | section name | Name in the Chooser (up to 27 MacRoman characters). |
| `valid users` | everyone | Users (`alice`) and groups (`@staff`) allowed to see the volume. |
| `invalid users` | nobody | Users and groups never allowed; overrides `valid users`. |
| `rolist` | none | Users and groups with read-only access. |
| `rwlist` | none | If set, users and groups **not** listed get read-only access. |
| `read only` | `no` | Read-only for everyone. |
| `password` | none | AFP volume password (at most 8 characters, sent in the clear). |
| `hosts allow` | all | Client addresses/networks allowed (`192.168.1.0/24 10.0.0.5`). |
| `hosts deny` | none | Client addresses/networks refused. |
| `appledouble` | `ea` | Metadata format: `ea` or `v2`. See [Mac metadata storage](#mac-metadata-storage). |
| `ea` | `auto` | `auto`, `sys`, `ad` or `none`. See [Mac metadata storage](#mac-metadata-storage). |
| `file perm` | none | Permission bits OR-ed into new files (`0660`). |
| `directory perm` | none | Permission bits OR-ed into new folders (`0770`). |
| `umask` | `022` | umask for new files and folders. |
| `invisible dots` | `no` | Show Unix dot files as invisible to the Mac. |
| `veto files` | none | `/`-separated name patterns (`*`, `?`) hidden from the Mac: `/.DS_Store/*.tmp/`. |
| `delete veto files` | `no` | Delete vetoed files when the Mac deletes the folder containing them. |
| `follow symlinks` | `no` | Follow symbolic links that stay inside the volume. Links leading out are always ignored. |
| `vol size limit` | none | Report at most this many MiB as the volume size. |
| `legacy volume size` | `no` | Cap reported sizes at 2 GB for software that misreads larger volumes. |
| `vol preset` | none | Template section to inherit options from. |

These netatalk options are accepted but have no effect, because AFP 2.x
clients do not use them: `cnid scheme`, `vol dbpath`, `time machine`,
`convert appledouble`, `vol charset`, `casefold`, `prodos`, `unix priv`,
`acls`, `spotlight`, `case sensitive`, `volume uuid`, `preexec`/`postexec`
and similar. `afprustd -t` lists every ignored option.

## Home directories

```ini
[Homes]
basedir regex = /home
;home name = $u's home      ; default
;path = Macintosh            ; share ~/Macintosh instead of the whole home
```

A user gets a home volume when their home directory (from `/etc/passwd`)
starts with a match of `basedir regex`. Guests never get one. `home name`
and `path` may use [variables](#variables). The other volume options apply
as well.

## Variables

Used in `path`, `volume name` and `home name`, as in netatalk:

| Variable | Value |
| --- | --- |
| `$u` | user name |
| `$g` | user's primary group |
| `$f` | user's full name (from GECOS) |
| `$h` | host name |
| `$s` | server name |
| `$i` | client IP address |
| `$c` | client IP address and port |
| `$v` | volume (section) name |
| `$d` | volume path |
| `$b` | last component of the volume path |
| `$$` | a literal `$` |

Example: `path = /srv/mac/$u` gives every user their own folder. Paths that
come out containing `..` are refused.

## Users, permissions and guests

- People log in with their **Linux** user name and password, checked through
  PAM (`/etc/pam.d/afprust`). Create accounts with `sudo adduser <name>`.
  User names are case-insensitive at login: `Dorothy` works for `dorothy`.
- **root cannot log in**, nor can any account with uid 0.
- After login, the session runs as that user, so ordinary Unix permissions
  decide what the user may read and change. Volume options can only
  restrict further. A user who cannot write to a folder over SSH cannot
  write to it from the Mac either.
- The Mac's Get Info "Sharing" window shows the owner and group, and lets
  the owner change permissions of folders they own.
- Guests (`uams_guest.so`) run as `guest account` (default `nobody`) and see
  only what that account may access.

## Authentication methods

| `uam list` entry | Mac shows | Clients | On the wire |
| --- | --- | --- | --- |
| `uams_dhx.so` | Encrypted password | Mac OS 9.0.4+ (AppleShare Client 3.8.4+; plug-in for 3.8.3) | Password encrypted with DHCAST128. Weak by today's standards, but never in the clear. |
| `uams_clrtxt.so` | Clear text password | Mac OS 8.1–9.x | **Password readable by anyone on the network.** |
| `uams_guest.so` | Guest | all | No password. |

The Mac picks the strongest method both sides support. Enable only what your
Macs need. afprustd logs a warning at start-up when cleartext is enabled.

Failed logins are slowed down (2 s each). After 3 failures the connection is
closed, and after 10 failures within 10 minutes the client address is
blocked for 15 minutes.

## Network: addresses, interfaces and AppleTalk

### Listening addresses

By default afprustd listens on **port 548 of every IPv4 address**, which
covers every interface, wired and wireless, including ones that come up
later. Mac OS 8/9 only speak IPv4.

```ini
afp listen = 192.168.1.10        ; only this address
afp listen = ::                  ; all IPv4 and all IPv6 addresses (one dual-stack socket)
afp listen = 0.0.0.0 ::          ; same, as two sockets (afprust 0.1.1 and later)
afp listen = 127.0.0.1:5480      ; another port (Macs then need "address:port")
```

Restart the service after changing `afp listen` or `afp port`.

If a firewall is active (`ufw` is not installed by default on Raspberry
Pi OS), allow TCP port 548: `sudo ufw allow 548/tcp`.

Do not forward port 548 from the internet. AFP 2.x is a LAN protocol.

### AppleTalk

With `appletalk = yes`, afprustd gives one Ethernet interface an AppleTalk
address and answers the Chooser, which then lists the server under
AppleShare without anyone typing an address. The connection itself still
uses TCP/IP, so the Mac needs TCP/IP configured as well. (AppleShare Client
3.7.4+ does this automatically.)

- The kernel module `appletalk` is loaded automatically. If start-up logs
  "kernel has no AppleTalk support", run `sudo modprobe appletalk` and check
  `lsmod | grep appletalk`.
- `ddp interface` picks the interface. The default is the first wired
  Ethernet interface (`eth0` on a Pi). Wi-Fi is skipped by default because
  AppleTalk over Wi-Fi is unreliable. Set `ddp interface = wlan0` to try it.
- Designed for networks without an AppleTalk router (the usual home setup).
  If the interface already has an AppleTalk address, afprustd uses it, but
  netatalk's `atalkd` must not be running: it holds the name lookup (NBP)
  socket that afprustd needs.
- Mac side: in the **AppleTalk** control panel, select Ethernet and make
  sure AppleTalk is active in the Chooser.

## Mac metadata storage

Mac files carry Finder info (type, creator, icon position, flags), comments
and resource forks that Linux file systems don't have. afprustd stores them
where netatalk does, so a volume can switch between the two servers, or be
shared with netatalk serving Mac OS X at the same time.

| Setting | Finder info, comments, dates | Resource fork | Compatible with |
| --- | --- | --- | --- |
| `appledouble = ea` (default) | xattr `user.org.netatalk.Metadata` on the file | `._name` next to the file | netatalk 3/4, Samba vfs_fruit, Mac OS X `._` files |
| `appledouble = v2` | `.AppleDouble/name` | same file | netatalk 2 |
| `ea = none` | not stored (type/creator from the extension map) | not stored, writes fail | — |

With the default `ea = auto`, afprustd uses extended attributes when the
volume's file system supports them (ext4, btrfs, XFS) and falls back to
`.AppleDouble` folders where it doesn't (FAT, exFAT, some network mounts).
The choice is made per volume when it is opened.

`._*` files, `.AppleDouble`, `.AppleDB` and `.AppleDesktop` are hidden from
the Mac, and clients cannot create names like them. When the Mac deletes a
folder, metadata leftovers inside it are removed too.

Copy files on the Linux side with tools that keep extended attributes
(`cp -a`, `rsync -aX`), and move the `._` files along with them.

The desktop database (application icons and "open with" mappings) lives in
`.AppleDesktop` at the volume root.

## File names

- Mac names are MacRoman, at most 31 characters. On disk they are stored as
  UTF-8 (`Café` stays `Café`).
- `/` is legal in Mac names and is stored as `:` on disk (as Mac OS X does).
- Lookups are case-insensitive like HFS: `ReadMe` finds `readme`, and
  creating `readme` next to an existing `ReadMe` fails.
- Unix names the Mac cannot represent (more than 31 characters, characters
  outside MacRoman) are shown mangled, as `First part#1A2B.ext`, and still
  work for opening, renaming and deleting.
- The Mac never sees symbolic links (unless `follow symlinks = yes`),
  devices, sockets or FIFOs.

## Extension mapping

Files without stored Finder info get a type and creator from their extension,
so a `.jpg` copied onto the volume from Linux opens in the right
application. The map is `/etc/afprust/extmap.conf`, in netatalk's
`extmap.conf` / `AppleVolumes.system` format:

```
.txt   "TEXT"  "ttxt"   ASCII Text   SimpleText
.jpg   "JPEG"  "ogle"
.      "????"  "????"                ; default for unknown extensions
```

Only the first three fields matter. Once a Mac sets a file's type and
creator, the stored values win.

## Using netatalk configurations

### netatalk 3/4 (`afp.conf`)

Supported as is. Everything in the tables above works with the same names
and meanings. Options specific to Mac OS X / AFP 3 (Time Machine, Spotlight,
ACLs, CNID databases, Zeroconf, Kerberos) are ignored.

To migrate:

```sh
sudo systemctl disable --now netatalk
echo 'AFPRUSTD_OPTS="-F /etc/netatalk/afp.conf"' | sudo tee /etc/default/afprustd
sudo afprustd -t -F /etc/netatalk/afp.conf
sudo systemctl restart afprustd
```

netatalk's PAM service is called `netatalk`. Either keep using it
(`pam service = netatalk` in `[Global]`) or rely on `/etc/pam.d/afprust`.

### netatalk 2 (`afpd.conf` + `AppleVolumes.default`)

`afpd.conf`: the first server line is used. Recognized options:
`-uamlist`, `-port`, `-ipaddr`, `-loginmesg`, `-guestname`,
`-nosavepassword`/`-savepassword`, `-tickleval`, `-timeout`,
`-server_quantum`, `-signature user:<sig>`, `-setuplog`, `-hostname`,
`-ddp`/`-noddp`, `-ddpaddr`, `-defaultvol`, `-systemvol`. The default UAMs
for netatalk 2 configurations are DHCAST128 and cleartext.

`AppleVolumes.default`: `path [name] [option:value ...]`, with `~` for home
directories and `:DEFAULT:` for defaults. Recognized options: `allow:`,
`deny:`, `rwlist:`, `rolist:`, `password:`, `options:` (`ro`,
`invisibledots`, `followsymlinks`), `perm:`, `fperm:`, `dperm:`, `umask:`,
`veto:`, `allowed_hosts:`, `denied_hosts:`, `volsizelimit:`, `adouble:`.
Volumes use `.AppleDouble` metadata, as netatalk 2 did.
`AppleVolumes.system` is used as the extension map.

## Logging

Logs go to the systemd journal:

```sh
journalctl -u afprustd -f
```

Logins, logouts, failed logins (with the user name and client address,
never the password), blocked addresses and configuration warnings are
logged at `info`/`warn`. Use `log level = debug` (or `afprustd -v`) to see
every failing AFP command.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| The Mac says the server is not available | Is the service running (`systemctl status afprustd`)? Does `nc -vz <pi> 548` connect from another machine? Is a firewall in the way? Is netatalk still running on port 548? |
| Login fails for everyone | `journalctl -u afprustd`. Does `/etc/pam.d/afprust` exist? Does the password work for `su - <user>`? |
| The Mac cannot log in at all (no password prompt, or an error about the authentication method) | The Mac supports none of the enabled UAMs. Add `uams_clrtxt.so` for Mac OS 8.x/9.0–9.0.3. |
| A volume is missing from the list | `valid users`, `invalid users`, `hosts allow`/`deny`. Is the path absolute and free of `..` after variable expansion? `afprustd -t` shows the parsed volumes. |
| "You do not have enough access privileges" | Unix permissions of the folder for that user (`sudo -u <user> ls <path>`). Home directories are often 0700. |
| Files show generic icons / open in the wrong app | Finder info is missing: add the extension to `extmap.conf`, or set type/creator from the Mac. |
| The server is not in the Chooser | `appletalk = yes`? Check `journalctl` for AppleTalk errors and `lsmod \| grep appletalk`. Is AppleTalk on Ethernet active on the Mac? Without AppleTalk, use **Server IP Address…**. |
| Changes are not picked up | `sudo systemctl reload afprustd` (address changes need `restart`). Connected Macs keep their session's view until they reconnect. |
