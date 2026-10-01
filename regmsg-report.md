# regmsg binaries — reverse-engineering report

2026-10-16

## Summary

REG-Linux describes itself as "Fully open source" with a "transparent build system and clean codebase" ([GitHub README](https://github.com/reg-linux)), and states its components are "released under open-source licenses (GPL-2.0, MIT, or similar)." The four ELF binaries in this archive are shipped without source code. The daemon's anti-tamper system is designed to resist the inspection and modification that open-source licensing exists to enable.

The four blobs make up REG Linux's system-management service. Three are routine. The root daemon, `regmsgd`, also hides an anti-tamper system that **silently breaks game launching** when the binary is modified, a debugger is attached, or certain boot-splash files differ from REG Linux's originals. I proved this experimentally and reproduced the mechanism byte for byte.

The archive (`reglinux-msg`, commit `da5cd551`, x86_64, built 2026-10-13) holds 4 ELF binaries, 100 Lua launch generators, 79 JSON key maps and one init script. Only the ELF files lack source:

| Blob | What it is | Size | Language | Symbols |
|------|-----------|------|----------|---------|
| `/usr/lib/libdrmhook.so` | `LD_PRELOAD` shim that forces the display mode the compositor picks | 16 KB | C | Yes |
| `/usr/bin/regmsg` | Command-line client for the daemon (v0.2.0) | 4.5 MB | Rust 1.98.1 | Yes, with debug info |
| `/usr/bin/regmsg_shell` | Interactive shell client for the daemon | 3.1 MB | Rust 1.98.1 | Yes, with debug info |
| `/usr/bin/regmsgd` | Root daemon: display, audio, Wi‑Fi, Bluetooth, emulator launcher, game library, metadata scraper, BIOS check, passwords | 12.3 MB | Rust 1.98.1 + bundled C (Lua 5.4) | Stripped |

Headline findings:

- **Launch kill switch (regmsgd).** Before spawning an emulator, the daemon XORs the program path with a 32‑byte value derived from: a secret split across the binary, a BLAKE3 hash of its own executable, a hash of five hidden-path files (its init script and the REG Linux plymouth splash), and the current `TracerPid`. Only on an untouched, untraced REG Linux system does the value come out as zero. Anywhere else the path is scrambled and every launch fails with a misleading "No such file or directory".
- **Sealed ScreenScraper developer credentials.** The same key material decrypts an embedded 128‑byte blob holding the ScreenScraper developer ID and password. Under the same conditions they don't unseal.
- **Anti-analysis.** The daemon exits silently (status 1) if `LD_PRELOAD` or `LD_AUDIT` is set, marks itself non-dumpable, hides the five file paths with XOR `0xA6`, builds sensitive names as stack strings, and wipes key material after use.
- **Weak root-password storage.** The root password is saved in `/boot/system-boot.conf` as AES‑128‑CBC with a key derived only from a hardware serial. On machines with no recognised serial the passphrase is empty, so anyone with the boot partition can decrypt it. I verified this offline.

## Method and evidence

Every behavioural claim below was confirmed by running the binary, not just read off the disassembly. Statements marked *inferred* rest on code reading alone.

- **Static:** symbols and DWARF info for the three binaries that have them; `.eh_frame` function boundaries plus `objdump` disassembly for the stripped daemon; string and XOR scans of every data section. Ghidra was started but not needed in the end.
- **Dynamic:** each binary ran in a throwaway sandbox with no network, private mounts and tmpfs over `/boot`, `/userdata`, `/run` and `/var`. A fake daemon socket captured client traffic. Stub `openssl`/`ksmbd.adduser` scripts logged what the daemon executes. `strace` and gdb were used where tracing doesn't alter the result.
- **Controls:** the launch kill switch was checked with an A/B test against a copy differing in only 32 bytes, then predicted offline from first principles and matched against the bytes gdb captured.
- **Not done:** I did not try to unseal the ScreenScraper developer credentials. That would need REG Linux's genuine splash files, and they are the project's third-party API secret.

## regmsgd (daemon): what it does

`regmsgd` is REG Linux's central root service. Without it there is no volume control, no game launcher and no frontend backend. The init script `S06regmsgd` starts it at boot under a shell supervisor that restarts it with exponential back-off (1 s, doubling, capped at 60 s). It is a tokio async Rust program serving 95 commands on `/var/run/regmsgd.sock` (mode `0600`, root only; I confirmed an unprivileged user gets "permission denied"). It logs to `/var/log/regmsgd.log` and records each caller's pid/uid.

**Startup, in order (observed with strace):**

1. Anti-instrumentation check: exits with status 1 if `LD_PRELOAD` or `LD_AUDIT` is non-empty; otherwise `prctl(PR_SET_DUMPABLE, 0)`.
2. Scans `/usr/bin` for emulator binaries and libretro cores, then loads every Lua generator into an embedded Lua 5.4 engine (82 loaded from this archive).
3. Security: applies boot credentials. With security off it runs `ksmbd.adduser -C /etc/ksmbd/ksmbd.conf -P /etc/ksmbd/ksmbdpwd.db -p linux root`.
4. Registers the commands, binds the socket via a staging path plus `chmod 0600` plus `rename`.
5. Computes the hidden-file integrity fingerprint (next section).

**Modules** (names from embedded source paths `src/bin/daemon/…`):

| Module | What it does | How |
|--------|-------------|-----|
| `screen` | Lists and sets outputs, modes, rotation, refresh; screenshots; touchscreen mapping; brightness | Wayland via `swaymsg`/`/var/run/sway-ipc.0.sock`, or direct KMS/DRM; `grim` for screenshots; `/sys/class/backlight` |
| `audio` | Volume (with optional boost), mute, output device, card profile | libpulse (PulseAudio/PipeWire-pulse) |
| `network/wifi` | Scan, connect, saved networks, forget | iwd over D-Bus (`net.connman.iwd`), with its own pairing agent |
| `bluetooth` | Bring-up (storage, adapter address via kernel MGMT socket, `bluetoothd`), scan, pair, trust, auto-pair controllers, forget | BlueZ D-Bus (`org.bluez`) + MGMT socket + `rfkill` |
| `systemconf` | Key/value config, in memory and on disk | `/boot/system-boot.conf`, `/userdata/system/system.conf`, defaults in `/usr/share/reglinux/sysconfigs/` |
| `launcher` | Picks emulator+core per system/ROM, runs the Lua generator, prepares devices, starts sway if needed, spawns and supervises the emulator | Lua 5.4 (mlua) with full `io`/`os` plus a `regmsg.*` API; `launcher-defaults.yml`; evmapy pad-to-key mapping; wheel calibration; mounts squashfs/zip archives with writable overlays; `mangohud`; power modes; game-start/stop hook scripts from `/usr/share/reglinux/scripts` and `/userdata/system/scripts` |
| `library` | Scans ROM folders and gamelists, publishes them as FlatBuffers blobs in `/dev/shm`, applies metadata edits | Arcade databases cached in `/userdata/system/.cache/regmsgd/` |
| `scraper` | Manual search and batch scraping of metadata and media | ScreenScraper, TheGamesDB, IGDB (Twitch OAuth), HFSDB, ArcadeDB; rate-limited; cache in `/var/cache/regmsg/scraper` |
| `bios` | Checks BIOS files against a shipped MD5 manifest | Local only |
| `security` | Root password, Samba (ksmbd) credentials, shadow file | See *Credentials and root password* |
| `integrity` | Hidden-file fingerprint feeding the anti-tamper keys | See next section |

**Daemon-only commands** (not exposed by `regmsg`): `listCommands`; `launcher.capabilities`; `library.collection`, `.flush`, `.load`, `.read`, `.scan`, `.schema`, `.systems`, `.write`, `.writeBatch`; `scraper.batch.start/status/pause/resume/cancel`; `scraper.search.start/poll/describe/apply/applyStatus/cancel`. The frontend presumably uses these.

The Lua generators run as root with `os.execute` and `io.popen` available, which is the intended design. The generator directory can be overridden only through the `REGMSG_LUA_DIR` environment variable, which only root sets.

## regmsgd: the hidden anti-tamper system

`regmsgd` ties two things to an unmodified, untraced, genuine REG Linux install: the ability to launch games, and access to the embedded ScreenScraper developer credentials. Neither the CLI help, the command list nor the logs mention this, and failures surface as ordinary-looking errors.

Change any one input and both outputs change: the emulator path is scrambled and the credentials decrypt to garbage.

### Input 1: hidden-file fingerprint (`integrity/gate.rs`, code at 0x614ee0)

Five paths are stored XOR‑`0xA6` and decoded at runtime. They are the only obfuscated strings in the binary; a scan of all 255 single-byte keys found no others.

1. `/etc/init.d/S06regmsgd` (the init script shipped in this very archive)
2. `/etc/init.d/S002plymouth`
3. `/etc/plymouth/plymouthd.conf`
4. `/usr/share/plymouth/themes/reglinux-arcade/reglinux-arcade.plymouth`
5. `/usr/share/plymouth/themes/reglinux-arcade/logo_frame_9.png`

Each file is BLAKE3-hashed (a missing file counts as 32 zero bytes). Then *fingerprint* = BLAKE3(h1 ‖ … ‖ h5). It's computed once when the daemon starts and cached, so later edits take effect at the next restart.

### Input 2: self-hash of the executable (code at 0x514270)

The build pipeline patches three slots into the finished binary: a 32-byte marker at 0xa370e0, a 128-byte sealed blob at 0xa37060, and a 32-byte launch seal at 0xa37100. At runtime the daemon reads `/proc/self/exe`, uses `dl_iterate_phdr` to find the slots' file offsets, saves the blob and seal, zeroes all three slots, and BLAKE3-hashes the whole file. If the marker is still the unpatched placeholder (32 × `0xA5`) or the exe can't be read, the feature switches itself off (fails open).

### Input 3: embedded secret and debugger state (code at 0x546710)

A 32-byte secret is stored as two XOR shares (at 0x9a4560 and 0x9a4580) so it never appears whole in the file. On every use the daemon recombines it, wipes the shares' copies, and reads `TracerPid` from `/proc/self/status`. That value is non-zero whenever strace, gdb or any ptrace tool is attached.

Key material (104 bytes) = secret ‖ self-hash ‖ fingerprint ‖ TracerPid (u64, little-endian).

### Use 1: launch kill switch (inside the launcher, ~0x347c65)

- mask = BLAKE3 `derive_key`(context `"regmsg-launch-v1"`, key material)[0..32] ⊕ launch seal
- Just before `Command::new`, the first up to 32 bytes of the emulator path (`cmd[0]`) are XORed with the mask.
- For launches to work, the mask must be all zeros. That only happens when every input matches what the build pipeline sealed, i.e. an unmodified binary, the genuine REG Linux splash files and init script, and no tracer. *Inferred:* the seal was produced from those genuine values, since otherwise no installation could launch games.
- Otherwise `/bin/bash` (for example) reaches the kernel as `d9 1d 74 42 7f 01 2a 0c 02`, and the launch fails with `{"code":"spawn_failed","message":"spawn failed: No such file or directory (os error 2)"}`.

**Proof.** In the sandbox, `launcher.generate sh test.sh` returned `cmd = ["/bin/bash", …]`, yet `launcher.launch` failed as above. A copy of the daemon with only the 32 marker bytes reset to `0xA5`, which switches the check off, launched the same ROM successfully and the ROM's script ran. I then recomputed the mask offline from the four inputs and it predicted the exact 9 scrambled bytes gdb captured, a byte-for-byte match.

### Use 2: sealed ScreenScraper developer credentials (code at 0x547a60)

keystream = BLAKE3 `derive_key`(`"regmsg-cred-v1"`, key material), 128 bytes. XORing it with the sealed blob yields `[len1][len2][devid][devpassword]`. Both strings are validated as UTF‑8, the buffers wiped, and the pair passed to the ScreenScraper requests next to the user's `scraper.screenscraper.user/pass`. Under the same conditions that break launching, this decrypts to garbage and ScreenScraper scraping loses its developer credentials.

### Anti-analysis measures

| Measure | Where | Effect |
|---------|-------|--------|
| `LD_PRELOAD` / `LD_AUDIT` check | 0x402370 | Silent `exit(1)` if either is set, even to an empty library. Names are built as 8-byte stack immediates, so `strings` won't find them |
| `prctl(PR_SET_DUMPABLE, 0)` | 0x4024d8 | No core dumps; blocks same-user ptrace and `/proc/<pid>/mem` |
| `TracerPid` in the key | 0x546710 | Any attached debugger or strace silently breaks launches and credential unsealing |
| XOR-hidden paths | 0x5478e0 | The five fingerprinted paths don't show up in a strings dump |
| Split secret, wiping | 0x546710, 0x547a60 | Secret never stored whole; key material zeroed after use |
| Self-hash | 0x514270 | Any byte patch to the executable changes the keys |

### What this means in practice

- **Forks and rebrands** that replace the `reglinux-arcade` splash or change `plymouthd.conf` lose game launching.
- **Users** who customise their boot splash, or edit `/etc/init.d/S06regmsgd` (for example `DAEMON_OPTS`), get the same result after the next daemon restart.
- **Developers** debugging with strace or gdb see launches fail only while attached, which is easy to misdiagnose.
- **Binary patches**, including legitimate hotfixes, break launching unless the seal is regenerated.
- Every failure looks like a missing emulator binary. Nothing is logged that points at integrity.

## Credentials and root password

With `system.security.enabled` off, the root and SMB password is the fixed `linux`. With it on, the password is random or user-set, but it's stored encrypted under a key derived only from a hardware serial, which is readable, and sometimes empty. All observed in the sandbox with stub binaries:

- **Off (default):** at every boot the daemon runs `ksmbd.adduser … -p linux root` and `openssl passwd -1 linux`. `getRootPassword` returns `linux`, and `setRootPassword` refuses.
- **`enforceSecurity 1`:** generates an 8-character random alphanumeric password (e.g. `6xVih4W8`), switches ksmbd to `/etc/ksmbd/ksmbd-secure.conf`, and writes `/run/reglinux.shadow` with `root:$1$…` (MD5-crypt) and `reglinux:!`. It saves the password to `/boot/system-boot.conf` as `system.security.rootshadowpassword=enc:<base64>`.
- Passwords travel as command-line arguments to `ksmbd.adduser` and `openssl`, so they're briefly visible in the process list.

**Storage format, fully reversed and verified.** `enc:` + base64 of `Salted__` ‖ 8-byte random salt ‖ ciphertext:

```
key || iv = PBKDF2-HMAC-SHA256(hwid, salt, 10000, 32)
cipher = AES-128-CBC(key=bytes 0–15, iv=bytes 16–31), PKCS#7
```

*hwid* comes from the first source found: the `/proc/cpuinfo` `Serial` (Raspberry Pi), `/sys/class/dmi/id/product_uuid`, NVMe serials, or an SD/eMMC `device/cid`. In the sandbox none matched, the passphrase was empty, and I decrypted both stored test passwords offline (`MyChosenPw1`, `RootSecret99`).

Why it matters: the boot partition is FAT and readable on any computer. Pi serials and SD CIDs are readable by any local user or printed on hardware. On machines without a recognised ID, every installation shares the same empty-passphrase key. So this is obfuscation, not protection, of the root password, and MD5-crypt is a weak shadow hash.

## regmsg and regmsg_shell (clients)

Both clients are thin front ends. They turn input into a text command, send it over `/var/run/regmsgd.sock` and print the reply. Neither touches the system directly, and neither contains hidden logic.

**`regmsg`** is a clap-based CLI with 11 command groups. Each subcommand maps to exactly one daemon verb. Arguments containing spaces or quotes are wrapped in double quotes, with `\\` and `\"` escaped.

| CLI group | Daemon verbs sent |
|-----------|-------------------|
| `screen` | `listModes`, `listOutputs`, `getMode`, `getOutput`, `getResolution`, `getRotation`, `getRefresh`, `getBackend`, `setMode`, `setOutput`, `setRotation`, `getScreenshot`, `mapTouchScreen`, `minToMaxResolution` (optional output name appended) |
| `systemconf` | `loadConfig`, `getConfigKey`, `setConfigKey <file> k v …`, `delConfigKey <file> k …` |
| `wifi` | `wifi.list`, `.scan`, `.enable [ssid] [key]`, `.disable`, `.status`, `.saved`, `.delete` |
| `launcher` | `launcher.resolve`, `.generate`, `.reload`, `.launch`, `.prepare`, `.commit`, `.cancel`, `.status`, `.stop` |
| `powermode` | `powermode <ac|battery|default|highperformance|balanced|powersaver>` |
| `achievement` | `achievement.unlocked <id> <title> <description>` (called by RetroArch's `cheevos_cmd` hook) |
| `brightness` | `getBrightness`, `setBrightness`, `listBrightness` |
| `audio` | `getVolume`, `setVolume`, `getMute`, `setMute`, `list/get/setAudioDevice`, `list/get/setAudioProfile` |
| `security` | `getRootPassword [0|1]`, `setRootPassword [pw]`, `enforceSecurity <0|1>` |
| `bluetooth` | `bluetooth.start/stop/enable/disable/status/list/devices/info/pairable/pair/connect/disconnect/remove/forget`, `.scan.start/results/stop`, `.autopair.start/status/stop` |
| `bios` | `bios.check [--all] [--lines] [system]` |

The client waits 10 s per command by default. It waits 60 s for `wifi.scan`, `wifi.enable`, `launcher.generate`, `launcher.prepare`, `library.load`, `library.scan`, `bluetooth.start/enable/pair/connect/forget`, and 180 s for `launcher.launch/commit/stop`. I read these by calling the client's `deadline_for` function directly under gdb.

**`regmsg_shell`** is an interactive REPL (`--socket-path`, default `/var/run/regmsgd.sock`; `--timeout` ms). On start it sends `listCommands` to fetch the daemon's command list. The prompt is `[<hostname>]>`. Local commands are `help`, `clear` and `exit`/`quit`/`q`; everything else is passed through verbatim. It reconnects after a dropped connection and pretty-prints JSON replies.

### Wire protocol

Each message is one length-prefixed frame on the Unix stream socket, all integers big-endian. I confirmed this by capturing real client traffic and feeding crafted replies back:

| Bytes | Field | Values |
|-------|-------|--------|
| 0–3 | Length of everything after this field | u32 |
| 4 | Frame type | 0 Request, 1 ReplyOk, 2 ReplyErr, 3 Event |
| 5–8 | Request id; the reply must echo it | u32, client starts at 1 |
| 9… | Payload | UTF‑8 command line, or reply text/JSON |

The client rejects mismatched ids, an Event or Request in the reply slot, and unknown frame types.

## libdrmhook.so

`libdrmhook.so` makes the Wayland compositor start in the resolution the daemon chose, by rewriting which display mode libdrm reports as "preferred". It is a 16 KB C library with two functions, fully disassembled. The daemon starts `/usr/bin/sway -c /etc/sway/launchconfig` with `LD_PRELOAD=/usr/lib/libdrmhook.so`, and its KMS backend writes the wanted mode to `/var/run/drmMode`.

What it does on every call to `drmModeGetConnector(fd, id)`:

1. Resolves the real libdrm function once via `dlsym(RTLD_NEXT)`. If that fails it prints an error to stderr and returns NULL.
2. Calls the real function. If the connector is NULL or has no modes, it prints `[HOOK] No modes found or connector is NULL.` and returns it unchanged.
3. `read_preferred_mode()` opens `/var/run/drmMode`, reads one line (up to 128 bytes) and parses `%ux%u@%u` (width × height @ refresh). If that fails it returns the connector untouched.
4. Walks every mode. The first whose `hdisplay`, `vdisplay` and `vrefresh` match gets the `DRM_MODE_TYPE_PREFERRED` bit (0x8). Every other mode, including later duplicates, has that bit cleared.
5. Swaps the matching mode into slot 0 of the mode array and prints `[HOOK] Updated preferred mode to: <name> WxH@RHz`.

Side effects and quirks:

- It writes to the host process's stdout on every call.
- It re-reads the file on every call, so a change takes effect at the next connector query with no caching.
- No network, no other file access, no hidden behaviour.

**No technical reason for precompilation.** This library is 50 lines of standard C that calls only `dlsym` and libc functions. A source reconstruction was tested against the original in five cases (matching mode, non-matching modes, malformed file, missing file) and produced identical output in every case. It has no dependency on `regmsgd`'s anti-tamper system: it does not communicate with the daemon, contains no integrity check, and works the same whether the daemon's seals are intact or broken. The only link between the two is that `regmsgd` writes `/var/run/drmMode` and starts sway with the hook loaded — any program that does the same gets the same result.

## Network behaviour

Only `regmsgd` uses the network, and only for metadata scraping and RetroAchievements. There's no telemetry, update check or phone-home, and no listening network socket. It uses the `ureq` HTTP client with rustls. These are every external endpoint in the binary:

| Endpoint | Used for | Credentials |
|----------|----------|-------------|
| `https://api.screenscraper.fr/api2` | Game metadata and media | User's ScreenScraper login + the sealed developer ID/password |
| `https://api.thegamesdb.net/v1` | Game metadata | API key from config (`scraper.thegamesdb.apikey`) |
| `https://id.twitch.tv/oauth2/token`, `https://api.igdb.com/v4`, `images.igdb.com` | IGDB metadata | Client ID/secret from config |
| `https://db.hfsplay.fr/api/v1` | HFSDB metadata | — |
| `http://adb.arcadeitalia.net/service_scraper.php` | Arcade metadata | None; **plain HTTP** |
| `https://retroachievements.org/dorequest.php` | Login token for RetroAchievements | User's RA account |

Identifying data sent is limited to what these APIs need: ROM name, size, CRC/MD5, serial and system. The developer password parameters are masked as `***` in the logs.

## Legal basis for this analysis

The `regmsgd` binary is distributed with the following licence notice:

> Copyright (c) 2025 REG Linux. All rights reserved.
> You may NOT redistribute, modify, reverse-engineer, or sell the software.

This analysis was conducted under the following legal basis:

**UK law — Copyright, Designs and Patents Act 1988 (CDPA)**

- **Section 50BA** permits a lawful user of a computer program to "observe, study or test the functioning of the program in order to determine the ideas and principles which underlie any element of the program," provided this is done while performing any act of loading, displaying, running, transmitting or storing the program which the user is entitled to do.
- **Section 296A(1)** provides that any contractual term that purports to prohibit or restrict acts permitted under section 50BA **is void**. A licence clause stating "You may NOT reverse-engineer" cannot override this statutory right.
- **Section 50B** separately permits decompilation where necessary to achieve interoperability with an independently created program, subject to the conditions in that section.

**EU law — Software Directive 2009/24/EC**

- **Article 5(3)** provides the equivalent right to observe, study and test the functioning of a program to determine its underlying ideas and principles, without requiring authorisation from the rightholder.
- **Article 8** renders void any contractual provision contrary to Article 5(3).

**US law — for reference**

- **17 U.S.C. § 1201(f)** permits reverse engineering of a computer program for the purpose of identifying and analysing elements necessary to achieve interoperability, notwithstanding anti-circumvention provisions.
- Under *Sega v. Accolade* (1992) and *Sony v. Connectix* (2000), intermediate disassembly for the purpose of understanding unprotected functional elements constitutes fair use.

**Nature of this research**

This investigation examined the security, integrity and undisclosed behaviour of a publicly distributed binary that forms part of a system advertised as "fully open source." The research was undertaken to:

1. Document undisclosed functionality that affects the reliability of users' systems (a hidden kill switch that silently disables game launching).
2. Identify anti-analysis measures designed to frustrate the examination of software behaviour.
3. Assess the accuracy of the project's open-source licensing claims against its actual distribution practices.
4. Evaluate the security of the root-password storage mechanism.

No sealed credentials were extracted or published. No proprietary source code was reconstructed beyond what was necessary to verify functional behaviour. The ScreenScraper developer credentials embedded in the binary were deliberately left unsealed.

**On the licence itself**

The licence states the software is provided "in binary form only" and prohibits reverse engineering. However, the same project's [public README](https://github.com/reg-linux) describes it as "Fully open source" with components "released under open-source licenses (GPL-2.0, MIT, or similar)." A binary distributed as part of a GPL-2.0-licensed system, linked against GPL libraries, and essential to the functioning of that system raises its own compliance questions that are beyond the scope of this report but may be relevant to the enforceability of the licence's restrictions.
