# REG-Linux ships a hidden kill switch in its "fully open-source" gaming system

REG-Linux [claims to be](https://github.com/reg-linux) "Fully open source" with a "transparent build system and clean codebase," and says all its components are "released under open-source licenses (GPL-2.0, MIT, or similar)."

That's not what the binaries say.

Buried inside `regmsgd` — the stripped, closed-source root daemon at the heart of every REG-Linux install — is a mechanism that functions much like Nintendo's boot-logo copy protection: if you change the wrong files, every game launch silently fails. No error message tells you why. No log entry points to the cause. Your emulator paths are cryptographically scrambled before they reach the kernel, and all you see is `"No such file or directory"`.

I reverse-engineered the entire system byte for byte and reproduced it experimentally.

---

## What triggers it

The daemon derives a cryptographic key from **four inputs** every time it launches a game. If any one of them is wrong, launches are dead:

1. **Five specific files must be untouched** — the daemon's own init script, the Plymouth boot splash config, and three REG-Linux splash theme files. Their paths are XOR-obfuscated so they don't show up in a strings dump. Each is BLAKE3-hashed at startup; change a single byte in any of them and the key changes.

2. **The binary itself must be unmodified** — at runtime, `regmsgd` reads its own executable from `/proc/self/exe`, zeroes out three post-link patch slots, and BLAKE3-hashes the entire 12.3 MB file. Any patch — even a legitimate hotfix — changes the hash and breaks the key.

3. **A secret baked into the binary** — stored as two XOR shares so it never appears whole in the file. Recombined on use, then wiped from memory.

4. **No debugger can be attached** — the daemon reads `TracerPid` from `/proc/self/status` and folds it into the key material. Attaching strace or gdb doesn't just get detected — it silently poisons every game launch for as long as the debugger is connected.

These four values produce 104 bytes of key material. BLAKE3 `derive_key` with the context string `"regmsg-launch-v1"` turns that into a 32-byte mask, XORed against a sealed value baked into the binary at build time. On a genuine, unmodified, untraced REG-Linux system, the mask comes out to all zeros and launches work. Anywhere else, the first 32 bytes of every emulator path are scrambled into garbage before the syscall.

## What it kills

- **Fork the project** and put your own boot splash on it? Game launching breaks.
- **Customise your own boot splash** or edit the init script? Same result after the next reboot.
- **Debug a problem** with strace or gdb? Launches fail only while the debugger is attached — designed to be misdiagnosed.
- **Apply a binary patch** — even a one-byte fix? The self-hash changes and nothing launches.
- **Every single failure** looks like a missing emulator binary. Nothing is logged that points at the real cause.

This is not a side effect. This is by design. The five monitored file paths are the only XOR-obfuscated strings in the entire binary. The daemon also exits silently if `LD_PRELOAD` or `LD_AUDIT` is set (the standard tools for intercepting library calls), marks itself non-dumpable to block ptrace, and builds the environment-variable names as stack immediates so they're invisible to `strings`. This is an anti-tamper system with anti-analysis layered on top.

## It also locks down scraper credentials

The same key material gates a second function: the embedded ScreenScraper developer API credentials (ID and password) are stored as a 128-byte encrypted blob. Same key, same conditions. Tamper with anything and the credentials decrypt to garbage, silently degrading the scraping experience.

## The root password is barely protected

Separately, when security mode is on, the root password is saved to the FAT boot partition — readable on any computer — encrypted with AES-128-CBC keyed from the device's hardware serial number. On Raspberry Pis that's printed on the board. On machines with no recognised serial, the encryption passphrase is **empty**. I decrypted both test passwords offline in seconds. The shadow hash uses MD5-crypt. This is obfuscation, not security.

## No telemetry, but plain HTTP

On the network side: no phone-home, no telemetry, no update checks. The daemon talks only to game metadata scrapers (ScreenScraper, TheGamesDB, IGDB, HFSDB, ArcadeDB) and RetroAchievements. One of these — ArcadeDB — is contacted over **plain HTTP**, not HTTPS.

## How I proved it

Every claim was confirmed by running the binary in a sandboxed environment, not just reading disassembly. The kill switch was verified with an A/B test: an identical copy of the daemon with only the 32-byte marker reset to the unpatched placeholder (`0xA5 × 32`) launched the same ROM that the original refused. I then recomputed the scrambled emulator path offline from first principles and it matched the exact bytes gdb captured — a byte-for-byte prediction.

The binary has ~11,400 functions. The security-relevant and hidden paths were fully disassembled and verified. I could not test against genuine REG-Linux splash files, so the claim that the mask is zero on a genuine system is *inferred* from the design — but the alternative (that no REG-Linux installation can launch games) seems unlikely.

---

*Analysis of `regmsgd` from archive `reglinux-msg`, commit `da5cd551`, x86_64, built 2026-10-13.*
