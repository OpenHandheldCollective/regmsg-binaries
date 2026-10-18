# regmsg binaries — follow-up report: build `8d65761` vs `da5cd55`

**Date:** 2026-10-18
**Scope:** Diff of the REG-Linux `regmsg-binaries` release archives between commit
`da5cd551f1508e0a7632054d6f63c09ab403f7b1` (built 2026-10-13) and commit
`8d6576102f903d74367356a3a1f633eebfd9e1a9` (built 2026-10-18). This extends the
original reverse-engineering report and assumes its findings.

---

## Summary

The new build was published five days after the one the original report covered,
and on the same day this comparison was written. It does not retreat from the
anti-tamper system. It keeps the launch kill switch and the sealed credentials
intact, rotates the obfuscation key that hides the files they depend on, and wraps
the whole thing in a new licence that forbids modifying or redistributing even the
parts shipped as readable source. The one genuinely open component, `libdrmhook.so`,
is still shipped as a precompiled blob, byte-for-byte identical to the previous
build, despite now being labelled MIT.

The headline change is a `LICENSE` file. It discloses, in plain language, the
integrity checks the original report had to recover by hand. Disclosure is welcome,
but it changes the packaging, not the mechanism: the lock that breaks game launching
on a modified or forked system is still present, still keyed to REG-Linux's own
branding files, and still surfaces as a misleading "No such file or directory". The
project has written down what it does and then licensed away the user's right to do
anything about it.

## What changed, file by file

| File | Old | New | Change |
|------|-----|-----|--------|
| `/usr/lib/libdrmhook.so` | 16064 B | 16064 B | **Identical** (byte for byte) |
| `/usr/bin/regmsg` | 4514976 B | 4514960 B | Rebuilt, ~same size |
| `/usr/bin/regmsg_shell` | 3125696 B | 3125696 B | Rebuilt, same size |
| `/usr/bin/regmsgd` | 12302648 B | 12413240 B | **+108 KB** (~+81 KB code, ~+25 KB rodata) |
| `/etc/init.d/S06regmsgd` | — | — | MIT/SPDX header added |
| `LICENSE`, `THIRD_PARTY_LICENSES` | absent | **added** | New licensing files |
| Launch generators (Lua) + keymaps (JSON) | — | — | Almost all rewritten; refactored onto a shared `lib/launch.lua` |

Generators added: `lib/launch.lua`, `lib/mame_data.lua`, `lib/fallout_ce.lua`,
`lib/libretro/dualscreen.lua`. Removed: `lib/guns_precal.lua`,
`lib/libretro/dispatch.lua`. The daemon's extra code tracks this launcher refactor
and new launcher features (dual-screen, video output, battery mode), not an
expansion of the lock.

## The anti-tamper system is intact

Every load-bearing piece of the mechanism from the original report is still present
in the new daemon, unchanged in structure:

- **Same key-derivation contexts.** `regmsg-launch-v1` and `regmsg-cred-v1` are both
  still in the binary. The launch kill switch and the sealed ScreenScraper
  credentials still derive from the same four inputs (embedded secret, self-hash,
  hidden-file fingerprint, TracerPid).
- **Same five hidden files.** The fingerprint still covers the init script, the two
  Plymouth config files, and the two `reglinux-arcade` splash/theme files. The list
  did not change.
- **Same failure path.** The `spawn_failed` launch error is still there, so a
  mismatch still scrambles the emulator path and fails the launch with an OS "No such
  file or directory (os error 2)" — the same misleading symptom, blamed on a missing
  emulator rather than on an integrity check.

### The one mechanism change: the obfuscation key was rotated, not removed

In the old build the five fingerprinted paths were hidden with a single-byte XOR of
`0xA6`. In the new build a scan for those paths under `0xA6` finds nothing — but a
brute-force sweep of all 255 keys shows they are simply re-encoded under `0x53`. The
decoded paths are identical. The response to having the obfuscation documented was to
change the key, keeping the strings out of a plain `strings` dump exactly as before.
Obfuscating paths that a new `LICENSE` file now lists in prose serves no protective
purpose; it only preserves the inconvenience to anyone inspecting the binary
directly.

## The new LICENSE: disclosure wrapped around a restriction

The new `LICENSE` is the substantive change, and it cuts against open source rather
than toward it.

**It documents the lock.** Section 3 states that `regmsgd` checks its own executable
and "a small set of REG-Linux boot and branding files," checks for a debugger, and
that on failure "the scraper credentials stay locked and the daemon will not launch
games." This matches the reverse-engineered behaviour. Writing it down removes the
"you weren't told" part of the original finding — but only for someone who reads the
licence, and it is still enforced through hidden, obfuscated paths and misleading
errors rather than an honest runtime message.

**It declares readable source non-free.** Section 1 places `regmsgd`, `regmsg`,
`regmsg_shell` **and the launch generators and JSON action tables** under a
proprietary licence. The Lua and JSON ship in readable form, but the licence
forbids distributing modified copies of them, selling them standalone, or using them
"in a way that relies on, or gets around, their integrity checks." Readable text that
you may not modify and redistribute is not open source; it is source-available under a
no-fork licence. A user may edit generators "on your own device, for your own use"
only.

**It relicenses the open parts but keeps them precompiled.** Section 2 labels
`libdrmhook.so` and "regmsg's original code inside `regmsgd`, `regmsg` and
`regmsg_shell`" as MIT. Yet `libdrmhook.so` still ships only as a 16 KB precompiled
blob — the exact same bytes as before — with no source in the archive. As the
original report showed, it is ~50 lines of standard C that calls only `dlsym` and
libc, has no dependency on `regmsgd`, and reproduces identically from a source
rebuild. Declaring it MIT while continuing to ship it as a blob, with its source
withheld, is the form of open source without the substance.

**It acknowledges reverse-engineering rights.** The licence cites EU Directive
2009/24/EC and the UK CDPA and affirms the right to study, test and decompile for
interoperability and LGPL debugging. This is a reasonable addition and worth noting.

## The main project README was also changed

Alongside the new build, the project edited its top-level README licensing
statement. The original report opened on a contradiction: REG-Linux described
itself as "Fully open source" with a "transparent build system and clean codebase"
while shipping these binaries without source. That claim is now gone. The README
now states the project is **"not entirely open source"** and gives a breakdown:

| Component | Stated licence |
| --------- | -------------- |
| The repository (board support, recipes, configs, overlays, scripts) | GPL-2.0-or-later |
| The software the recipes build (kernel, emulators, libraries) | Each package's own licence |
| **REG-Station** (frontend) and **regmsg** (daemon) | **Proprietary — binaries only** |
| Some firmware and GPU drivers | Vendor binaries under their own licences |

This is the clearest concession in the whole update. The project has publicly
dropped the "Fully open source" framing and now names REG-Station and regmsg as
proprietary, binary-only components. It aligns the public description with what the
binaries always did.

It changes the marketing, not the mechanics. The daemon is still a closed binary with
a launch lock keyed to REG-Linux's branding, the credentials are still sealed, the
obfuscation is still present, and the generators the README's open-source parts rely
on are still under the no-modification regmsg licence. Relabelling the project "not
entirely open source" removes the false claim the original report rested part of its
case on, but it does not loosen the lock or publish the withheld source; it concedes
the characterisation while keeping the practice.

## Assessment

The project reacted quickly and chose to formalise the behaviour rather than change
it. The anti-tamper lock that breaks launching on forks, rebrands and customised boot
splashes is still there; the credential seal is still there; the path obfuscation is
still there with a fresh key; the misleading error is still there. On top of that the
new licence now explicitly forbids the modification and redistribution that open
source exists to permit, and extends that prohibition to the readable Lua and JSON
that previously looked like the open, hackable part of the system.

Documenting a restriction is better than hiding it, and the RE-rights clause and MIT
labelling of the client code are real improvements. The README now concedes the project is "not
entirely open source," which drops the specific false claim the original report
opened on. But the net direction of this build is still to entrench the lock and put
a no-fork licence around the readable parts. For a downstream developer who wants to fork
REG-Linux, change its branding, or ship a modified launcher, nothing has become
possible that was impossible in the previous build — and the licence now says in
writing that they may not.

## Method

Both release archives were unpacked and compared by file list, SHA-256, and size.
Build provenance was read from the embedded `reglinux-msg-<commit>` vendor paths.
The anti-tamper mechanism was checked by locating the key-derivation context strings,
the `spawn_failed` path, and the fingerprinted file paths; the obfuscation key was
recovered by a 255-key single-byte XOR brute force against known path fragments. No
claim here depends on running the new daemon; the structural findings are from static
comparison against the fully reversed previous build.
