"""通用工具：权限、数据目录、日志、PowerShell/命令行执行、哈希、注册表、隔离区."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime

APP_NAME = "SFguard"
CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------- 权限

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate(args: list[str] | None = None) -> bool:
    """以管理员身份重新启动自己（UAC 提权）。返回是否成功发起。"""
    if is_admin():
        return True
    try:
        params = " ".join('"%s"' % a for a in (args if args is not None else sys.argv[1:]))
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, os.getcwd(), 1
        )
        return int(rc) > 32
    except Exception:
        return False


def username() -> str:
    return os.environ.get("USERNAME", "")


def hostname() -> str:
    return os.environ.get("COMPUTERNAME", "")


def is_windows() -> bool:
    return os.name == "nt"


def windows_version() -> str:
    try:
        import platform

        return f"{platform.system()} {platform.release()} ({platform.version()})"
    except Exception:
        return "Windows"


# --------------------------------------------------------------------------- 目录

def _writable(path: str) -> bool:
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write-test")
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe)
        return True
    except Exception:
        return False


def data_root() -> str:
    """程序数据目录，优先 ProgramData（全机共享），不可写时退回 %LOCALAPPDATA%。"""
    candidates = []
    pd = os.environ.get("PROGRAMDATA")
    if pd:
        candidates.append(os.path.join(pd, APP_NAME))
    la = os.environ.get("LOCALAPPDATA")
    if la:
        candidates.append(os.path.join(la, APP_NAME))
    candidates.append(os.path.join(os.path.expanduser("~"), "." + APP_NAME.lower()))
    for c in candidates:
        if _writable(c):
            return c
    return os.path.join(os.environ.get("TEMP", "."), APP_NAME)


def subdir(name: str) -> str:
    p = os.path.join(data_root(), name)
    os.makedirs(p, exist_ok=True)
    return p


def quarantine_dir() -> str:
    return subdir("quarantine")


def report_dir() -> str:
    return subdir("reports")


def log_dir() -> str:
    return subdir("logs")


# --------------------------------------------------------------------------- 日志

class Logger:
    def __init__(self, filename: str | None = None, echo: bool = True):
        self.echo = echo
        self.lines: list[str] = []
        self.path = os.path.join(log_dir(), filename or f"sfguard-{datetime.now():%Y%m%d}.log")

    def _write(self, level: str, msg: str) -> None:
        line = f"{datetime.now():%Y-%m-%d %H:%M:%S} [{level}] {msg}"
        self.lines.append(line)
        if self.echo:
            try:
                print(line)
            except Exception:
                pass
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def info(self, msg: str) -> None:
        self._write("INFO", msg)

    def warn(self, msg: str) -> None:
        self._write("WARN", msg)

    def error(self, msg: str) -> None:
        self._write("ERROR", msg)

    def ok(self, msg: str) -> None:
        self._write(" OK ", msg)


# --------------------------------------------------------------------------- 执行

def _decode(raw: bytes) -> str:
    if not raw:
        return ""
    for enc in ("utf-8", "gbk", "mbcs"):
        try:
            text = raw.decode(enc)
            if enc != "utf-8" or text.count("\ufffd") < 3:
                return text
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def _powershell() -> str | None:
    for name in ("powershell.exe", "pwsh.exe"):
        p = shutil.which(name)
        if p:
            return p
    default = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    return default if os.path.exists(default) else None


def run_ps(script: str, timeout: int = 120, logger: Logger | None = None) -> tuple[int, str, str]:
    exe = _powershell()
    if not exe:
        return 127, "", "PowerShell 不可用"
    prefix = (
        "$ProgressPreference='SilentlyContinue';"
        "$ErrorActionPreference='Continue';"
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
    )
    cmd = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-Command", prefix + script]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW if is_windows() else 0)
        out, err = _decode(p.stdout), _decode(p.stderr)
        if logger and p.returncode != 0 and err.strip():
            logger.warn(f"PowerShell 返回 {p.returncode}: {err.strip()[:400]}")
        return p.returncode, out, err
    except subprocess.TimeoutExpired:
        if logger:
            logger.warn(f"PowerShell 超时（{timeout}s）")
        return 124, "", "timeout"
    except Exception as exc:  # pragma: no cover
        if logger:
            logger.warn(f"PowerShell 执行异常: {exc}")
        return 1, "", str(exc)


def run_cmd(args: list[str], timeout: int = 90) -> tuple[int, str, str]:
    try:
        p = subprocess.run(args, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW if is_windows() else 0)
        return p.returncode, _decode(p.stdout), _decode(p.stderr)
    except Exception as exc:
        return 1, "", str(exc)


def ps_json(script: str, timeout: int = 120, logger: Logger | None = None):
    """执行 PowerShell 并把输出当 JSON 解析，失败返回 None。"""
    rc, out, err = run_ps(script, timeout=timeout, logger=logger)
    out = (out or "").strip()
    if not out:
        return None
    # 去掉可能的 BOM / 前导空白
    out = out.lstrip("\ufeff").strip()
    try:
        return json.loads(out)
    except Exception:
        # 尝试截取第一个 JSON 起始位置
        for i, ch in enumerate(out):
            if ch in "[{":
                try:
                    return json.loads(out[i:])
                except Exception:
                    break
    if logger:
        logger.warn(f"JSON 解析失败，输出片段: {out[:200]!r}")
    return None


# --------------------------------------------------------------------------- 文件

def sha256_file(path: str, limit: int = 600 * 1024 * 1024) -> str | None:
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TB"


def safe_name(path: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", os.path.basename(path) or "item")
    return name[:80]


def quarantine(path: str, reason: str, logger: Logger) -> tuple[bool, str]:
    """把文件/目录移入隔离区，返回 (是否成功, 说明)。"""
    if not os.path.exists(path):
        return True, "已不存在"
    qroot = quarantine_dir()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = os.path.join(qroot, f"{stamp}_{safe_name(path)}")
    i = 1
    while os.path.exists(target):
        target = os.path.join(qroot, f"{stamp}_{i}_{safe_name(path)}")
        i += 1
    digest = sha256_file(path) if os.path.isfile(path) else None
    try:
        shutil.move(path, target)
    except Exception as exc:
        # 被占用：尝试授予权限后重试一次
        try:
            run_ps(f"takeown /f '{path}' /r /d y 2>$null; "
                   f"icacls '{path}' /grant administrators:F /t 2>$null; Start-Sleep -Milliseconds 300",
                   timeout=60, logger=logger)
            shutil.move(path, target)
        except Exception:
            logger.error(f"隔离失败 {path}: {exc}")
            return False, f"隔离失败：{exc}"
    record = {
        "time": datetime.now().isoformat(timespec="seconds"),
        "original": path,
        "quarantine": target,
        "sha256": digest,
        "reason": reason,
    }
    try:
        with open(os.path.join(qroot, "manifest.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception:
        pass
    logger.ok(f"已隔离 {path} -> {target}")
    return True, target


def force_rmtree(path: str, logger: Logger) -> bool:
    try:
        shutil.rmtree(path, ignore_errors=False)
        return True
    except Exception:
        run_ps(f"takeown /f '{path}' /r /d y 2>$null; icacls '{path}' /grant administrators:F /t 2>$null",
               timeout=60, logger=logger)
        try:
            shutil.rmtree(path, ignore_errors=True)
            return not os.path.exists(path)
        except Exception:
            return False


# --------------------------------------------------------------------------- 注册表

def reg_read(root: int, path: str, name: str, default=None):
    import winreg

    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as k:
            value, _ = winreg.QueryValueEx(k, name)
            return value
    except Exception:
        return default


def reg_write(root: int, path: str, name: str, value, kind: int | None = None) -> bool:
    import winreg

    try:
        with winreg.CreateKeyEx(root, path, 0, winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, name, 0, kind or winreg.REG_SZ, value)
        return True
    except Exception:
        return False


def reg_delete_value(root: int, path: str, name: str) -> bool:
    import winreg

    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
        return True
    except Exception:
        return False


def reg_delete_tree(root: int, path: str) -> bool:
    import winreg

    def _del(sub: str):
        try:
            with winreg.OpenKey(root, sub, 0, winreg.KEY_READ) as k:
                children = []
                i = 0
                while True:
                    try:
                        children.append(winreg.EnumKey(k, i))
                        i += 1
                    except OSError:
                        break
            for c in children:
                _del(sub + "\\" + c)
        except Exception:
            pass
        try:
            winreg.DeleteKey(root, sub)
        except Exception:
            pass

    _del(path)
    return True


def reg_list_values(root: int, path: str) -> dict:
    import winreg

    result = {}
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                    result[name] = value
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return result


def reg_list_subkeys(root: int, path: str) -> list[str]:
    import winreg

    subs = []
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    subs.append(winreg.EnumKey(k, i))
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return subs


# --------------------------------------------------------------------------- 其他

def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def open_folder(path: str) -> None:
    try:
        os.startfile(path)  # noqa: S606
    except Exception:
        run_cmd(["explorer.exe", path])


def json_dump(obj, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def expand(path: str) -> str:
    return os.path.expandvars(os.path.expanduser(path))


def which(name: str) -> str | None:
    return shutil.which(name)


def hide_console() -> None:
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass
