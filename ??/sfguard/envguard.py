"""环境自检与自修复：让工具在任意 Win10/11 上「自己把环境补齐」后再工作."""

from __future__ import annotations

import json
import os
import shutil
import time

from . import ioc
from .util import (
    Logger,
    data_root,
    is_admin,
    quarantine_dir,
    reg_read,
    reg_write,
    report_dir,
    run_cmd,
    run_ps,
    subdir,
)

DEFENDER_SERVICES = ("WinDefend", "WdNisSvc", "SecurityHealthService", "Sense", "MpsSvc")


def _third_party_av_names() -> list[str]:
    from .util import ps_json

    data = ps_json(
        "try { ConvertTo-Json -InputObject @(Get-CimInstance -Namespace root/SecurityCenter2 "
        "-ClassName AntiVirusProduct -ErrorAction Stop | Select-Object displayName) -Compress } "
        "catch { '[]' }", timeout=40)
    if isinstance(data, dict):
        data = [data]
    names = []
    for a in data or []:
        n = str(a.get("displayName") or "").strip() if isinstance(a, dict) else ""
        if n and "defender" not in n.lower():
            names.append(n)
    return names


def _svc_state(name: str) -> str:
    rc, out, _ = run_cmd(["sc", "query", name], timeout=20)
    if rc != 0:
        return "missing"
    for line in out.splitlines():
        if "STATE" in line:
            return line.strip()
    return "unknown"


def _mpcmdrun() -> str | None:
    candidates = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     r"Windows Defender\MpCmdRun.exe"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                     r"Microsoft\Windows Defender\Platform"),
    ]
    if os.path.exists(candidates[0]):
        return candidates[0]
    base = candidates[1]
    if os.path.isdir(base):
        versions = sorted(os.listdir(base), reverse=True)
        for v in versions:
            p = os.path.join(base, v, "MpCmdRun.exe")
            if os.path.exists(p):
                return p
    # 通过 Defender 模块获取
    rc, out, _ = run_ps(
        "try{(Get-MpComputerStatus).AMRunningMode | Out-Null; "
        "(Get-Command MpCmdRun.exe -ErrorAction SilentlyContinue).Source}catch{}",
        timeout=40,
    )
    p = (out or "").strip().splitlines()
    if p and os.path.exists(p[0]):
        return p[0]
    return shutil.which("MpCmdRun.exe")


def _disk_free_gb(path: str) -> float:
    try:
        usage = shutil.disk_usage(path)
        return usage.free / (1024 ** 3)
    except Exception:
        return -1.0


def _pending_reboot() -> bool:
    keys = [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending", "HKLM"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired", "HKLM"),
    ]
    import winreg

    for path, _ in keys:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path):
                return True
        except Exception:
            continue
    return False


def inspect_environment(logger: Logger, quick: bool = False) -> list:
    """返回 EnvCheck 列表（不修改任何东西）。"""
    from .scanner import EnvCheck

    checks: list[EnvCheck] = []

    def add(key, name, status, detail, fix_label="", fix_action=""):
        checks.append(EnvCheck(key, name, status, detail, fix_label, fix_action))

    # 1. 权限
    admin = is_admin()
    add("admin", "管理员权限",
        "ok" if admin else "warn",
        "已具备管理员权限，可执行完整修复。" if admin
        else "当前为普通权限：可以体检，但修复需要提权（点击右侧按钮以管理员身份重启）。",
        "" if admin else "提权重启", "" if admin else "elevate")

    # 2. 数据目录
    try:
        root = data_root()
        ok = os.path.isdir(root) and os.access(root, os.W_OK)
        add("datadir", "程序工作目录", "ok" if ok else "fail",
            f"数据/隔离/报告目录：{root}" if ok else "无法创建程序工作目录（磁盘只读或权限受限）。",
            "" if ok else "重建目录", "" if ok else "env_repair")
    except Exception as exc:
        add("datadir", "程序工作目录", "fail", f"创建失败：{exc}", "重建目录", "env_repair")

    # 3. PowerShell
    from .util import _powershell

    ps = _powershell()
    add("powershell", "PowerShell 运行环境", "ok" if ps else "fail",
        f"已检测到 {ps}" if ps else "未找到 PowerShell，将降级为注册表/命令行方式（功能受限）。",
        "" if ps else "重新检测", "" if ps else "env_repair")

    # 4. Defender 服务
    if not quick:
        states = {}
        for svc in ("WinDefend", "MpsSvc"):
            states[svc] = _svc_state(svc)
        running = any("RUNNING" in states.get(s, "").upper() for s in ("WinDefend",))
        if running:
            add("defender-svc", "Defender 服务", "ok", f"WinDefend: {states.get('WinDefend', '?')}")
        else:
            third = _third_party_av_names()
            if third:
                add("defender-svc", "Defender 服务", "ok",
                    f"Defender 未运行，已由第三方安全软件接管：{'、'.join(third)}")
            else:
                add("defender-svc", "Defender 服务", "fail",
                    f"WinDefend: {states.get('WinDefend', '?')}（实时防护可能已失效）",
                    "启动并修复", "repair_defender")

    # 5. Defender 策略是否被恶意关闭
    disable_av = 0
    disable_rtp = 0
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Policies\Microsoft\Windows Defender") as k:
            try:
                disable_av = winreg.QueryValueEx(k, "DisableAntiSpyware")[0]
            except Exception:
                pass
    except Exception:
        pass
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection") as k:
            try:
                disable_rtp = winreg.QueryValueEx(k, "DisableRealtimeMonitoring")[0]
            except Exception:
                pass
    except Exception:
        pass
    if disable_av or disable_rtp:
        add("defender-policy", "Defender 策略完整性", "fail",
            "发现恶意策略键（DisableAntiSpyware=%s, DisableRealtimeMonitoring=%s），实时防护被强制关闭。"
            % (disable_av, disable_rtp), "清除篡改", "clean_defender_policy")
    else:
        add("defender-policy", "Defender 策略完整性", "ok", "未发现关闭防护的策略注入。")

    # 6. 磁盘空间
    free = _disk_free_gb(data_root())
    add("disk", "隔离区磁盘空间", "ok" if free < 0 or free > 0.5 else "warn",
        f"剩余 {free:.1f} GB" if free >= 0 else "无法读取磁盘信息")

    # 7. 待重启
    pending = _pending_reboot()
    add("reboot", "系统重启状态", "warn" if pending else "ok",
        "存在待重启的系统更新/组件，重启后部分修复才会完全生效。" if pending
        else "没有待重启项。")

    # 8. 网络（用于更新病毒库 / 上报样本）
    if not quick:
        ok = False
        for host, port in (("definitionupdates.microsoft.com", 443), ("www.virustotal.com", 443)):
            import socket

            try:
                s = socket.create_connection((host, port), timeout=3)
                s.close()
                ok = True
                break
            except Exception:
                continue
        add("network", "外网连通性", "ok" if ok else "warn",
            "可访问微软更新与 VirusTotal，可自动更新病毒库。" if ok
            else "当前无法直连微软更新或 VirusTotal（不影响本地查杀，仅影响自动更新与样本上报）。")

    # 9. 隔离区
    try:
        q = quarantine_dir()
        add("quarantine", "隔离区", "ok", q)
    except Exception as exc:
        add("quarantine", "隔离区", "fail", str(exc), "重建目录", "env_repair")

    return checks


# --------------------------------------------------------------------------- 修复

def provision(logger: Logger, progress=None) -> list[tuple[str, bool, str]]:
    """补齐运行环境，返回 [(步骤, 是否成功, 说明)]。"""
    out: list[tuple[str, bool, str]] = []

    def step(name: str, fn) -> None:
        if progress:
            progress(name)
        logger.info(f"[环境] {name}")
        try:
            ok, msg = fn()
        except Exception as exc:
            ok, msg = False, str(exc)
        out.append((name, ok, msg))
        (logger.ok if ok else logger.warn)(f"{name}: {msg}")

    def _dirs():
        root = data_root()
        for sub in ("logs", "quarantine", "reports"):
            subdir(sub)
        return True, root

    def _defender_policy():
        import winreg

        removed = []
        targets = [
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting"),
        ]
        for path, name in targets:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE) as k:
                    try:
                        winreg.QueryValueEx(k, name)
                    except FileNotFoundError:
                        continue
                    winreg.DeleteValue(k, name)
                    removed.append(f"{path}\\{name}")
            except Exception:
                continue
        # 整棵 Exclusions 策略树
        for tree in (r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",):
            from .util import reg_delete_tree

            reg_delete_tree(winreg.HKEY_LOCAL_MACHINE, tree)
        return True, f"已移除 {len(removed)} 个策略值，并清理 Exclusions 策略树"

    def _defender_start():
        started = []
        for svc in ("WinDefend", "WdNisSvc", "SecurityHealthService", "MpsSvc"):
            rc, out, _ = run_cmd(["sc", "query", svc], timeout=20)
            if rc != 0:
                continue
            if "RUNNING" not in out.upper():
                run_cmd(["sc", "start", svc], timeout=60)
                if "RUNNING" in _svc_state(svc).upper():
                    started.append(svc)
        return True, ("已启动: " + ", ".join(started)) if started else "服务已在运行"

    def _defender_rtp():
        rc, out, err = run_ps(
            "Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; "
            "Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue; "
            "Set-MpPreference -DisableIOAVProtection $false -ErrorAction SilentlyContinue; "
            "'ok'", timeout=90, logger=logger)
        return ("ok" in out.lower()), (out.strip() or err.strip())[:200]

    def _signature():
        exe = _mpcmdrun()
        if not exe:
            return False, "未找到 MpCmdRun.exe"
        rc, out, err = run_cmd([exe, "-SignatureUpdate"], timeout=300)
        return rc == 0, (out or err).strip().splitlines()[-1] if (out or err).strip() else f"退出码 {rc}"

    def _uac():
        import winreg

        changed = []
        for name, value in ioc.UAC_DEFAULTS.items():
            cur = reg_read(winreg.HKEY_LOCAL_MACHINE, ioc.UAC_KEY, name, None)
            if cur != value:
                if reg_write(winreg.HKEY_LOCAL_MACHINE, ioc.UAC_KEY, name,
                             value, winreg.REG_DWORD):
                    changed.append(name)
        return True, ("已恢复 " + ", ".join(changed)) if changed else "UAC 配置正常"

    def _proxy():
        import winreg

        key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        server = str(reg_read(winreg.HKEY_CURRENT_USER, key, "ProxyServer", "") or "")
        if server.startswith(("127.0.0.1:", "localhost:")):
            try:
                port = int(server.split(":")[-1])
            except Exception:
                port = 0
            import socket

            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
            except Exception:
                reg_write(winreg.HKEY_CURRENT_USER, key, "ProxyEnable", 0, winreg.REG_DWORD)
                return True, f"代理 {server} 已失效，已切换为直连"
        return True, "代理设置正常"

    step("建立工作目录", _dirs)
    if is_admin():
        step("清除 Defender 策略篡改", _defender_policy)
        step("启动安全服务", _defender_start)
        step("恢复实时保护", _defender_rtp)
        step("恢复 UAC 安全设置", _uac)
    else:
        out.append(("清除 Defender 策略篡改", False, "需要管理员权限"))
        out.append(("启动安全服务", False, "需要管理员权限"))
    step("修复失效代理", _proxy)
    return out


def repair_defender(logger: Logger, progress=None) -> list[tuple[str, bool, str]]:
    """Defender 深度修复：策略 + 服务 + 实时保护 + 必要时重置平台。"""
    results = provision(logger, progress)
    if not is_admin():
        return results

    if progress:
        progress("重置 Defender 平台")
    try:
        rc, out, _ = run_ps("(Get-MpComputerStatus).AMServiceEnabled", timeout=40, logger=logger)
        healthy = "true" in (out or "").lower()
    except Exception:
        healthy = False

    if not healthy:
        exe = _mpcmdrun()
        if exe:
            rc, out, err = run_cmd([exe, "-ResetPlatform"], timeout=300)
            results.append(("重置 Defender 平台", rc == 0,
                            (out or err).strip()[:300] or f"退出码 {rc}"))

    if progress:
        progress("更新病毒库")
    exe = _mpcmdrun()
    if exe:
        rc, out, err = run_cmd([exe, "-SignatureUpdate"], timeout=300)
        results.append(("更新病毒库", rc == 0, (out or err).strip()[:300] or f"退出码 {rc}"))

    # 清理 PowerShell 侧排除项
    if progress:
        progress("清理 Defender 排除项")
    rc, out, err = run_ps(
        "$n=0; "
        "$p=Get-MpPreference; "
        "foreach($x in @($p.ExclusionPath)){ if($x){ try{Remove-MpPreference -ExclusionPath $x -ErrorAction Stop; $n++}catch{} } }; "
        "foreach($x in @($p.ExclusionProcess)){ if($x){ try{Remove-MpPreference -ExclusionProcess $x -ErrorAction Stop; $n++}catch{} } }; "
        "foreach($x in @($p.ExclusionExtension)){ if($x){ try{Remove-MpPreference -ExclusionExtension $x -ErrorAction Stop; $n++}catch{} } }; "
        "\"removed=$n\"", timeout=120, logger=logger)
    results.append(("清理 Defender 排除项", "removed=" in (out or ""), (out or err).strip()[:200]))
    return results
