"""修复引擎：终止进程、清持久化、恢复防御、修复系统设置（全部可回滚）."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from . import ioc
from .envguard import provision, repair_defender
from .util import (
    Logger,
    expand,
    now_iso,
    quarantine,
    reg_delete_tree,
    reg_delete_value,
    reg_list_values,
    reg_write,
    report_dir,
    run_cmd,
    run_ps,
    sha256_file,
)


@dataclass
class FixOutcome:
    finding_id: str
    title: str
    ok: bool
    message: str


class Fixer:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.backup_path = os.path.join(report_dir(), "backups")
        os.makedirs(self.backup_path, exist_ok=True)
        self.backup_file = os.path.join(self.backup_path, f"registry-{time.strftime('%Y%m%d-%H%M%S')}.json")
        self.backups: list[dict] = []

    # ------------------------------------------------------------------ 备份
    def _backup(self, kind: str, detail: dict) -> None:
        self.backups.append({"time": now_iso(), "kind": kind, **detail})
        try:
            with open(self.backup_file, "w", encoding="utf-8") as f:
                json.dump(self.backups, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    # ------------------------------------------------------------------ 入口
    def fix(self, findings, progress=None) -> list[FixOutcome]:
        outcomes: list[FixOutcome] = []
        done_keys: set[str] = set()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
            if f.status == "已处理" or not f.fixable:
                continue
            key = f"{f.action}|{json.dumps(f.params, sort_keys=True, ensure_ascii=False, default=str)}"
            if key in done_keys:
                continue
            done_keys.add(key)
            if progress:
                progress(f"修复：{f.title}")
            self.logger.info(f"--- 修复 {f.title}")
            try:
                ok, msg = self._dispatch(f.action, f.params, f)
            except Exception as exc:
                ok, msg = False, str(exc)
            if ok:
                f.status = "已处理"
                f.fix_result = msg
                self.logger.ok(f"{f.title} -> {msg}")
            else:
                self.logger.warn(f"{f.title} -> 失败：{msg}")
            outcomes.append(FixOutcome(f.id, f.title, ok, msg))
        return outcomes

    def _dispatch(self, action: str, params: dict, finding=None) -> tuple[bool, str]:
        fn = getattr(self, f"do_{action}", None)
        if not fn:
            return False, f"未知修复动作 {action}"
        return fn(params)

    # ------------------------------------------------------------------ 动作
    def do_kill_process(self, p: dict) -> tuple[bool, str]:
        pids = p.get("pids") or ([p.get("pid")] if p.get("pid") else [])
        pids = [int(x) for x in pids if x]
        if not pids:
            return False, "缺少 PID"
        killed, failed = [], []
        for pid in pids:
            run_cmd(["taskkill", "/F", "/T", "/PID", str(pid)], timeout=30)
            if self._pid_alive(pid):
                run_ps(f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue", timeout=30)
            (failed if self._pid_alive(pid) else killed).append(pid)
        if failed:
            return False, f"已终止 {len(killed)} 个，失败 {len(failed)} 个（可能受保护）：{failed}"
        return True, f"已终止 {len(killed)} 个进程：{killed}"

    @staticmethod
    def _pid_alive(pid) -> bool:
        try:
            import ctypes

            h = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
            if not h:
                return False
            code = ctypes.c_ulong()
            ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
            ctypes.windll.kernel32.CloseHandle(h)
            return code.value == 259  # STILL_ACTIVE
        except Exception:
            return False

    def do_quarantine_path(self, p: dict) -> tuple[bool, str]:
        path = expand(p.get("path") or "")
        if not path:
            return False, "缺少路径"
        if not os.path.exists(path):
            return True, "已不存在"
        ok, msg = quarantine(path, p.get("reason", "可疑文件"), self.logger)
        self._backup("quarantine", {"path": path, "result": msg})
        return ok, msg

    def do_delete_task(self, p: dict) -> tuple[bool, str]:
        name = p.get("name") or ""
        path = p.get("path") or "\\"
        full = f"{path}{name}"
        rc, out, err = run_ps(
            f"Unregister-ScheduledTask -TaskName '{name}' -TaskPath '{path}' -Confirm:$false "
            f"-ErrorAction SilentlyContinue; if (Get-ScheduledTask -TaskName '{name}' "
            f"-TaskPath '{path}' -ErrorAction SilentlyContinue) {{ 'exists' }} else {{ 'gone' }}",
            timeout=60, logger=self.logger)
        if "gone" in (out or "").lower():
            self._backup("delete_task", {"task": full})
            return True, "计划任务已删除"
        rc2, out2, err2 = run_cmd(["schtasks", "/Delete", "/TN", full, "/F"], timeout=30)
        gone = rc2 == 0
        if gone:
            self._backup("delete_task", {"task": full})
        return gone, "计划任务已删除" if gone else f"删除失败：{(err2 or out2).strip()[:150]}"

    def do_delete_run_value(self, p: dict) -> tuple[bool, str]:
        import winreg

        hive = winreg.HKEY_CURRENT_USER if p.get("hive") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        sub, name, value = p.get("sub"), p.get("name"), p.get("value")
        self._backup("delete_run_value", {"hive": p.get("hive"), "sub": sub,
                                          "name": name, "value": value})
        ok = reg_delete_value(hive, sub, name)
        return ok, "启动项已删除" if ok else "删除失败（权限不足）"

    def do_delete_reg_value(self, p: dict) -> tuple[bool, str]:
        import winreg

        hive = winreg.HKEY_CURRENT_USER if p.get("hive") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        sub, name = p.get("sub"), p.get("name")
        old = reg_list_values(hive, sub).get(name)
        self._backup("delete_reg_value", {"hive": p.get("hive"), "sub": sub, "name": name, "value": old})
        ok = reg_delete_value(hive, sub, name)
        return ok, "注册表值已删除" if ok else "删除失败（权限不足）"

    def do_disable_service(self, p: dict) -> tuple[bool, str]:
        name = p.get("name") or ""
        if not name:
            return False, "缺少服务名"
        self._backup("disable_service", {"name": name, "image": p.get("image")})
        run_cmd(["sc", "stop", name], timeout=60)
        rc, out, err = run_cmd(["sc", "config", name, "start=", "disabled"], timeout=30)
        return rc == 0, "服务已停止并禁用" if rc == 0 else f"配置失败：{(err or out).strip()[:150]}"

    def do_remove_wmi(self, p: dict) -> tuple[bool, str]:
        name = (p.get("name") or "").replace("'", "''")
        script = f"""
$n='{name}'
Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
  Where-Object {{ $_.Filter -match $n -or $_.Consumer -match $n }} | Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
  Where-Object {{ $_.Name -eq $n }} | Remove-CimInstance -ErrorAction SilentlyContinue
Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
  Where-Object {{ $_.Name -eq $n }} | Remove-CimInstance -ErrorAction SilentlyContinue
'done'
"""
        rc, out, err = run_ps(script, timeout=90, logger=self.logger)
        self._backup("remove_wmi", {"name": name})
        return "done" in (out or "").lower(), "WMI 订阅已移除" if "done" in (out or "").lower() else (err or out)[:150]

    def do_restore_winlogon(self, p: dict) -> tuple[bool, str]:
        import winreg

        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        name = p.get("name")
        default = "C:\\Windows\\system32\\userinit.exe," if name == "Userinit" else "explorer.exe"
        self._backup("restore_winlogon", {"name": name, "value": p.get("value")})
        ok = reg_write(winreg.HKEY_LOCAL_MACHINE, key, name, default, winreg.REG_SZ)
        return ok, f"已恢复为默认值 {default}" if ok else "写入失败（权限不足）"

    def do_clean_appinit(self, p: dict) -> tuple[bool, str]:
        import winreg

        key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        self._backup("clean_appinit", {"AppInit_DLLs": reg_list_values(
            winreg.HKEY_LOCAL_MACHINE, key).get("AppInit_DLLs")})
        reg_write(winreg.HKEY_LOCAL_MACHINE, key, "AppInit_DLLs", "", winreg.REG_SZ)
        reg_write(winreg.HKEY_LOCAL_MACHINE, key, "LoadAppInit_DLLs", 0, winreg.REG_DWORD)
        return True, "AppInit_DLLs 已清空并关闭加载"

    def do_clean_exclusions(self, p: dict) -> tuple[bool, str]:
        paths = [x for x in (p.get("paths") or []) if str(x).strip()]
        procs = [x for x in (p.get("procs") or []) if str(x).strip()]
        exts = [x for x in (p.get("exts") or []) if str(x).strip()]

        def esc(items):
            return ",".join("'" + str(i).replace("'", "''") + "'" for i in items)

        cmds = []
        if paths:
            cmds.append(f"foreach($x in @({esc(paths)})){{ Remove-MpPreference -ExclusionPath $x -ErrorAction SilentlyContinue }}")
        if procs:
            cmds.append(f"foreach($x in @({esc(procs)})){{ Remove-MpPreference -ExclusionProcess $x -ErrorAction SilentlyContinue }}")
        if exts:
            cmds.append(f"foreach($x in @({esc(exts)})){{ Remove-MpPreference -ExclusionExtension $x -ErrorAction SilentlyContinue }}")
        script = ";".join(cmds) + "; 'ok'"
        rc, out, err = run_ps(script, timeout=120, logger=self.logger)
        self._backup("clean_exclusions", {"paths": paths, "procs": procs, "exts": exts})
        return "ok" in (out or "").lower(), "排除项已清理" if "ok" in (out or "").lower() else (err or out)[:150]

    def do_clean_defender_policy(self, p: dict) -> tuple[bool, str]:
        import winreg

        removed = []
        # 删除排除策略树
        reg_delete_tree(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions")
        removed.append("Exclusions 策略树")
        # 删除关闭防护的值
        for key, name in (
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiVirus"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableBehaviorMonitoring"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableOnAccessProtection"),
            (r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableScanOnRealtimeEnable"),
        ):
            old = reg_list_values(winreg.HKEY_LOCAL_MACHINE, key).get(name)
            if old is not None:
                reg_delete_value(winreg.HKEY_LOCAL_MACHINE, key, name)
                removed.append(f"{key}\\{name}")
                self._backup("delete_policy", {"key": key, "name": name, "value": old})
        # 重新开启实时保护
        run_ps("Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue", timeout=60)
        return True, "已清除：" + "、".join(removed)

    def do_repair_defender(self, p: dict) -> tuple[bool, str]:
        results = repair_defender(self.logger)
        ok = all(r[1] for r in results) if results else False
        msg = "；".join(f"{n}:{'成功' if o else '失败'}" for n, o, _ in results)
        return ok or any(r[1] for r in results), msg[:400]

    def do_update_signature(self, p: dict) -> tuple[bool, str]:
        from .envguard import _mpcmdrun

        exe = _mpcmdrun()
        if not exe:
            return False, "未找到 MpCmdRun.exe"
        rc, out, err = run_cmd([exe, "-SignatureUpdate"], timeout=300)
        return rc == 0, (out or err).strip()[:200] or f"退出码 {rc}"

    def do_restore_uac(self, p: dict) -> tuple[bool, str]:
        import winreg

        changed = []
        for name, value in ioc.UAC_DEFAULTS.items():
            cur = reg_list_values(winreg.HKEY_LOCAL_MACHINE, ioc.UAC_KEY).get(name)
            if cur != value:
                if reg_write(winreg.HKEY_LOCAL_MACHINE, ioc.UAC_KEY, name, value, winreg.REG_DWORD):
                    changed.append(f"{name}={value}")
                    self._backup("restore_uac", {"name": name, "old": cur, "new": value})
        if changed:
            return True, "已恢复：" + ", ".join(changed) + "（部分设置需重启生效）"
        return True, "UAC 已是安全默认值"

    def do_clean_hosts(self, p: dict) -> tuple[bool, str]:
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            r"System32\drivers\etc\hosts")
        bad = [str(x).strip() for x in (p.get("lines") or []) if str(x).strip()]
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception as exc:
            return False, f"读取失败：{exc}"
        # 备份
        backup = os.path.join(self.backup_path, f"hosts-{time.strftime('%Y%m%d-%H%M%S')}.bak")
        try:
            with open(backup, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception:
            pass
        kept = []
        removed = 0
        for line in content.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and any(s == b or s.startswith(b.split()[0] + " ") for b in bad):
                removed += 1
                continue
            kept.append(line)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(kept) + "\n")
        except Exception as exc:
            return False, f"写入失败（需管理员）：{exc}"
        run_cmd(["ipconfig", "/flushdns"], timeout=30)
        return True, f"已移除 {removed} 条恶意 hosts 记录（备份：{os.path.basename(backup)}）"

    def do_reset_proxy(self, p: dict) -> tuple[bool, str]:
        import winreg

        key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        old = reg_list_values(winreg.HKEY_CURRENT_USER, key)
        self._backup("reset_proxy", {"ProxyEnable": old.get("ProxyEnable"),
                                     "ProxyServer": old.get("ProxyServer"),
                                     "AutoConfigURL": old.get("AutoConfigURL")})
        reg_write(winreg.HKEY_CURRENT_USER, key, "ProxyEnable", 0, winreg.REG_DWORD)
        reg_delete_value(winreg.HKEY_CURRENT_USER, key, "ProxyServer")
        reg_delete_value(winreg.HKEY_CURRENT_USER, key, "AutoConfigURL")
        run_cmd(["netsh", "winhttp", "reset", "proxy"], timeout=30)
        return True, "已恢复直连并刷新 WinHTTP 代理"

    def do_delete_firewall_rule(self, p: dict) -> tuple[bool, str]:
        import winreg

        key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        name = p.get("name")
        old = reg_list_values(winreg.HKEY_LOCAL_MACHINE, key).get(name)
        self._backup("delete_firewall_rule", {"name": name, "value": old})
        ok = reg_delete_value(winreg.HKEY_LOCAL_MACHINE, key, name)
        return ok, "防火墙规则已删除" if ok else "删除失败（权限不足）"

    def do_env_repair(self, p: dict) -> tuple[bool, str]:
        results = provision(self.logger)
        ok = any(r[1] for r in results)
        return ok, "；".join(f"{n}:{'OK' if o else '跳过'}" for n, o, _ in results)[:300]
