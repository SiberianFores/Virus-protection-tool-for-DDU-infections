"""安全检查引擎：进程 / 文件 / 持久化 / 防御削弱 / 网络 / 残留 / 环境."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime

from . import ioc
from .util import (
    Logger,
    data_root,
    expand,
    human_size,
    is_admin,
    now_iso,
    ps_json,
    reg_list_subkeys,
    reg_list_values,
    reg_read,
    run_cmd,
    run_ps,
    sha256_file,
)

SEVERITY_WEIGHT = {"critical": 30, "high": 18, "medium": 10, "low": 4, "info": 0}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    detail: str
    evidence: str = ""
    fixable: bool = False
    action: str = ""
    params: dict = field(default_factory=dict)
    status: str = "待处理"
    fix_result: str = ""


@dataclass
class EnvCheck:
    key: str
    name: str
    status: str  # ok / warn / fail
    detail: str
    fix_label: str = ""
    fix_action: str = ""


@dataclass
class ScanResult:
    started: float = 0.0
    finished: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    env_checks: list[EnvCheck] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)

    @property
    def score(self) -> int:
        penalty = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings if f.status != "已处理")
        return max(0, 100 - penalty)

    @property
    def level(self) -> str:
        s = self.score
        if s >= 95:
            return "安全"
        if s >= 80:
            return "注意"
        if s >= 55:
            return "危险"
        return "严重"

    @property
    def fixable(self) -> list[Finding]:
        return [f for f in self.findings if f.fixable and f.status != "已处理"]

    def by_severity(self, sev: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]


# --------------------------------------------------------------------------- 采集

class Snapshot:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.processes: list[dict] = []
        self.tasks: list[dict] = []
        self.services: list[dict] = []
        self.defender: dict = {}
        self.mppref: dict = {}
        self.threats: list[dict] = []
        self.netstat: list[dict] = []
        self.hosts: list[str] = []
        self.wmi: list[dict] = []
        self.startup: list[dict] = []
        self.proxy: dict = {}
        self.firewall: list[str] = []
        self.av_products: list[dict] = []
        self.admin = is_admin()

    # ---- 进程
    def load_processes(self) -> None:
        data = ps_json(
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | "
            "ConvertTo-Json -Depth 3"
        )
        if isinstance(data, dict):
            data = [data]
        if data:
            self.processes = [p for p in data if isinstance(p, dict)]
            return
        # 回退：ctypes 枚举（没有命令行）
        try:
            import ctypes
            from ctypes import wintypes

            TH32CS_SNAPPROCESS = 0x00000002
            PROCESS_QUERY_LIMITED = 0x1000

            class PE32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260),
                ]

            k32 = ctypes.windll.kernel32
            snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            entry = PE32()
            entry.dwSize = ctypes.sizeof(PE32)
            procs = []
            if k32.Process32First(snap, ctypes.byref(entry)):
                while True:
                    name = entry.szExeFile.decode("mbcs", "replace")
                    pid = int(entry.th32ProcessID)
                    path = ""
                    h = k32.OpenProcess(PROCESS_QUERY_LIMITED, False, pid)
                    if h:
                        buf = ctypes.create_unicode_buffer(1024)
                        size = wintypes.DWORD(1024)
                        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                            path = buf.value
                        k32.CloseHandle(h)
                    procs.append({"ProcessId": pid, "ParentProcessId": int(entry.th32ParentProcessID),
                                  "Name": name, "ExecutablePath": path, "CommandLine": ""})
                    if not k32.Process32Next(snap, ctypes.byref(entry)):
                        break
            k32.CloseHandle(snap)
            self.processes = procs
            self.logger.warn(f"PowerShell 取进程失败，使用回退枚举：{len(procs)} 个进程")
        except Exception as exc:
            self.logger.error(f"枚举进程失败：{exc}")

    # ---- 计划任务
    def load_tasks(self) -> None:
        script = r"""
$out = @()
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
foreach ($t in $tasks) {
  $o = [ordered]@{
    name   = [string]$t.TaskName
    path   = [string]$t.TaskPath
    state  = [string]$t.State
    author = [string]$t.Author
  }
  $needXml = ($t.TaskPath -notlike '\Microsoft\Windows\*') -or
             ($t.TaskName -match 'update|cache|svc|runtime|security|window|guard|host')
  if ($needXml) {
    try { $o['xml'] = [string](Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath) } catch { $o['xml'] = '' }
  }
  $out += [pscustomobject]$o
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 4
"""
        data = ps_json(script, timeout=180, logger=self.logger)
        if isinstance(data, dict):
            data = [data]
        self.tasks = [t for t in (data or []) if isinstance(t, dict)]

    # ---- 服务
    def load_services(self) -> None:
        try:
            import winreg

            base = r"SYSTEM\CurrentControlSet\Services"
            for name in reg_list_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
                key = base + "\\" + name
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key, 0, winreg.KEY_READ) as k:
                        image, _ = winreg.QueryValueEx(k, "ImagePath")
                except Exception:
                    continue
                start = reg_read(winreg.HKEY_LOCAL_MACHINE, key, "Start", None)
                self.services.append({"name": name, "image": str(image), "start": start})
        except Exception as exc:
            self.logger.warn(f"读取服务失败：{exc}")

    # ---- Defender
    def load_defender(self) -> None:
        script = r"""
$o = @{}
try {
  $s = Get-MpComputerStatus -ErrorAction Stop
  $o['status'] = @{
    AMServiceEnabled = [bool]$s.AMServiceEnabled
    AntivirusEnabled = [bool]$s.AntivirusEnabled
    RealTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled
    OnAccessProtectionEnabled = [bool]$s.OnAccessProtectionEnabled
    IsTamperProtected = [bool]$s.IsTamperProtected
    AntivirusSignatureVersion = [string]$s.AntivirusSignatureVersion
    AntivirusSignatureAge = [int]$s.AntivirusSignatureAge
    AntivirusSignatureLastUpdated = [string]$s.AntivirusSignatureLastUpdated
    AntispywareEnabled = [bool]$s.AntispywareEnabled
    BehaviorMonitorEnabled = [bool]$s.BehaviorMonitorEnabled
    IoavProtectionEnabled = [bool]$s.IoavProtectionEnabled
    NISEnabled = [bool]$s.NISEnabled
  }
} catch { $o['statusError'] = [string]$_.Exception.Message }
try {
  $p = Get-MpPreference -ErrorAction Stop
  $o['pref'] = @{
    ExclusionPath = @($p.ExclusionPath | ForEach-Object { [string]$_ })
    ExclusionProcess = @($p.ExclusionProcess | ForEach-Object { [string]$_ })
    ExclusionExtension = @($p.ExclusionExtension | ForEach-Object { [string]$_ })
    DisableRealtimeMonitoring = $p.DisableRealtimeMonitoring
    DisableBehaviorMonitoring = $p.DisableBehaviorMonitoring
    DisableIOAVProtection = $p.DisableIOAVProtection
    DisableScriptScanning = $p.DisableScriptScanning
    MAPSReporting = $p.MAPSReporting
    SubmitSamplesConsent = $p.SubmitSamplesConsent
    PUAProtection = $p.PUAProtection
  }
} catch { $o['prefError'] = [string]$_.Exception.Message }
$o | ConvertTo-Json -Depth 5 -Compress
"""
        data = ps_json(script, timeout=120, logger=self.logger)
        if isinstance(data, dict):
            self.defender = data.get("status") or {}
            self.mppref = data.get("pref") or {}
            if data.get("statusError"):
                self.defender["_error"] = data["statusError"]
            if data.get("prefError"):
                self.mppref["_error"] = data["prefError"]

    # ---- 已安装安全软件（用于区分「Defender 被木马关闭」和「用户装了第三方杀软」）
    def load_av_products(self) -> None:
        script = r"""
try {
  $out = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
    Select-Object displayName, productState, pathToSignedProductExe)
  ConvertTo-Json -InputObject $out -Compress -Depth 3
} catch { '[]' }
"""
        data = ps_json(script, timeout=45, logger=self.logger)
        if isinstance(data, dict):
            data = [data]
        self.av_products = [a for a in (data or []) if isinstance(a, dict)]

    # ---- Defender 历史检测
    def load_threats(self) -> None:
        script = r"""
try {
  $out = @(Get-MpThreatDetection -ErrorAction Stop |
    Select-Object InitialDetectionTime, ThreatName, ActionSuccess, Resources)
  ConvertTo-Json -InputObject $out -Compress -Depth 4
} catch { '[]' }
"""
        data = ps_json(script, timeout=90, logger=self.logger)
        if isinstance(data, dict):
            data = [data]
        self.threats = [t for t in (data or []) if isinstance(t, dict)]

    # ---- 网络
    def load_netstat(self) -> None:
        rc, out, _ = run_cmd(["netstat", "-ano", "-p", "TCP"])
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0].upper() == "TCP":
                local, remote, state, pid = parts[1], parts[2], parts[3], parts[4]
                if not pid.isdigit():
                    continue
                self.netstat.append({
                    "local": local, "remote": remote, "state": state, "pid": int(pid),
                    "lport": _port(local), "rport": _port(remote),
                })

    # ---- hosts / 代理 / 防火墙
    def load_hosts(self) -> None:
        path = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            r"System32\drivers\etc\hosts")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                self.hosts = f.readlines()
        except Exception:
            self.hosts = []

    def load_proxy(self) -> None:
        import winreg

        key = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        self.proxy = {
            "Enable": reg_read(winreg.HKEY_CURRENT_USER, key, "ProxyEnable", 0),
            "Server": reg_read(winreg.HKEY_CURRENT_USER, key, "ProxyServer", ""),
            "AutoConfigURL": reg_read(winreg.HKEY_CURRENT_USER, key, "AutoConfigURL", ""),
        }

    def load_firewall(self) -> None:
        import winreg

        key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"
        values = reg_list_values(winreg.HKEY_LOCAL_MACHINE, key)
        self.firewall = [f"{k}={v}" for k, v in values.items()]

    # ---- 启动目录快捷方式
    def load_startup(self) -> None:
        script = r"""
$dirs = @(
  [Environment]::GetFolderPath('Startup'),
  [Environment]::GetFolderPath('CommonStartup')
)
$sh = New-Object -ComObject WScript.Shell
$out = @()
foreach ($d in $dirs) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  Get-ChildItem -LiteralPath $d -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
    $t = ''
    try { $t = $sh.CreateShortcut($_.FullName).TargetPath } catch {}
    $out += [pscustomobject]@{ file = $_.FullName; target = $t }
  }
}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"""
        data = ps_json(script, timeout=60, logger=self.logger)
        if isinstance(data, dict):
            data = [data]
        self.startup = [s for s in (data or []) if isinstance(s, dict)]

    # ---- WMI 永久事件订阅
    def load_wmi(self) -> None:
        if not self.admin:
            return
        script = r"""
$out = @()
try {
  Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction Stop |
    Select-Object Name, CommandLineTemplate, ScriptText, ExecutablePath |
    ForEach-Object { $out += [pscustomobject]@{ name = [string]$_.Name; cmd = [string]$_.CommandLineTemplate; script = [string]$_.ScriptText; exe = [string]$_.ExecutablePath } }
} catch {}
ConvertTo-Json -InputObject @($out) -Compress -Depth 3
"""
        data = ps_json(script, timeout=60, logger=self.logger)
        if isinstance(data, dict):
            data = [data]
        self.wmi = [w for w in (data or []) if isinstance(w, dict)]

    def load_all(self) -> None:
        steps = [
            ("进程", self.load_processes),
            ("计划任务", self.load_tasks),
            ("服务", self.load_services),
            ("Defender", self.load_defender),
            ("安全软件", self.load_av_products),
            ("威胁历史", self.load_threats),
            ("网络", self.load_netstat),
            ("hosts", self.load_hosts),
            ("代理", self.load_proxy),
            ("防火墙", self.load_firewall),
            ("启动目录", self.load_startup),
            ("WMI 订阅", self.load_wmi),
        ]
        for label, fn in steps:
            t0 = time.time()
            try:
                fn()
            except Exception as exc:
                self.logger.warn(f"采集{label}失败：{exc}")
            self.logger.info(f"采集{label}完成（{time.time() - t0:.1f}s）")


def _port(addr: str) -> int:
    try:
        return int(addr.rsplit(":", 1)[1])
    except Exception:
        return 0


# --------------------------------------------------------------------------- 检查

class Scanner:
    def __init__(self, logger: Logger):
        self.logger = logger
        self.result = ScanResult()
        self.snap = Snapshot(logger)
        self.hash_budget = 900 * 1024 * 1024
        self.file_budget = 900
        self.files_seen = 0
        self.files_hashed = 0
        self.hash_cache: dict[str, str] = {}
        self.candidate_files: list[str] = []

    # ---- 主流程
    def run(self, quick: bool = False) -> ScanResult:
        self.result.started = time.time()
        self.logger.info("=" * 60)
        self.logger.info(f"开始安全检查（{'快速' if quick else '标准'}模式）")
        self.snap.load_all()
        checks = [
            ("进程", self.check_processes),
            ("持久化", self.check_persistence),
            ("防御削弱", self.check_defense),
            ("网络", self.check_network),
            ("文件", self.check_files),
            ("残留", self.check_residue),
            ("环境", self.check_environment),
        ]
        for label, fn in checks:
            t0 = time.time()
            try:
                fn()
            except Exception as exc:
                self.logger.error(f"{label}检查异常：{exc}")
            self.logger.info(f"完成 {label} 检查（{time.time() - t0:.1f}s）")

        self._dedupe_covered_paths()
        self.result.findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.title))
        self.result.finished = time.time()
        self.result.stats = {
            "进程数": len(self.snap.processes),
            "计划任务数": len(self.snap.tasks),
            "服务数": len(self.snap.services),
            "扫描文件数": self.files_seen,
            "计算哈希文件数": self.files_hashed,
            "耗时秒": round(self.result.finished - self.result.started, 1),
            "管理员": self.snap.admin,
        }
        self.result.summary = {
            "score": self.result.score,
            "level": self.result.level,
            "critical": len(self.result.by_severity("critical")),
            "high": len(self.result.by_severity("high")),
            "medium": len(self.result.by_severity("medium")),
            "low": len(self.result.by_severity("low")),
            "info": len(self.result.by_severity("info")),
        }
        self.logger.ok(
            f"检查完成：评分 {self.result.score}（{self.result.level}），"
            f"严重 {self.result.summary['critical']} / 高危 {self.result.summary['high']} / "
            f"中危 {self.result.summary['medium']}，耗时 {self.result.stats['耗时秒']}s"
        )
        return self.result

    def _dedupe_covered_paths(self) -> None:
        """若某个目录整体会被隔离，其内部文件的独立条目就是冗余的。"""
        roots = []
        for f in self.result.findings:
            if f.action != "quarantine_path":
                continue
            p = str(f.params.get("path") or "")
            if p and os.path.isdir(p):
                roots.append(p.lower().rstrip("\\"))
        if not roots:
            return
        kept = []
        for f in self.result.findings:
            covered = False
            if f.action == "quarantine_path":
                p = str(f.params.get("path") or "").lower().rstrip("\\")
                for r in roots:
                    if p != r and p.startswith(r + "\\"):
                        covered = True
                        break
            if not covered:
                kept.append(f)
        self.result.findings = kept

    def add(self, **kwargs) -> Finding:
        f = Finding(**kwargs)
        # 保证 id 唯一（界面以 id 作为 Treeview 节点）
        base_id = f.id
        i = 2
        existing = {x.id for x in self.result.findings}
        while f.id in existing:
            f.id = f"{base_id}#{i}"
            i += 1
        # 同一路径已被父目录级修复覆盖时，跳过重复项
        if f.action == "quarantine_path":
            path = str(f.params.get("path") or "").lower().rstrip("\\")
            for other in self.result.findings:
                if other.action == "quarantine_path":
                    parent = str(other.params.get("path") or "").lower().rstrip("\\")
                    if parent and parent != path and path.startswith(parent + "\\"):
                        return f
        self.result.findings.append(f)
        self.logger.info(f"[{SEVERITY_LABEL.get(f.severity, f.severity)}] {f.title}")
        return f

    # ---- 进程
    def check_processes(self) -> None:
        procs = self.snap.processes
        bad_pids = set()
        for p in procs:
            name = (p.get("Name") or "").lower()
            path = (p.get("ExecutablePath") or "")
            cmd = (p.get("CommandLine") or "")
            lpath = path.lower()
            pid = p.get("ProcessId")

            if name in ioc.BAD_PROCESS_NAMES:
                bad_pids.add(pid)
                self.add(
                    id=f"proc-name-{pid}", severity="critical", category="进程",
                    title=f"发现已知恶意进程 {p.get('Name')} (PID {pid})",
                    detail="该进程名属于本次「假 DDU」木马家族（本地代理或改名矿工内核）。",
                    evidence=f"PID {pid}\n路径: {path or '(未知)'}\n命令行: {_mask_cmd(cmd)}",
                    fixable=True, action="kill_process",
                    params={"pid": pid, "name": p.get("Name"), "path": path},
                )
                continue

            for marker in ioc.CMD_MARKERS:
                if marker.lower() in cmd.lower():
                    bad_pids.add(pid)
                    self.add(
                        id=f"proc-cmd-{pid}", severity="critical", category="进程",
                        title=f"进程命令行含挖矿特征 (PID {pid})",
                        detail=f"命中特征：{marker}",
                        evidence=f"{p.get('Name')} (PID {pid})\n路径: {path}\n命令行: {_mask_cmd(cmd)}",
                        fixable=True, action="kill_process",
                        params={"pid": pid, "name": p.get("Name"), "path": path},
                    )
                    break

            for pat in ioc.SUSPICIOUS_PATH_PATTERNS:
                if pat in lpath:
                    bad_pids.add(pid)
                    self.add(
                        id=f"proc-path-{pid}", severity="high", category="进程",
                        title=f"进程从系统伪装目录运行 (PID {pid})",
                        detail=f"可执行文件位于可疑路径（{pat}），正常系统组件不会从这些位置运行。",
                        evidence=f"{p.get('Name')} (PID {pid})\n路径: {path}",
                        fixable=True, action="kill_process",
                        params={"pid": pid, "name": p.get("Name"), "path": path},
                    )
                    break

            base = os.path.basename(lpath)
            if base in ioc.IMPERSONATED_NAMES and lpath and not _in_allowed_roots(lpath) \
                    and not lpath.startswith("\\device\\"):
                self.add(
                    id=f"proc-imp-{pid}", severity="high", category="进程",
                    title=f"系统组件名出现在非系统目录 (PID {pid})",
                    detail=f"进程名 {p.get('Name')} 伪装成「{ioc.IMPERSONATED_NAMES[base]}」，"
                           f"但不在 Windows/Program Files 目录下，这是挖矿木马常见的改名伪装手法。",
                    evidence=f"PID {pid}\n路径: {path}\n命令行: {_mask_cmd(cmd)}",
                    fixable=True, action="kill_process",
                    params={"pid": pid, "name": p.get("Name"), "path": path},
                )
                continue

        # 挖矿程序进程：按名字聚合，避免同一个矿工多进程刷屏
        miners: dict[str, list[dict]] = {}
        for p in procs:
            name = (p.get("Name") or "").lower()
            if name in ioc.MINER_PROCESS_NAMES:
                miners.setdefault(name, []).append(p)
        for name, items in miners.items():
            pids = [int(x.get("ProcessId")) for x in items]
            paths = {x.get("ExecutablePath") or "(未知)" for x in items}
            self.add(
                id=f"proc-miner-{name}", severity="low", category="进程",
                title=f"发现挖矿程序进程 {name}（{len(pids)} 个实例）",
                detail="这是已知的挖矿内核文件名。如果是你自己安装的挖矿软件，可忽略；"
                       "如果不是你装的，请结束进程并排查来源。为防止误杀你自己在用的矿工，"
                       "本项不参与「一键修复」，可在任务管理器中手动结束。",
                evidence="\n".join(f"PID {x.get('ProcessId')}: {x.get('ExecutablePath')}\n"
                                   f"  命令行: {_mask_cmd(x.get('CommandLine') or '')}" for x in items[:4]),
                fixable=False,
            )

        self.result.stats["可疑进程数"] = len(bad_pids)

    # ---- 持久化
    def check_persistence(self) -> None:
        self._check_tasks()
        self._check_run_keys()
        self._check_startup()
        self._check_services()
        self._check_wmi()
        self._check_registry_hijack()

    def _task_xml_hits(self, xml: str) -> list[str]:
        hits = []
        low = (xml or "").lower()
        for token in ("1c212048", "1a44a355", "ntsvcf753", "runtimebroker6a2d",
                      "wsc.ps1", "wsc.cmd", "pearlhash", "61160", "30e7a103"):
            if token in low:
                hits.append(token)
        return hits

    @staticmethod
    def _xml_command(xml: str) -> str:
        m = re.findall(r"<Command>(.*?)</Command>", xml or "", re.S | re.I)
        args = re.findall(r"<Arguments>(.*?)</Arguments>", xml or "", re.S | re.I)
        text = " ".join(m + args)
        return re.sub(r"\s+", " ", text).strip()

    @staticmethod
    def _xml_interval_minutes(xml: str) -> int | None:
        m = re.search(r"<Interval>(PT(\d+)M)</Interval>", xml or "", re.I)
        if m:
            return int(m.group(2))
        m = re.search(r"<Interval>(PT(\d+)H)</Interval>", xml or "", re.I)
        if m:
            return int(m.group(2)) * 60
        return None

    def _check_tasks(self) -> None:
        for t in self.snap.tasks:
            name = t.get("name") or ""
            path = t.get("path") or ""
            state = t.get("state") or ""
            xml = t.get("xml") or ""
            full = f"{path}{name}"

            if name.lower() in ioc.BAD_TASK_NAMES:
                self.add(
                    id=f"task-{name}", severity="critical", category="持久化",
                    title=f"发现恶意计划任务「{full}」",
                    detail="该任务冒充 Windows 更新组件，按 PT5M 周期反复拉起木马载荷。",
                    evidence=f"任务: {full}\n状态: {state}\n动作: {self._xml_command(xml)[:500]}",
                    fixable=True, action="delete_task",
                    params={"name": name, "path": path},
                )
                continue

            hits = self._task_xml_hits(xml)
            if hits:
                self.add(
                    id=f"task-ioc-{name}", severity="critical", category="持久化",
                    title=f"计划任务包含木马特征「{full}」",
                    detail=f"任务动作/参数命中 IoC：{', '.join(hits)}",
                    evidence=f"任务: {full}\n状态: {state}\n动作: {self._xml_command(xml)[:500]}",
                    fixable=True, action="delete_task",
                    params={"name": name, "path": path},
                )
                continue

            cmd = self._xml_command(xml)
            if cmd:
                lcmd = cmd.lower()
                suspicious_cmd = any(p in lcmd for p in ioc.SUSPICIOUS_PATH_PATTERNS)
                interval = self._xml_interval_minutes(xml)
                if suspicious_cmd and interval is not None and interval <= ioc.SHORT_INTERVAL_MINUTES:
                    self.add(
                        id=f"task-short-{name}", severity="high", category="持久化",
                        title=f"高频自启任务从可疑目录运行「{full}」",
                        detail=f"每 {interval} 分钟重复执行，且目标位于 AppData/Temp 等用户可写目录，"
                               f"是挖矿木马典型驻留方式。请确认是否为已知软件。",
                        evidence=f"任务: {full}\n间隔: {interval} 分钟\n动作: {cmd[:500]}",
                        fixable=True, action="delete_task",
                        params={"name": name, "path": path},
                    )

    def _check_run_keys(self) -> None:
        import winreg

        roots = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        for sub, hive in ioc.RUN_KEYS:
            values = reg_list_values(roots[hive], sub)
            for name, value in values.items():
                if not isinstance(value, str):
                    continue
                low = value.lower()
                reasons = []
                if name.lower() in ioc.BAD_RUN_VALUES:
                    reasons.append("已知恶意启动项名称")
                if any(p in low for p in ioc.SUSPICIOUS_PATH_PATTERNS):
                    reasons.append("启动目标位于伪装目录")
                if any(d in low for d in ioc.BAD_DOMAINS):
                    reasons.append("启动命令含恶意域名")
                if re.search(r"-e(nc(odedcommand)?)?\s+[A-Za-z0-9+/=]{40,}", low) or "frombase64string" in low:
                    reasons.append("隐藏的编码 PowerShell 命令")
                if "wscript" in low and ("caches" in low or "temp" in low):
                    reasons.append("脚本宿主从临时目录启动")
                if not reasons:
                    continue
                exe = _first_exe(value)
                exists = bool(exe and os.path.exists(exe))
                if exe and not exists:
                    reasons.append("启动目标文件不存在（已被清理的残留项）")
                self.add(
                    id=f"run-{hive}-{name}", severity="critical" if name.lower() in ioc.BAD_RUN_VALUES else "high",
                    category="持久化",
                    title=f"可疑开机启动项 {name}（{hive}）",
                    detail="；".join(reasons),
                    evidence=f"{hive}\\{sub}\n{name} = {value[:800]}",
                    fixable=True, action="delete_run_value",
                    params={"hive": hive, "sub": sub, "name": name, "value": value},
                )

    def _check_startup(self) -> None:
        for s in self.snap.startup:
            target = (s.get("target") or "")
            low = target.lower()
            if not target:
                continue
            if any(p in low for p in ioc.SUSPICIOUS_PATH_PATTERNS) or \
                    os.path.basename(low) in ioc.BAD_PROCESS_NAMES:
                self.add(
                    id=f"startup-{os.path.basename(s.get('file', ''))}", severity="high", category="持久化",
                    title=f"启动目录快捷方式指向可疑目录",
                    detail="快捷方式在登录时拉起位于伪装目录的程序。",
                    evidence=f"快捷方式: {s.get('file')}\n目标: {target}",
                    fixable=True, action="quarantine_path",
                    params={"path": s.get("file"), "reason": "可疑启动快捷方式"},
                )

    def _check_services(self) -> None:
        for svc in self.snap.services:
            image = (svc.get("image") or "")
            low = image.lower()
            hit = any(p in low for p in ioc.SUSPICIOUS_PATH_PATTERNS)
            if not hit and not re.search(r"programdata\\[0-9a-f]{8}\\", low):
                continue
            self.add(
                id=f"svc-{svc.get('name')}", severity="critical", category="持久化",
                title=f"可疑系统服务 {svc.get('name')}",
                detail="服务镜像位于用户可写/伪装目录，常被用于开机自启恶意代码。",
                evidence=f"服务: {svc.get('name')}\nImagePath: {image}\nStart: {svc.get('start')}",
                fixable=True, action="disable_service",
                params={"name": svc.get("name"), "image": image},
            )

    def _check_wmi(self) -> None:
        for w in self.snap.wmi:
            blob = (w.get("cmd") or "") + (w.get("script") or "") + (w.get("exe") or "")
            low = blob.lower()
            if not blob:
                continue
            if any(t in low for t in ("1c212048", "ntsvcf753", "runtimebroker6a2d", "caches\\", "pearlhash")):
                self.add(
                    id=f"wmi-{w.get('name')}", severity="critical", category="持久化",
                    title=f"发现可疑 WMI 永久事件订阅 {w.get('name')}",
                    detail="WMI 订阅可在无文件、无计划任务的情况下长期驻留。",
                    evidence=blob[:800],
                    fixable=True, action="remove_wmi",
                    params={"name": w.get("name")},
                )

    def _check_registry_hijack(self) -> None:
        import winreg

        # IFEO Debugger
        base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        for sub in reg_list_subkeys(winreg.HKEY_LOCAL_MACHINE, base):
            key = base + "\\" + sub
            dbg = reg_read(winreg.HKEY_LOCAL_MACHINE, key, "Debugger", "")
            if dbg and any(p in str(dbg).lower() for p in ioc.SUSPICIOUS_PATH_PATTERNS):
                self.add(
                    id=f"ifeo-{sub}", severity="critical", category="持久化",
                    title=f"映像劫持：{sub} 的调试器被替换",
                    detail="IFEO Debugger 指向可疑目录，可用于劫持任意程序启动。",
                    evidence=f"{key}\nDebugger = {dbg}",
                    fixable=True, action="delete_reg_value",
                    params={"hive": "HKLM", "sub": key, "name": "Debugger"},
                )

        # Winlogon
        wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        userinit = reg_read(winreg.HKEY_LOCAL_MACHINE, wl, "Userinit", "")
        shell = reg_read(winreg.HKEY_LOCAL_MACHINE, wl, "Shell", "")
        for label, value in (("Userinit", userinit), ("Shell", shell)):
            if value and any(p in str(value).lower() for p in ioc.SUSPICIOUS_PATH_PATTERNS):
                self.add(
                    id=f"winlogon-{label}", severity="critical", category="持久化",
                    title=f"Winlogon {label} 被篡改",
                    detail="登录外壳被替换为可疑程序，可绕过所有常规自启项检查。",
                    evidence=f"HKLM\\{wl}\\{label} = {value}",
                    fixable=True, action="restore_winlogon",
                    params={"name": label, "value": str(value)},
                )

        # AppInit_DLLs
        appinit_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
        appinit = reg_read(winreg.HKEY_LOCAL_MACHINE, appinit_key, "AppInit_DLLs", "")
        load_appinit = reg_read(winreg.HKEY_LOCAL_MACHINE, appinit_key, "LoadAppInit_DLLs", 0)
        if appinit and load_appinit:
            self.add(
                id="appinit", severity="high", category="持久化",
                title="AppInit_DLLs 已启用并注入 DLL",
                detail="该机制会把指定 DLL 注入所有加载 user32.dll 的进程，现代系统上极少使用。",
                evidence=f"AppInit_DLLs = {appinit}\nLoadAppInit_DLLs = {load_appinit}",
                fixable=True, action="clean_appinit",
                params={},
            )

    # ---- 防御削弱
    def _third_party_av(self) -> list[str]:
        names = []
        for a in getattr(self.snap, "av_products", []) or []:
            name = str(a.get("displayName") or "").strip()
            if name and "defender" not in name.lower():
                names.append(name)
        return names

    def check_defense(self) -> None:
        import winreg

        d = self.snap.defender or {}
        pref = self.snap.mppref or {}
        third_party = self._third_party_av()
        av_note = ("（本机已安装第三方安全软件：%s，Defender 停用属正常）" % "、".join(third_party)
                   if third_party else "")

        if d.get("_error"):
            self.add(
                id="defender-unavailable", severity="info" if third_party else "high", category="防御",
                title="无法读取 Defender 状态",
                detail=(f"已检测到第三方安全软件 {('、'.join(third_party))}，Defender 通常会让位给它们，"
                        f"属正常情况。" if third_party else
                        f"可能是 Defender 被篡改、服务被禁用或权限不足：{d['_error'][:300]}"),
                evidence=str(d.get("_error"))[:500],
                fixable=not third_party, action="repair_defender",
                params={},
            )
        else:
            if d.get("AntivirusEnabled") is False or d.get("AMServiceEnabled") is False:
                self.add(
                    id="defender-off", severity="info" if third_party else "critical", category="防御",
                    title="Microsoft Defender 反病毒服务未运行",
                    detail=("系统当前由第三方安全软件提供防护。" + av_note if third_party else
                            "实时防护失效，系统当前处于无保护状态。"),
                    evidence=json.dumps(d, ensure_ascii=False)[:600],
                    fixable=not third_party, action="repair_defender", params={},
                )
            elif d.get("RealTimeProtectionEnabled") is False:
                self.add(
                    id="defender-rtp-off", severity="info" if third_party else "high", category="防御",
                    title="Defender 实时保护已关闭",
                    detail=("第三方安全软件接管了实时防护。" if third_party else
                            "实时保护关闭后，新落地的恶意文件不会被拦截。"),
                    evidence=json.dumps(d, ensure_ascii=False)[:600],
                    fixable=not third_party, action="repair_defender", params={},
                )
            age = d.get("AntivirusSignatureAge")
            if isinstance(age, int) and age > 7 and not third_party:
                self.add(
                    id="defender-sig-old", severity="medium", category="防御",
                    title=f"Defender 病毒库已 {age} 天未更新",
                    detail=f"当前版本 {d.get('AntivirusSignatureVersion')}，建议立即更新。",
                    evidence=json.dumps(d, ensure_ascii=False)[:400],
                    fixable=True, action="update_signature", params={},
                )

        # 排除项：PowerShell 接口
        ex_paths = pref.get("ExclusionPath") or []
        ex_procs = pref.get("ExclusionProcess") or []
        ex_ext = pref.get("ExclusionExtension") or []
        dangerous_paths = [p for p in ex_paths if _dangerous_exclusion(p)]
        dangerous_procs = [p for p in ex_procs if os.path.basename(str(p)).lower() in ioc.BAD_PROCESS_NAMES
                           or str(p).lower() in ("peakminer.exe", "lolminer.exe", "srbminer-multi.exe")]
        if dangerous_paths or dangerous_procs:
            self.add(
                id="defender-exclusion", severity="critical", category="防御",
                title="Defender 存在高危排除项",
                detail="整盘/系统目录或矿工进程被加入排除列表，等于为木马开后门。",
                evidence=("排除路径: " + ", ".join(map(str, ex_paths))[:600] +
                          "\n排除进程: " + ", ".join(map(str, ex_procs))[:400]),
                fixable=True, action="clean_exclusions",
                params={"paths": ex_paths, "procs": ex_procs, "exts": ex_ext},
            )

        # 排除项：策略注册表（普通管理员删不掉的那种）
        pol_paths = reg_list_values(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths")
        pol_procs = reg_list_values(winreg.HKEY_LOCAL_MACHINE,
                                    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes")
        hide = reg_read(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
                        "HideExclusionsFromLocalAdmins", 0)
        no_merge = reg_read(winreg.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
                            "DisableLocalAdminMerge", 0)
        if pol_paths or pol_procs or hide or no_merge:
            self.add(
                id="defender-policy-exclusion", severity="critical", category="防御",
                title="Defender 策略注册表被写入排除项",
                detail="木马通过策略键注入排除项，并隐藏它们（HideExclusionsFromLocalAdmins），"
                       "普通管理员在界面中看不到、也删不掉。",
                evidence=(f"策略排除路径({len(pol_paths)}): " + ", ".join(list(pol_paths)[:10]) +
                          f"\n策略排除进程({len(pol_procs)}): " + ", ".join(list(pol_procs)[:10]) +
                          f"\nHideExclusionsFromLocalAdmins={hide} DisableLocalAdminMerge={no_merge}"),
                fixable=True, action="clean_defender_policy", params={},
            )

        # 关闭实时保护/反间谍的策略
        rtp_policy = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        disable_rtp = reg_read(winreg.HKEY_LOCAL_MACHINE, rtp_policy, "DisableRealtimeMonitoring", 0)
        disable_av = reg_read(winreg.HKEY_LOCAL_MACHINE,
                              r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 0)
        if disable_rtp or disable_av:
            self.add(
                id="defender-policy-disable", severity="critical", category="防御",
                title="Defender 被策略强制关闭",
                detail="策略键禁用实时保护/反间谍，优先级高于本地设置。",
                evidence=f"DisableRealtimeMonitoring={disable_rtp}\nDisableAntiSpyware={disable_av}",
                fixable=True, action="clean_defender_policy", params={},
            )

        # UAC
        uac = {k: reg_read(winreg.HKEY_LOCAL_MACHINE, ioc.UAC_KEY, k, None)
               for k in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop")}
        if uac["EnableLUA"] == 0 or uac["ConsentPromptBehaviorAdmin"] == 0:
            self.add(
                id="uac-weakened", severity="critical", category="防御",
                title="UAC 提权提示已被关闭",
                detail="ConsentPromptBehaviorAdmin=0 让任何程序静默提权，是木马常用的持久化手法。",
                evidence=json.dumps(uac, ensure_ascii=False),
                fixable=True, action="restore_uac", params={},
            )
        elif uac["PromptOnSecureDesktop"] == 0:
            self.add(
                id="uac-desktop", severity="medium", category="防御",
                title="UAC 安全桌面被关闭",
                detail="PromptOnSecureDesktop=0 会削弱提权提示的抗欺骗能力。",
                evidence=json.dumps(uac, ensure_ascii=False),
                fixable=True, action="restore_uac", params={},
            )

        # hosts
        bad_hosts = []
        for line in self.snap.hosts:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            low = s.lower()
            if any(dom in low for dom in ioc.BAD_DOMAINS) or \
                    re.search(r"\b69\.63\.176\.15\b", low) or \
                    ("workers.dev" in low and not low.startswith("127.0.0.1") and not low.startswith("0.0.0.0")):
                bad_hosts.append(s)
        if bad_hosts:
            self.add(
                id="hosts-tampered", severity="high", category="防御",
                title="hosts 文件存在可疑条目",
                detail="恶意域名被写入 hosts，可能导致安全站点无法访问或被重定向。",
                evidence="\n".join(bad_hosts)[:800],
                fixable=True, action="clean_hosts",
                params={"lines": bad_hosts},
            )

        # 系统代理指向失效本地端口
        proxy = self.snap.proxy or {}
        enable = proxy.get("Enable") or 0
        server = str(proxy.get("Server") or "")
        if enable and server:
            m = re.match(r"(?:https?=)?(127\.0\.0\.1|localhost):(\d+)", server)
            if m:
                port = int(m.group(2))
                if not any(n["state"].upper() == "LISTENING" and n["lport"] == port
                           for n in self.snap.netstat):
                    self.add(
                        id="proxy-dead", severity="low", category="防御",
                        title="系统代理指向已失效的本地端口",
                        detail="代理进程已退出但设置仍生效，会导致浏览器白屏、更新失败。",
                        evidence=f"ProxyEnable=1 ProxyServer={server}",
                        fixable=True, action="reset_proxy", params={"server": server},
                    )

        # 防火墙规则指向可疑路径
        for rule in self.snap.firewall:
            low = rule.lower()
            if any(p in low for p in ioc.SUSPICIOUS_PATH_PATTERNS):
                name = rule.split("=", 1)[0]
                self.add(
                    id=f"fw-{name}", severity="medium", category="防御",
                    title="防火墙规则引用了可疑目录程序",
                    detail="木马常为自己添加放行规则；清理后可消除后门通道。",
                    evidence=rule[:500],
                    fixable=True, action="delete_firewall_rule", params={"name": name},
                )

    # ---- 网络
    def check_network(self) -> None:
        procs = {p.get("ProcessId"): p for p in self.snap.processes}
        for n in self.snap.netstat:
            if n["state"].upper() == "LISTENING" and n["lport"] in ioc.BAD_PORTS:
                p = procs.get(n["pid"]) or {}
                self.add(
                    id=f"net-port-{n['lport']}", severity="critical", category="网络",
                    title=f"本机监听木马专用端口 {n['lport']}",
                    detail="61160 是本地 Stratum 代理端口，42842 是隐藏矿工 API 端口。",
                    evidence=f"{n['local']} <- PID {n['pid']} {p.get('Name', '')}\n{p.get('ExecutablePath', '')}",
                    fixable=True, action="kill_process",
                    params={"pid": n["pid"], "name": p.get("Name", ""), "path": p.get("ExecutablePath", "")},
                )
            elif n["state"].upper() == "ESTABLISHED" and n["rport"] in ioc.MINER_PORTS:
                p = procs.get(n["pid"]) or {}
                path = (p.get("ExecutablePath") or "").lower()
                if any(pat in path for pat in ioc.SUSPICIOUS_PATH_PATTERNS):
                    self.add(
                        id=f"net-pool-{n['rport']}-{n['pid']}", severity="high", category="网络",
                        title=f"可疑进程外连矿池端口 {n['rport']}",
                        detail="进程位于伪装目录，且连接到矿池常用端口。",
                        evidence=f"{n['remote']} <- PID {n['pid']} {p.get('Name', '')}\n{p.get('ExecutablePath', '')}",
                        fixable=True, action="kill_process",
                        params={"pid": n["pid"], "name": p.get("Name", ""), "path": p.get("ExecutablePath", "")},
                    )

    # ---- 文件
    def check_files(self) -> None:
        import glob

        roots: list[tuple[str, int]] = []
        for env in ("LOCALAPPDATA", "APPDATA", "PROGRAMDATA"):
            base = os.environ.get(env)
            if base:
                roots.append((os.path.join(base, r"Microsoft\Windows\Caches"), 8))
        pd = os.environ.get("PROGRAMDATA")
        if pd:
            roots.append((pd, 1))
        for env in ("TEMP",):
            base = os.environ.get(env)
            if base:
                roots.append((base, 2))
        roots.append((os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"), 2))
        dl = os.path.join(os.path.expanduser("~"), "Downloads")
        roots.append((dl, 3))

        seen_dirs: set[str] = set()
        for root, depth in roots:
            if not root or not os.path.isdir(root):
                continue
            for path in self._walk(root, depth):
                if path in seen_dirs:
                    continue
                seen_dirs.add(path)
                self._inspect_file(path)

        # IoC 目录
        ioc_dirs = [
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\Caches\1C212048"),
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Microsoft\Windows\Caches\1A44A355"),
            os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Caches\1C212048"),
            os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Caches\1C212048"),
            os.path.join(os.environ.get("PROGRAMDATA", ""), r"30E7A103"),
        ]
        for d in ioc_dirs:
            if d and os.path.isdir(d) and not d.startswith("Microsoft"):
                files = []
                try:
                    for dirpath, _, names in os.walk(d):
                        for n in names:
                            files.append(os.path.join(dirpath, n))
                except Exception:
                    pass
                self.add(
                    id=f"iocdir-{os.path.basename(d)}-{len(d)}", severity="critical", category="文件",
                    title=f"发现木马载荷目录 {d}",
                    detail=f"该路径是本次木马家族使用的伪装目录（内含 {len(files)} 个文件）。",
                    evidence="\n".join(files[:15]) or d,
                    fixable=True, action="quarantine_path",
                    params={"path": d, "reason": "木马载荷目录"},
                )

        # 载荷目录的通用特征：ProgramData 下 8 位十六进制目录
        pd = os.environ.get("PROGRAMDATA")
        if pd and os.path.isdir(pd):
            try:
                for entry in os.scandir(pd):
                    if entry.is_dir() and re.fullmatch(r"[0-9A-Fa-f]{8}", entry.name):
                        files = []
                        for dirpath, _, names in os.walk(entry.path):
                            for n in names:
                                files.append(os.path.join(dirpath, n))
                        self.add(
                            id=f"hexdir-{entry.name}", severity="high", category="文件",
                            title=f"ProgramData 下发现随机命名目录 {entry.name}",
                            detail="八位十六进制随机目录是本次木马家族的载荷存放特征（如 30E7A103）。",
                            evidence="\n".join(files[:15]) or entry.path,
                            fixable=True, action="quarantine_path",
                            params={"path": entry.path, "reason": "随机命名载荷目录"},
                        )
            except Exception:
                pass

        # 特征文件组合
        self._check_artifacts()
        # Caches 下的八位随机子目录（本家族载荷目录特征）
        self._check_caches_hexdirs()
        # Defender 历史检测路径
        self._check_threat_history()

    def _walk(self, root: str, max_depth: int):
        base_depth = root.rstrip("\\").count("\\")
        for dirpath, dirnames, filenames in os.walk(root):
            depth = dirpath.count("\\") - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d.lower() not in
                           ("node_modules", "$recycle.bin", "installer", "winsxs")]
            for name in filenames:
                self.files_seen += 1
                yield os.path.join(dirpath, name)
            if self.files_seen > 60000:
                return

    def _hash(self, path: str) -> str | None:
        if path in self.hash_cache:
            return self.hash_cache[path]
        if self.files_hashed >= self.file_budget or self.hash_budget <= 0:
            return None
        try:
            size = os.path.getsize(path)
        except Exception:
            return None
        if size > 120 * 1024 * 1024 or size == 0:
            return None
        digest = sha256_file(path)
        if digest:
            self.files_hashed += 1
            self.hash_budget -= size
            self.hash_cache[path] = digest
        return digest

    def _inspect_file(self, path: str) -> None:
        name = os.path.basename(path).lower()
        low = path.lower()
        ext = os.path.splitext(name)[1]
        suspicious_name = name in ioc.BAD_PROCESS_NAMES or name in ioc.SUSPICIOUS_FILE_NAMES
        in_ioc_dir = any(m in low for m in ioc.IOC_DIR_MARKERS)
        look_like_payload = ext in (".exe", ".dll", ".sys") and (
            in_ioc_dir or suspicious_name or
            ("\\programdata\\" in low and re.search(r"\\[0-9a-f]{8}\\", low))
        )
        should_hash = look_like_payload or (suspicious_name and ext in (".zip", ".exe", ".dll")) \
            or (in_ioc_dir and ext in (".ps1", ".cmd", ".bat", ".js", ".vbs", ".src")) \
            or (name.startswith("ddu-") and ext == ".zip")
        if not should_hash:
            return
        digest = self._hash(path)
        if not digest:
            return
        info = ioc.KNOWN_HASHES.get(digest)
        if info:
            self.add(
                id=f"hash-{digest[:12]}", severity="critical", category="文件",
                title=f"文件哈希命中已知恶意样本：{info[0]}",
                detail=info[1],
                evidence=f"路径: {path}\nSHA-256: {digest}\n大小: {human_size(os.path.getsize(path))}",
                fixable=True, action="quarantine_path",
                params={"path": path, "reason": f"已知恶意样本 {info[0]}"},
            )
            return
        if digest in ioc.PACKAGE_MEMBER_HASHES and name in ioc.SUSPICIOUS_FILE_NAMES:
            self.add(
                id=f"pkg-{digest[:12]}", severity="medium", category="残留",
                title="发现假 DDU 投毒包内的安装器",
                detail="该文件本身干净，但只应出现在恶意投毒压缩包内。",
                evidence=f"路径: {path}\nSHA-256: {digest}",
                fixable=True, action="quarantine_path",
                params={"path": path, "reason": "投毒包成员"},
            )
            return
        # 未命中哈希，但位置/名称高度可疑
        if in_ioc_dir or name in ioc.BAD_PROCESS_NAMES:
            self.add(
                id=f"suspect-{digest[:12]}", severity="high", category="文件",
                title=f"可疑文件（不在已知哈希库）：{os.path.basename(path)}",
                detail="位于木马伪装目录/使用木马文件名，但哈希未命中。可能是新变种，建议上传 VirusTotal 复核。",
                evidence=f"路径: {path}\nSHA-256: {digest}\n大小: {human_size(os.path.getsize(path))}",
                fixable=True, action="quarantine_path",
                params={"path": path, "reason": "可疑位置/名称"},
            )

    def _check_caches_hexdirs(self) -> None:
        for env in ("LOCALAPPDATA", "APPDATA", "PROGRAMDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            caches = os.path.join(base, r"Microsoft\Windows\Caches")
            if not os.path.isdir(caches):
                continue
            try:
                entries = list(os.scandir(caches))
            except Exception:
                continue
            for entry in entries:
                if not entry.is_dir() or not re.fullmatch(r"[0-9A-Fa-f]{8}", entry.name):
                    continue
                payload = []
                for dirpath, _, names in os.walk(entry.path):
                    for n in names:
                        if os.path.splitext(n)[1].lower() in (".exe", ".dll", ".sys", ".src", ".cmd", ".ps1"):
                            payload.append(os.path.join(dirpath, n))
                if not payload:
                    continue
                self.add(
                    id=f"cacheshex-{env}-{entry.name}", severity="high", category="文件",
                    title=f"Caches 下发现八位随机子目录 {entry.name}",
                    detail="本木马家族把载荷放在 %…%\\Microsoft\\Windows\\Caches\\<8位十六进制>\\ 下，"
                           "并附带 .src/.o/.p 配置。若确认不是你自己创建，应整体隔离。",
                    evidence="\n".join(payload[:10]),
                    fixable=True, action="quarantine_path",
                    params={"path": entry.path, "reason": "Caches 随机子目录载荷"},
                )

    def _check_artifacts(self) -> None:
        hits = []
        for env in ("LOCALAPPDATA", "APPDATA", "PROGRAMDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            for dirpath, dirnames, filenames in os.walk(os.path.join(base, r"Microsoft\Windows\Caches")):
                names = {n.lower() for n in filenames}
                if ".src" in names or (".o" in names and ".p" in names) or "wsc.ps1" in names or "wsc.cmd" in names:
                    hits.append(dirpath)
        if hits:
            self.add(
                id="artifact-set", severity="critical", category="文件",
                title="发现木马配置特征文件（.src/.o/.p/wsc）",
                detail="这些文件名组合是本次木马家族载荷目录的固定特征。",
                evidence="\n".join(hits[:10]),
                fixable=True, action="quarantine_path",
                params={"path": hits[0], "reason": "木马配置特征"},
            )

    def _check_threat_history(self) -> None:
        names = {
            "trojan:win64/dllhijack.aa!mtb",
            "trojandropper:win64/yogi.mk!mtb",
            "trojan:script/coinminer!rfn",
            "trojan:win32/coinminer",
        }
        shown = 0
        for t in self.snap.threats:
            tname = str(t.get("ThreatName") or "")
            if tname.lower() not in names and "coinminer" not in tname.lower() and "dllhijack" not in tname.lower():
                continue
            resources = t.get("Resources") or []
            if isinstance(resources, str):
                resources = [resources]
            self.add(
                id=f"threat-{shown}-{tname}", severity="high" if shown else "critical", category="残留",
                title=f"Defender 历史检测记录：{tname}",
                detail=f"检测时间 {t.get('InitialDetectionTime')}，处置成功={t.get('ActionSuccess')}。"
                       f"若文件仍在，请立即隔离。",
                evidence="\n".join([str(r) for r in resources][:10]) or str(t)[:400],
                fixable=False,
            )
            shown += 1
            if shown >= 5:
                break

    # ---- 残留
    def check_residue(self) -> None:
        dl = os.path.join(os.path.expanduser("~"), "Downloads")
        if os.path.isdir(dl):
            for entry in os.scandir(dl):
                low = entry.name.lower()
                if low.startswith("ddu-") and low.endswith((".zip", ".exe")):
                    digest = self._hash(entry.path)
                    known = ioc.KNOWN_HASHES.get(digest or "")
                    self.add(
                        id=f"residue-{entry.name}", severity="critical" if known else "medium",
                        category="残留",
                        title=f"下载目录存在假 DDU 安装包：{entry.name}",
                        detail=("哈希命中已知投毒包，请立即隔离。" if known
                               else "文件名与投毒包一致，哈希未命中已知库，建议上传 VirusTotal 复核后删除。"),
                        evidence=f"路径: {entry.path}\nSHA-256: {digest or '(未计算)'}",
                        fixable=True, action="quarantine_path",
                        params={"path": entry.path, "reason": "假 DDU 投毒包"},
                    )
        # WinRing0 驱动
        wd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "WinRing0x64.sys")
        if os.path.exists(wd):
            digest = self._hash(wd)
            self.add(
                id="winring0", severity="high", category="残留",
                title="发现 WinRing0x64.sys 内核漏洞驱动",
                detail="该驱动可被用于任意物理内存读写，常随挖矿木马落地（部分灯效软件也会安装，请甄别来源）。",
                evidence=f"路径: {wd}\nSHA-256: {digest or '(未知)'}",
                fixable=True, action="quarantine_path",
                params={"path": wd, "reason": "WinRing0 漏洞驱动"},
            )

    # ---- 环境
    def check_environment(self) -> None:
        from .envguard import inspect_environment

        checks = inspect_environment(self.logger)
        self.result.env_checks = checks
        for c in checks:
            if c.status == "fail":
                self.result.findings.append(Finding(
                    id=f"env-{c.key}", severity="medium", category="环境",
                    title=c.name, detail=c.detail,
                    fixable=bool(c.fix_action), action=c.fix_action, params={},
                ))


def _first_exe(cmdline: str) -> str:
    s = (cmdline or "").strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 0:
            return s[1:end]
    m = re.match(r'([^\s"]+\.exe)', s, re.I)
    return m.group(1) if m else ""


def _mask_cmd(cmdline: str) -> str:
    """遮蔽矿工命令行里的钱包地址等敏感信息。"""
    if not cmdline:
        return ""
    text = re.sub(r'(-u\s+)"?([A-Za-z0-9._\-]{16,})"?', r'\1"<已隐藏>"', cmdline)
    text = re.sub(r'\b0x[0-9A-Fa-f]{20,}\b', '<已隐藏>', text)
    return text


def _in_allowed_roots(lower_path: str) -> bool:
    """系统组件名只应在这些目录下出现。"""
    roots = []
    sysroot = os.environ.get("SystemRoot", r"C:\Windows").lower().rstrip("\\")
    roots += [sysroot, sysroot + "\\system32", sysroot + "\\syswow64"]
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        p = os.environ.get(env)
        if p:
            roots.append(p.lower().rstrip("\\"))
    p = os.environ.get("PROGRAMDATA")
    if p:
        roots.append(os.path.join(p, r"Microsoft\Windows Defender").lower())
    return any(lower_path.startswith(r + "\\") or lower_path == r for r in roots)


def _dangerous_exclusion(path) -> bool:
    p = str(path).strip().lower().rstrip("\\")
    if not p:
        return False
    if p in ("c:", "c:\\", "c:\\*", "d:\\", "*"):
        return True
    if p.startswith("c:\\windows") or p in (r"c:\program files", r"c:\program files (x86)",
                                            r"c:\programdata", r"c:\users"):
        return True
    if "\\caches" in p or "temp" == os.path.basename(p):
        return True
    return False
