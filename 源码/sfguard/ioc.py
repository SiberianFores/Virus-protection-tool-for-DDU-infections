"""IoC 数据库：本次「假 DDU + 挖矿木马」事件的已知特征."""

# SHA-256：命中即判定为恶意（最后一条为包内干净安装器，仅用于识别投毒包）
KNOWN_HASHES = {
    "a4a4205051c05607d59024d4e4e22de284f89e7e0d7d46db442a903bbf24b3e9":
        ("ddu-18.1.6.0.zip", "假 DDU 投毒包（2026-11-25 在线版）"),
    "c8ffe43132b659d9ff659ccbf39819b2e8992417f496ddccb4ba5d2f52b75305":
        ("ddu-18.1.6.0.zip", "假 DDU 投毒包（2026-11-24 感染版）"),
    "52d0c6d4ea0de89c55bdee6a415a323ef05e424d961b375d0b5676ece0f399d0":
        ("SqlSetupBootstrapper.dll", "DLL 劫持入口（Trojan:Win64/DllHijack.AA!MTB）"),
    "c387abbd97577fc87df8d2dd3d58eb37019c9e98f004ab9be94e65dac4c82d1c":
        ("RuntimeBroker6A2D.exe", "SRBMiner 改造的挖矿内核"),
    "4bf8caf155f1acf3a9099fdf090385fd60bf9a22cd3505e225d7782a4658d212":
        ("RuntimeBroker6A2D.exe", "PeakMiner 改造的挖矿内核"),
    "45d54e54e0bfcae4f983a8c5db88d1e3fed1618b26d4461c76af8027c4ec4616":
        ("RuntimeBroker6A2D.exe", "lolMiner 改造的挖矿内核"),
    "fd0c1b6636f6fb1d16a3a802b4456e40a199efb34ad18ccd83a8890680a85370":
        ("NtSvcF753.exe", "本地 Stratum 代理（ProgramData 副本）"),
    "47ddb98eecc4bcaccc14ec1a992bbd2dd8932250b55e330e1399a22540a02757":
        ("NtSvcF753.exe", "本地 Stratum 代理（Roaming 副本）"),
    "737b66f34e33a991a6f983b5164d800f358376a10a43cd88175259a83b986556":
        ("ccv.exe", "木马组件 ccv.exe"),
    "0fbcaa65ada37326741259d2ebc96d52e61d38cd6c28823194f2ffb4bf906ebe":
        ("mzcv.exe", "木马组件 mzcv.exe"),
    "11bd2c9f9e2397c9a16e0990e4ed2cf0679498fe0fd418a3dfdac60b5c160ee5":
        ("WinRing0x64.sys", "内核漏洞驱动（提权/反检测）"),
}

# 包内干净文件（用于识别「假 DDU 包」而不误报）
PACKAGE_MEMBER_HASHES = {
    "f0b332ed4ff4f4dde04cf7463b6aba23d8cd3198bd763a627c5c196c2d775760": "ddu-18.1.6.0.exe",
}

# 已知投毒包内文件名（用于扫描下载目录）
SUSPICIOUS_FILE_NAMES = (
    "ddu-18.1.6.0.zip",
    "ddu-18.1.6.0.exe",
    "sqlsetupbootstrapper.dll",
    "ntsvcf753.exe",
    "runtimebroker6a2d.exe",
)

# 恶意进程名（大小写不敏感）
BAD_PROCESS_NAMES = {
    "ntsvcf753.exe",
    "runtimebroker6a2d.exe",
    "ccv.exe",
    "mzcv.exe",
}

# 唯一确信是伪装的进程名（System32 之外出现即可疑）
IMPERSONATED_NAMES = {
    "securityhealthhost.exe": "Windows 安全健康组件",
    "securityhealthsystray.exe": "Windows 安全中心托盘",
    "runtimebroker.exe": "Windows 运行时代理",
    "svchost.exe": "Windows 服务宿主",
    "taskhostw.exe": "Windows 任务宿主",
    "dllhost.exe": "COM 代理宿主",
    "sihost.exe": "Shell 基础结构宿主",
    "smartscreen.exe": "SmartScreen 筛选器",
    "wuauclt.exe": "Windows 更新客户端",
    "conhost.exe": "控制台窗口宿主",
    "lsass.exe": "本地安全认证",
    "csrss.exe": "客户端服务子系统",
    "winlogon.exe": "Windows 登录程序",
    "explorer.exe": "Windows 资源管理器",
}

# 挖矿程序常见进程名（可能是用户自己装的，也可能是伪装载荷）
MINER_PROCESS_NAMES = {
    "xmrig.exe", "srbminer-multi.exe", "lolminer.exe", "trex.exe", "t-rex.exe",
    "phoenixminer.exe", "teamredminer.exe", "nbminer.exe", "gminer.exe",
    "bminer.exe", "ethminer.exe", "nanominer.exe", "cpuminer.exe", "minerd.exe",
    "peakminer.exe", "rigel.exe", "onezerominer.exe", "kawpowminer.exe",
}

# 注册表 Run 值
BAD_RUN_VALUES = ("secidnwfz", "windowscachemanager")

RUN_KEYS = [
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
    (r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
]

# 计划任务
BAD_TASK_NAMES = ("windows update health handler",)

# 目录特征
IOC_DIR_MARKERS = (
    r"\microsoft\windows\caches\1c212048",
    r"\microsoft\windows\caches\1a44a355",
)
CACHES_DIRS = (
    r"Microsoft\Windows\Caches",
)
ARTIFACT_FILES = (".o", ".p", ".src", "wsc.cmd", "wsc.ps1")

# 网络
BAD_PORTS = (61160, 42842)
BAD_DOMAINS = ("fast-dl.dx04-1997.workers.dev", "dx04-1997.workers.dev")

# 命令行特征
CMD_MARKERS = (
    "--algorithm pearlhash",
    "--pool 127.0.0.1:61160",
    "127.0.0.1:61160",
    "--api-port 42842",
    "pearlhash",
)

# 命令中出现的可疑路径片段
SUSPICIOUS_PATH_PATTERNS = (
    r"\microsoft\windows\caches\\",
    "content.ie5",
    r"\windows\temp\\",
    r"\appdata\local\temp\\",
)

# 用于识别「每 5 分钟拉起一次」的持久化
SHORT_INTERVAL_MINUTES = 15

# 已知矿池/矿工常用端口（仅在与可疑进程关联时提示）
MINER_PORTS = (3333, 4444, 5555, 7777, 9999, 14444, 45700, 45560, 3357, 3389)

DEFENDER_POLICY_KEYS = (
    r"SOFTWARE\Policies\Microsoft\Windows Defender",
    r"SOFTWARE\Microsoft\Windows Defender",
)

DEFENDER_EXCLUSION_POLICY = (
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions",
    r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
    r"SOFTWARE\Microsoft\Windows Defender\Exclusions",
)

UAC_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
UAC_DEFAULTS = {
    "EnableLUA": 1,
    "ConsentPromptBehaviorAdmin": 5,
    "PromptOnSecureDesktop": 1,
    "EnableInstallerDetection": 1,
    "EnableVirtualization": 1,
    "EnableSecureUIAPaths": 1,
    "FilterAdministratorToken": 0,
}

QUARANTINE_NOTE = (
    "本工具不做直接删除：所有恶意文件会被移动到隔离区并记录 SHA-256，"
    "便于回溯与上报；确认无误后可在隔离区自行清空。"
)
