"""Tkinter 桌面界面."""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

from . import APP_TITLE, APP_VERSION, ioc
from .fixer import Fixer
from .report import build_json, save_reports
from .scanner import SEVERITY_LABEL, Scanner, ScanResult
from .util import (
    Logger,
    data_root,
    elevate,
    hide_console,
    is_admin,
    open_folder,
    quarantine_dir,
    report_dir,
    run_cmd,
    run_ps,
    username,
)

BG = "#0d1117"
PANEL = "#151b24"
PANEL2 = "#1b2330"
BORDER = "#253141"
TEXT = "#e6edf3"
MUTED = "#8b98a9"
ACCENT = "#2f81f7"
OK = "#3fb950"
WARN = "#d29922"
CRIT = "#f85149"
ORANGE = "#db6d28"

SEV_UI = {
    "critical": (CRIT, "严重"),
    "high": (ORANGE, "高危"),
    "medium": (WARN, "中危"),
    "low": ("#58a6ff", "低危"),
    "info": (MUTED, "提示"),
}
ENV_UI = {"ok": (OK, "正常"), "warn": (WARN, "注意"), "fail": (CRIT, "异常")}


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.queue: queue.Queue = queue.Queue()
        self.result: ScanResult | None = None
        self.fix_outcomes = []
        self.busy = False
        self.selected_finding = None

        self.logger = Logger(echo=False)
        self.logger._write_orig = self.logger._write

        def _write(level, msg, _orig=self.logger._write_orig):
            _orig(level, msg)
            self.queue.put(("log", msg))

        self.logger._write = _write  # type: ignore[method-assign]

        self._build_style()
        self._build_ui()
        self._pump()
        self.root.after(400, lambda: self.start_scan(quick=False))
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ------------------------------------------------------------------ 样式
    def _build_style(self):
        self.root.configure(bg=BG)
        self.root.title(APP_TITLE)
        self.root.geometry("1160x780")
        self.root.minsize(1020, 680)
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", background=BG, foreground=TEXT, fieldbackground=PANEL2,
                        bordercolor=BORDER, font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL, relief="flat")
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Panel.TLabel", background=PANEL, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Microsoft YaHei UI", 9))
        style.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED, font=("Microsoft YaHei UI", 9))
        style.configure("H1.TLabel", background=BG, foreground=TEXT, font=("Microsoft YaHei UI", 17, "bold"))
        style.configure("H2.TLabel", background=PANEL, foreground=TEXT, font=("Microsoft YaHei UI", 11, "bold"))
        style.configure("TButton", background=PANEL2, foreground=TEXT, borderwidth=0,
                        focuscolor=PANEL2, padding=(12, 8))
        style.map("TButton",
                  background=[("active", "#243044"), ("disabled", "#161d27")],
                  foreground=[("disabled", "#55606f")])
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff",
                        font=("Microsoft YaHei UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#4b93f8"), ("disabled", "#1f3552")])
        style.configure("Danger.TButton", background="#8f2f2f", foreground="#ffffff",
                        font=("Microsoft YaHei UI", 10, "bold"))
        style.map("Danger.TButton", background=[("active", "#b03a3a"), ("disabled", "#3a2222")])
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                        padding=(16, 9), borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", PANEL2)],
                  foreground=[("selected", TEXT)])
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL,
                        foreground=TEXT, borderwidth=0, rowheight=27,
                        font=("Microsoft YaHei UI", 9))
        style.configure("Treeview.Heading", background=PANEL2, foreground=MUTED,
                        borderwidth=0, font=("Microsoft YaHei UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#26405f")],
                  foreground=[("selected", "#ffffff")])
        style.configure("Horizontal.TProgressbar", background=ACCENT,
                        troughcolor=PANEL2, borderwidth=0, thickness=6)

    # ------------------------------------------------------------------ 布局
    def _build_ui(self):
        root = self.root
        header = tk.Frame(root, bg=PANEL, height=76)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        title_box = tk.Frame(header, bg=PANEL)
        title_box.pack(side="left", padx=22, pady=12)
        tk.Label(title_box, text="SFguard", bg=PANEL, fg=TEXT,
                 font=("Microsoft YaHei UI", 18, "bold")).pack(anchor="w")
        tk.Label(title_box, text="DDU 投毒木马专杀 · 系统安全体检",
                 bg=PANEL, fg=MUTED, font=("Microsoft YaHei UI", 9)).pack(anchor="w")

        right = tk.Frame(header, bg=PANEL)
        right.pack(side="right", padx=18)
        self.admin_var = tk.StringVar()
        self._admin_badge = tk.Label(right, textvariable=self.admin_var, bg=PANEL2, fg=WARN,
                                     font=("Microsoft YaHei UI", 9), padx=10, pady=4)
        self._admin_badge.pack(side="left", padx=(0, 10))
        self.elevate_btn = ttk.Button(right, text="以管理员身份运行", style="Accent.TButton",
                                      command=self.on_elevate)
        self.elevate_btn.pack(side="left")
        self._refresh_admin_badge()

        body = tk.Frame(root, bg=BG)
        body.pack(fill="both", expand=True, padx=16, pady=12)

        # 左栏
        left = tk.Frame(body, bg=BG, width=310)
        left.pack(side="left", fill="y", padx=(0, 12))
        left.pack_propagate(False)

        card = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        card.pack(fill="x")
        tk.Label(card, text="安全评分", bg=PANEL, fg=MUTED,
                 font=("Microsoft YaHei UI", 9)).pack(anchor="w", padx=18, pady=(14, 0))
        self.score_canvas = tk.Canvas(card, width=240, height=150, bg=PANEL, highlightthickness=0)
        self.score_canvas.pack(pady=(2, 0))
        self.level_label = tk.Label(card, text="尚未检查", bg=PANEL, fg=MUTED,
                                    font=("Microsoft YaHei UI", 12, "bold"))
        self.level_label.pack(pady=(0, 4))
        self.count_label = tk.Label(card, text="", bg=PANEL, fg=MUTED,
                                    font=("Microsoft YaHei UI", 9), justify="center")
        self.count_label.pack(pady=(0, 14))
        self._draw_score(None)

        btns = tk.Frame(left, bg=BG)
        btns.pack(fill="x", pady=(12, 0))
        self.scan_btn = ttk.Button(btns, text="🔍  开始安全检查", style="Accent.TButton",
                                   command=lambda: self.start_scan())
        self.scan_btn.pack(fill="x", pady=(0, 8), ipady=4)
        self.fix_btn = ttk.Button(btns, text="🛠  一键修复全部问题", style="Danger.TButton",
                                  command=self.on_fix_all)
        self.fix_btn.pack(fill="x", pady=(0, 8), ipady=4)
        self.export_btn = ttk.Button(btns, text="📄  导出检查报告", command=self.on_export)
        self.export_btn.pack(fill="x", pady=(0, 8))
        row = tk.Frame(btns, bg=BG)
        row.pack(fill="x")
        ttk.Button(row, text="隔离区", command=self.on_open_quarantine).pack(side="left", expand=True, fill="x", padx=(0, 4))
        ttk.Button(row, text="运行目录", command=lambda: open_folder(data_root())).pack(side="left", expand=True, fill="x", padx=(4, 0))

        env_card = tk.Frame(left, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        env_card.pack(fill="both", expand=True, pady=(12, 0))
        head = tk.Frame(env_card, bg=PANEL)
        head.pack(fill="x", padx=14, pady=(12, 6))
        tk.Label(head, text="运行环境", bg=PANEL, fg=TEXT,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(side="left")
        ttk.Button(head, text="补齐", command=self.on_provision, width=6).pack(side="right")
        self.env_frame = tk.Frame(env_card, bg=PANEL)
        self.env_frame.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.env_labels = {}
        for key, name in (("admin", "管理员权限"), ("datadir", "工作目录"),
                          ("powershell", "PowerShell"), ("defender-svc", "Defender 服务"),
                          ("defender-policy", "Defender 策略")):
            rowf = tk.Frame(self.env_frame, bg=PANEL)
            rowf.pack(fill="x", pady=2)
            dot = tk.Label(rowf, text="●", bg=PANEL, fg=MUTED, font=("Segoe UI", 9))
            dot.pack(side="left")
            tk.Label(rowf, text=name, bg=PANEL, fg=TEXT, font=("Microsoft YaHei UI", 9),
                     anchor="w").pack(side="left", padx=(6, 0))
            val = tk.Label(rowf, text="待检测", bg=PANEL, fg=MUTED, font=("Microsoft YaHei UI", 9),
                           anchor="e")
            val.pack(side="right")
            self.env_labels[key] = (dot, val)

        # 右栏
        right_box = tk.Frame(body, bg=BG)
        right_box.pack(side="left", fill="both", expand=True)

        self.nb = ttk.Notebook(right_box)
        self.nb.pack(fill="both", expand=True)

        # 总览
        self.tab_overview = tk.Frame(self.nb, bg=PANEL)
        self.nb.add(self.tab_overview, text="总览")
        self.overview_text = tk.Text(self.tab_overview, bg=PANEL, fg=TEXT, bd=0,
                                     font=("Microsoft YaHei UI", 10), wrap="word",
                                     padx=26, pady=20, insertbackground=TEXT)
        self.overview_text.pack(fill="both", expand=True)
        self._set_overview_welcome()

        # 问题
        self.tab_issues = tk.Frame(self.nb, bg=PANEL)
        self.nb.add(self.tab_issues, text="问题列表")
        cols = ("sev", "cat", "title", "status")
        self.tree = ttk.Treeview(self.tab_issues, columns=cols, show="headings", selectmode="browse")
        self.tree.heading("sev", text="等级")
        self.tree.heading("cat", text="类别")
        self.tree.heading("title", text="问题")
        self.tree.heading("status", text="状态")
        self.tree.column("sev", width=64, anchor="center", stretch=False)
        self.tree.column("cat", width=80, anchor="center", stretch=False)
        self.tree.column("status", width=84, anchor="center", stretch=False)
        self.tree.column("title", width=520, anchor="w")
        for sev, (color, _) in SEV_UI.items():
            self.tree.tag_configure(sev, foreground=color)
        vsb = ttk.Scrollbar(self.tab_issues, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="top", fill="both", expand=True, padx=(12, 0), pady=(12, 0))
        vsb.place(in_=self.tree, relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.tree.bind("<<TreeviewSelect>>", self.on_select_issue)

        detail_box = tk.Frame(self.tab_issues, bg=PANEL2, height=190)
        detail_box.pack(fill="x", side="bottom", padx=12, pady=(8, 12))
        detail_box.pack_propagate(False)
        dhead = tk.Frame(detail_box, bg=PANEL2)
        dhead.pack(fill="x", padx=12, pady=(8, 0))
        tk.Label(dhead, text="详情与证据", bg=PANEL2, fg=MUTED,
                 font=("Microsoft YaHei UI", 9, "bold")).pack(side="left")
        self.fix_one_btn = ttk.Button(dhead, text="修复此项", command=self.on_fix_selected)
        self.fix_one_btn.pack(side="right")
        self.detail_text = tk.Text(detail_box, bg=PANEL2, fg=TEXT, bd=0,
                                   font=("Consolas", 9), wrap="word", padx=12, pady=8,
                                   height=8, insertbackground=TEXT)
        self.detail_text.pack(fill="both", expand=True)
        self.detail_text.configure(state="disabled")

        # 环境
        self.tab_env = tk.Frame(self.nb, bg=PANEL)
        self.nb.add(self.tab_env, text="环境自检")
        self.env_tree = ttk.Treeview(self.tab_env, columns=("name", "state", "detail"),
                                     show="headings", selectmode="browse")
        self.env_tree.heading("name", text="检查项")
        self.env_tree.heading("state", text="状态")
        self.env_tree.heading("detail", text="说明")
        self.env_tree.column("name", width=180, anchor="w", stretch=False)
        self.env_tree.column("state", width=80, anchor="center", stretch=False)
        self.env_tree.column("detail", width=560, anchor="w")
        self.env_tree.tag_configure("ok", foreground=OK)
        self.env_tree.tag_configure("warn", foreground=WARN)
        self.env_tree.tag_configure("fail", foreground=CRIT)
        self.env_tree.pack(fill="both", expand=True, padx=12, pady=12)

        # 日志
        self.tab_log = tk.Frame(self.nb, bg=PANEL)
        self.nb.add(self.tab_log, text="运行日志")
        self.log_text = tk.Text(self.tab_log, bg=PANEL, fg="#b9c6d6", bd=0,
                                font=("Consolas", 9), wrap="word", padx=14, pady=12,
                                insertbackground=TEXT)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_configure("ok", foreground=OK)
        self.log_text.tag_configure("warn", foreground=WARN)
        self.log_text.tag_configure("error", foreground=CRIT)

        # IoC
        self.tab_ioc = tk.Frame(self.nb, bg=PANEL)
        self.nb.add(self.tab_ioc, text="IoC 数据库")
        ioc_text = tk.Text(self.tab_ioc, bg=PANEL, fg="#c8d4e2", bd=0,
                           font=("Consolas", 9), wrap="word", padx=18, pady=14)
        ioc_text.pack(fill="both", expand=True)
        lines = ["本次「假 DDU 投毒 → 隐藏挖矿木马」事件特征库", "=" * 60, "", "【SHA-256】"]
        for digest, (name, note) in ioc.KNOWN_HASHES.items():
            lines.append(f"{digest.upper()}")
            lines.append(f"    {name}  —  {note}")
        lines.append("")
        lines.append("【持久化】")
        lines.append(r"计划任务  \Windows Update Health Handler   （每 5 分钟）")
        for key, hive in ioc.RUN_KEYS[:3]:
            lines.append(f"{hive}\\{key}")
            lines.append("    SECIDNWFZ / WindowsCacheManager")
        lines.append("")
        lines.append("【路径特征】")
        for m in ioc.IOC_DIR_MARKERS:
            lines.append("%LOCALAPPDATA%" + m)
        lines.append(r"内容文件：.o(内容 Running) / .p / .src / wsc.cmd / wsc.ps1")
        lines.append("")
        lines.append("【网络】")
        lines.append("127.0.0.1:61160  Stratum 代理      0.0.0.0:42842  矿工 API")
        lines.append("fast-dl.dx04-1997.workers.dev/ddu-18.1.6.0.zip")
        lines.append("")
        lines.append("【命令行】")
        for m in ioc.CMD_MARKERS:
            lines.append("  " + m)
        ioc_text.insert("1.0", "\n".join(lines))
        ioc_text.configure(state="disabled")

        # 状态栏
        footer = tk.Frame(root, bg=PANEL, height=40)
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)
        self.progress = ttk.Progressbar(footer, mode="determinate", maximum=100)
        self.progress.pack(side="right", padx=16, pady=16, fill="x", expand=True)
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(footer, textvariable=self.status_var, bg=PANEL, fg=MUTED,
                 font=("Microsoft YaHei UI", 9), anchor="w").pack(side="left", padx=16)
        tk.Label(footer, text=f"v{APP_VERSION}", bg=PANEL, fg="#56606f",
                 font=("Microsoft YaHei UI", 9)).pack(side="right", padx=(0, 16))

    # ------------------------------------------------------------------ 小部件行为
    def _refresh_admin_badge(self):
        if is_admin():
            self.admin_var.set("● 管理员权限")
            self._admin_badge.configure(fg=OK)
            self.elevate_btn.state(["disabled"])
            self.elevate_btn.configure(text="已提权")
        else:
            self.admin_var.set("● 普通权限（只读体检）")
            self._admin_badge.configure(fg=WARN)

    def _draw_score(self, score):
        c = self.score_canvas
        c.delete("all")
        cx, cy, r = 120, 84, 62
        c.create_oval(cx - r, cy - r, cx + r, cy + r, outline="#232e3d", width=12)
        if score is None:
            c.create_text(cx, cy - 6, text="--", fill=MUTED, font=("Segoe UI", 34, "bold"))
            c.create_text(cx, cy + 26, text="待检查", fill=MUTED, font=("Microsoft YaHei UI", 9))
            return
        color = OK if score >= 95 else (WARN if score >= 80 else (ORANGE if score >= 55 else CRIT))
        extent = -359.9 * score / 100
        c.create_arc(cx - r, cy - r, cx + r, cy + r, start=90, extent=extent,
                     outline=color, width=12, style="arc")
        c.create_text(cx, cy - 8, text=str(score), fill=color, font=("Segoe UI", 36, "bold"))
        c.create_text(cx, cy + 28, text="/ 100", fill=MUTED, font=("Microsoft YaHei UI", 9))

    def _set_overview_welcome(self):
        self.overview_text.configure(state="normal")
        self.overview_text.delete("1.0", "end")
        self.overview_text.insert("end", self._overview_content(None))
        self.overview_text.configure(state="disabled")

    def _overview_content(self, result: ScanResult | None) -> str:
        if result is None:
            return (
                "\n  SFguard 正在准备体检……\n\n"
                "  本工具针对 2026-11 爆发的「假 DDU 安装包 → 隐藏挖矿木马」事件：\n"
                "  该木马会伪装成系统缓存组件，每 5 分钟由计划任务拉起，\n"
                "  关闭 Defender 排除项与 UAC 提示，并长期占用显卡。\n\n"
                "  检查项：进程 · 文件哈希 · 计划任务 · 注册表启动项 · 服务 · WMI ·\n"
                "           Defender 状态与排除项 · hosts · 代理 · 防火墙 · 网络端口\n"
            )
        s = result.summary
        lines = []
        lines.append(f"\n  体检完成：{result.score} 分（{result.level}）\n")
        lines.append(f"  严重 {s.get('critical', 0)}   高危 {s.get('high', 0)}   "
                     f"中危 {s.get('medium', 0)}   低危 {s.get('low', 0)}   提示 {s.get('info', 0)}\n")
        lines.append("  " + "─" * 58 + "\n")
        if not result.findings:
            lines.append("  ✅ 未发现木马残留与系统异常。\n")
            lines.append("  建议保持 Defender 实时保护开启并定期更新病毒库。\n")
        else:
            lines.append("  需要优先处理：\n")
            shown = 0
            for f in result.findings:
                if f.severity not in ("critical", "high") or f.status == "已处理":
                    continue
                label = SEVERITY_LABEL.get(f.severity, f.severity)
                lines.append(f"   • [{label}] {f.title}\n")
                shown += 1
                if shown >= 8:
                    break
            if shown == 0:
                lines.append("   • 仅有中低风险项，可在「问题列表」中查看。\n")
            lines.append("\n  提示：点击左侧「一键修复全部问题」可自动处置；\n"
                         "        修复完成后会自动复检并更新评分。\n")
        st = result.stats
        lines.append("\n  " + "─" * 58 + "\n")
        lines.append(f"  扫描：进程 {st.get('进程数', 0)} · 任务 {st.get('计划任务数', 0)} · "
                     f"服务 {st.get('服务数', 0)} · 文件 {st.get('扫描文件数', 0)} "
                     f"（哈希 {st.get('计算哈希文件数', 0)}）· {st.get('耗时秒', 0)} 秒\n")
        lines.append(f"  时间：{datetime.now():%Y-%m-%d %H:%M:%S}\n")
        return "".join(lines)

    # ------------------------------------------------------------------ 事件循环
    def _pump(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                try:
                    if kind == "log":
                        self._append_log(payload)
                    elif kind == "status":
                        self.status_var.set(payload)
                    elif kind == "progress":
                        self.progress["value"] = payload
                    elif kind == "scan_done":
                        self._on_scan_done(payload)
                    elif kind == "fix_done":
                        self._on_fix_done(payload)
                    elif kind == "env_done":
                        self._apply_env(payload)
                    elif kind == "error":
                        self._set_busy(False)
                        messagebox.showerror("出错了", str(payload))
                except Exception as exc:
                    self.logger.error(f"界面更新异常：{exc}")
        except queue.Empty:
            pass
        self.root.after(120, self._pump)

    def _append_log(self, msg: str):
        self.log_text.insert("end", msg + "\n")
        if "ERROR" in msg:
            self.log_text.tag_add("error", "end-2l", "end-1c")
        elif "[ OK ]" in msg:
            self.log_text.tag_add("ok", "end-2l", "end-1c")
        elif "[WARN]" in msg:
            self.log_text.tag_add("warn", "end-2l", "end-1c")
        self.log_text.see("end")

    def _set_busy(self, busy: bool):
        self.busy = busy
        state = ["disabled"] if busy else ["!disabled"]
        for btn in (self.scan_btn, self.fix_btn, self.export_btn, self.fix_one_btn):
            btn.state(state)
        if not busy:
            self.fix_btn.state(["disabled"] if not (self.result and self.result.fixable) else ["!disabled"])

    # ------------------------------------------------------------------ 扫描
    def start_scan(self, quick: bool = False):
        if self.busy:
            return
        self._set_busy(True)
        self.status_var.set("正在体检……")
        self.progress["value"] = 3
        self.nb.select(self.tab_log)

        def worker():
            try:
                scanner = Scanner(self.logger)
                result = scanner.run(quick=quick)
                self.queue.put(("scan_done", result))
            except Exception as exc:
                self.queue.put(("error", f"体检失败：{exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan_done(self, result: ScanResult):
        self.result = result
        self._set_busy(False)
        self.progress["value"] = 100
        self.status_var.set(f"体检完成：{result.score} 分（{result.level}）")
        self._draw_score(result.score)
        self.level_label.configure(
            text=result.level,
            fg=OK if result.score >= 95 else (WARN if result.score >= 80 else (ORANGE if result.score >= 55 else CRIT)))
        s = result.summary
        self.count_label.configure(
            text=f"严重 {s['critical']} · 高危 {s['high']} · 中危 {s['medium']} · 提示 {s['info']}")

        self.overview_text.configure(state="normal")
        self.overview_text.delete("1.0", "end")
        self.overview_text.insert("end", self._overview_content(result))
        self.overview_text.configure(state="disabled")

        self.tree.delete(*self.tree.get_children())
        for f in result.findings:
            self.tree.insert("", "end", iid=f.id,
                             values=(SEVERITY_LABEL.get(f.severity, f.severity),
                                     f.category, f.title, f.status),
                             tags=(f.severity,))
        self._apply_env(result.env_checks)
        self._set_busy(False)
        if result.findings:
            self.nb.select(self.tab_issues)
        else:
            self.nb.select(self.tab_overview)

    def on_select_issue(self, _event=None):
        sel = self.tree.selection()
        if not sel or not self.result:
            return
        fid = sel[0]
        finding = next((f for f in self.result.findings if f.id == fid), None)
        self.selected_finding = finding
        if not finding:
            return
        text = [f"{finding.title}", "", f"等级：{SEVERITY_LABEL.get(finding.severity)}    "
                                       f"类别：{finding.category}    状态：{finding.status}", "",
                finding.detail, ""]
        if finding.evidence:
            text.append("— 证据 —")
            text.append(finding.evidence)
        if finding.fix_result:
            text.append("")
            text.append("— 修复结果 —")
            text.append(finding.fix_result)
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", "\n".join(text))
        self.detail_text.configure(state="disabled")
        self.fix_one_btn.state(["!disabled"] if finding.fixable and finding.status != "已处理" else ["disabled"])

    def _apply_env(self, checks):
        self.env_checks = checks
        self.env_tree.delete(*self.env_tree.get_children())
        for c in checks:
            color, label = ENV_UI.get(c.status, (MUTED, c.status))
            self.env_tree.insert("", "end", values=(c.name, label, c.detail), tags=(c.status,))
            if c.key in self.env_labels:
                dot, val = self.env_labels[c.key]
                dot.configure(fg=color)
                val.configure(text=label, fg=color)

    # ------------------------------------------------------------------ 修复
    def on_fix_all(self):
        if not self.result or not self.result.fixable:
            messagebox.showinfo("无需修复", "没有可自动修复的问题。")
            return
        if not is_admin():
            if messagebox.askyesno("需要管理员权限", "修复需要管理员权限，是否立即提权重启？"):
                self.on_elevate()
            return
        n = len(self.result.fixable)
        if not messagebox.askyesno(
                "确认修复",
                f"即将自动处置 {n} 个问题：\n\n"
                "• 终止恶意进程\n• 删除恶意计划任务与启动项\n"
                "• 隔离恶意文件（不直接删除，可在隔离区找回）\n"
                "• 清除 Defender 排除项与策略篡改\n• 恢复 UAC 安全提示\n\n"
                "所有注册表改动会先备份。是否继续？"):
            return
        self._run_fix(self.result.fixable)

    def on_fix_selected(self):
        f = self.selected_finding
        if not f or not self.result:
            return
        if not is_admin():
            if messagebox.askyesno("需要管理员权限", "修复需要管理员权限，是否立即提权重启？"):
                self.on_elevate()
            return
        self._run_fix([f])

    def _run_fix(self, findings):
        self._set_busy(True)
        self.status_var.set("正在修复……")
        self.progress["value"] = 5
        self.nb.select(self.tab_log)

        def worker():
            try:
                fixer = Fixer(self.logger)
                outcomes = fixer.fix(findings, progress=lambda m: self.queue.put(("status", m)))
                self.queue.put(("fix_done", outcomes))
            except Exception as exc:
                self.queue.put(("error", f"修复失败：{exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def _on_fix_done(self, outcomes):
        self.fix_outcomes = outcomes
        ok = sum(1 for o in outcomes if o.ok)
        failed = len(outcomes) - ok
        self.status_var.set(f"修复完成：成功 {ok}，失败 {failed}，正在复检……")
        messagebox.showinfo(
            "修复完成",
            f"成功 {ok} 项，失败 {failed} 项。\n\n" +
            "\n".join(f"{'✅' if o.ok else '❌'} {o.title}" for o in outcomes[:10]) +
            ("\n……" if len(outcomes) > 10 else "") +
            "\n\n接下来会自动复检，确认效果。")
        self.root.after(600, lambda: self.start_scan())

    def on_provision(self):
        if self.busy:
            return
        self._set_busy(True)
        self.status_var.set("正在补齐运行环境……")

        def worker():
            from .envguard import provision, inspect_environment

            try:
                provision(self.logger, progress=lambda m: self.queue.put(("status", m)))
                checks = inspect_environment(self.logger)
                self.queue.put(("env_done", checks))
                self.queue.put(("status", "运行环境已检查"))
            except Exception as exc:
                self.queue.put(("error", f"环境补齐失败：{exc}"))

        threading.Thread(target=worker, daemon=True).start()

    def on_elevate(self):
        if is_admin():
            return
        self.logger.info("请求管理员权限……")
        if elevate(list(self.root_argv())):
            self.root.after(300, self.root.destroy)
        else:
            messagebox.showwarning("提权被取消", "未获得管理员权限，仍可执行只读体检。")

    def root_argv(self):
        import sys

        return sys.argv[1:]

    # ------------------------------------------------------------------ 其它
    def on_export(self):
        if not self.result:
            messagebox.showinfo("请先体检", "还没有可导出的检查结果。")
            return
        paths = save_reports(self.result, self.fix_outcomes)
        self.logger.ok(f"报告已导出：{paths['markdown']}")
        if messagebox.askyesno("报告已导出", f"已保存到：\n{paths['markdown']}\n\n是否打开 HTML 报告？"):
            try:
                os.startfile(paths["html"])
            except Exception:
                open_folder(report_dir())

    def on_open_quarantine(self):
        open_folder(quarantine_dir())

    def on_close(self):
        if self.busy and not messagebox.askyesno("正在运行", "任务尚未完成，确定退出？"):
            return
        self.root.destroy()


def run_gui():
    hide_console()
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.25)
    except Exception:
        pass
    App(root)
    root.mainloop()
