"""报告生成：Markdown / HTML / JSON."""

from __future__ import annotations

import html
import json
import os
from datetime import datetime

from . import APP_TITLE, APP_VERSION, ioc
from .scanner import SEVERITY_LABEL, SEVERITY_ORDER, ScanResult
from .util import data_root, hostname, is_admin, username, windows_version


def _machine() -> dict:
    return {
        "主机名": hostname(),
        "用户": username(),
        "系统": windows_version(),
        "管理员权限": "是" if is_admin() else "否",
        "程序版本": f"{APP_TITLE} v{APP_VERSION}",
        "数据目录": data_root(),
    }


def build_json(result: ScanResult, fix_outcomes=None) -> dict:
    return {
        "tool": APP_TITLE,
        "version": APP_VERSION,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "machine": _machine(),
        "score": result.score,
        "level": result.level,
        "summary": result.summary,
        "stats": result.stats,
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "severity_label": SEVERITY_LABEL.get(f.severity, f.severity),
                "category": f.category,
                "title": f.title,
                "detail": f.detail,
                "evidence": f.evidence,
                "status": f.status,
                "fix_result": f.fix_result,
            }
            for f in result.findings
        ],
        "environment": [
            {"key": c.key, "name": c.name, "status": c.status, "detail": c.detail}
            for c in result.env_checks
        ],
        "fix_outcomes": [
            {"id": o.finding_id, "title": o.title, "ok": o.ok, "message": o.message}
            for o in (fix_outcomes or [])
        ],
    }


def build_markdown(result: ScanResult, fix_outcomes=None) -> str:
    machine = _machine()
    lines = []
    lines.append(f"# 系统安全检查报告\n")
    lines.append(f"> 生成时间：{datetime.now():%Y-%m-%d %H:%M:%S}　工具：{APP_TITLE} v{APP_VERSION}\n")
    lines.append("## 一、总览\n")
    lines.append("| 项目 | 值 |")
    lines.append("|---|---|")
    for k, v in machine.items():
        lines.append(f"| {k} | {v} |")
    lines.append(f"| 安全评分 | **{result.score} / 100（{result.level}）** |")
    s = result.summary
    lines.append(f"| 问题统计 | 严重 {s.get('critical', 0)} · 高危 {s.get('high', 0)} · "
                 f"中危 {s.get('medium', 0)} · 低危 {s.get('low', 0)} · 提示 {s.get('info', 0)} |")
    lines.append(f"| 扫描统计 | 文件 {result.stats.get('扫描文件数', 0)} 个，"
                 f"哈希 {result.stats.get('计算哈希文件数', 0)} 个，"
                 f"耗时 {result.stats.get('耗时秒', 0)} 秒 |")
    lines.append("")

    findings = result.findings
    if not findings:
        lines.append("**未发现任何异常。**\n")
    else:
        lines.append("## 二、发现的问题\n")
        for cat in ("进程", "持久化", "防御", "网络", "文件", "残留", "环境"):
            group = [f for f in findings if f.category == cat]
            if not group:
                continue
            lines.append(f"### {cat}（{len(group)}）\n")
            lines.append("| 等级 | 状态 | 问题 | 说明 |")
            lines.append("|---|---|---|---|")
            for f in group:
                detail = f.detail.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {SEVERITY_LABEL.get(f.severity, f.severity)} | {f.status} | "
                             f"{f.title.replace('|', '\\|')} | {detail[:180]} |")
            lines.append("")
            lines.append("<details><summary>查看证据</summary>\n")
            for f in group:
                if f.evidence:
                    lines.append(f"**{f.title}**\n")
                    lines.append("```")
                    lines.append(f.evidence[:1200])
                    lines.append("```\n")
            lines.append("</details>\n")

    if fix_outcomes:
        lines.append("## 三、处置记录\n")
        lines.append("| 项目 | 结果 | 说明 |")
        lines.append("|---|---|---|")
        for o in fix_outcomes:
            lines.append(f"| {o.title} | {'成功' if o.ok else '失败'} | {o.message[:160].replace('|', '\\|')} |")
        lines.append("")
    else:
        lines.append("## 三、处置记录\n")
        lines.append("本次仅执行只读体检，未修改系统任何设置。\n")

    lines.append("## 四、环境自检\n")
    lines.append("| 检查项 | 状态 | 说明 |")
    lines.append("|---|---|---|")
    icon = {"ok": "✅ 正常", "warn": "⚠️ 注意", "fail": "❌ 异常"}
    for c in result.env_checks:
        lines.append(f"| {c.name} | {icon.get(c.status, c.status)} | {c.detail.replace('|', '\\|')[:200]} |")
    lines.append("")

    lines.append("## 五、建议\n")
    if result.score >= 95:
        lines.append("- 本次检查未发现木马残留，保持 Defender 实时保护开启、定期更新即可。")
    else:
        lines.append("- 优先处理「严重 / 高危」项，然后重新体检确认评分回升。")
        lines.append("- 若在本机发现本次家族的文件但哈希未命中，建议上传 VirusTotal 复核后隔离。")
    lines.append("- 本次木马家族（假 DDU）曾关闭 Defender 排除项与 UAC 提示，修复后请重启一次。")
    lines.append("- 如曾在此机器上输入过账号密码，建议修改重要账号密码并开启两步验证。")
    lines.append("")

    lines.append("## 附录：本次事件 IoC（假 DDU 投毒 → 隐藏挖矿木马）\n")
    lines.append("### 文件哈希（SHA-256）\n")
    lines.append("| SHA-256 | 文件名 | 说明 |")
    lines.append("|---|---|---|")
    for digest, (name, note) in ioc.KNOWN_HASHES.items():
        lines.append(f"| `{digest.upper()}` | {name} | {note} |")
    lines.append("")
    lines.append("### 路径 / 注册表 / 任务\n")
    lines.append("```")
    lines.append(r"%APPDATA%\Microsoft\Windows\Caches\1C212048          ← 代理 + wsc 脚本")
    lines.append(r"%LOCALAPPDATA%\Microsoft\Windows\Caches\1C212048     ← 挖矿内核 + WinRing0")
    lines.append(r"%LOCALAPPDATA%\Microsoft\Windows\Caches\1A44A355     ← 多矿工载荷仓库")
    lines.append(r"C:\ProgramData\Microsoft\Windows\Caches\1C212048")
    lines.append(r"C:\ProgramData\30E7A103                              ← ccv.exe / mzcv.exe")
    for key, hive in ioc.RUN_KEYS[:3]:
        lines.append(f"{hive}\\{key}  ->  SECIDNWFZ / WindowsCacheManager")
    lines.append(r"\Windows Update Health Handler  （每 5 分钟触发）")
    lines.append("127.0.0.1:61160（Stratum 代理） / 0.0.0.0:42842（矿工 API）")
    lines.append("```")
    return "\n".join(lines)


def build_html(result: ScanResult, fix_outcomes=None) -> str:
    md = build_markdown(result, fix_outcomes)
    e = html.escape
    rows = []
    sev_color = {"critical": "#c0392b", "high": "#e67e22", "medium": "#d4a017",
                 "low": "#4a7ebb", "info": "#7f8c8d"}
    for f in result.findings:
        rows.append(
            f"<tr><td><span class='sev' style='background:{sev_color.get(f.severity, '#888')}'>"
            f"{e(SEVERITY_LABEL.get(f.severity, f.severity))}</span></td>"
            f"<td>{e(f.category)}</td><td>{e(f.title)}</td><td>{e(f.detail)}</td>"
            f"<td>{e(f.status)}</td></tr>")
    if not rows:
        rows.append("<tr><td colspan='5'>未发现异常</td></tr>")
    env_rows = []
    for c in result.env_checks:
        icon = {"ok": "✅", "warn": "⚠️", "fail": "❌"}.get(c.status, "•")
        env_rows.append(f"<tr><td>{e(c.name)}</td><td>{icon}</td><td>{e(c.detail)}</td></tr>")
    machine = "".join(f"<tr><th>{e(k)}</th><td>{e(str(v))}</td></tr>" for k, v in _machine().items())
    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>系统安全检查报告 - {e(hostname())}</title>
<style>
 body{{font-family:"Microsoft YaHei UI","Segoe UI",sans-serif;background:#f6f7f9;color:#1c2530;margin:0;padding:32px}}
 .wrap{{max-width:1080px;margin:0 auto;background:#fff;border-radius:14px;padding:32px 36px;box-shadow:0 8px 30px rgba(20,30,45,.08)}}
 h1{{margin:0 0 6px;font-size:26px}} h2{{margin:30px 0 10px;font-size:19px;border-left:4px solid #c0392b;padding-left:10px}}
 .meta{{color:#6b7785;font-size:13px;margin-bottom:22px}}
 .score{{display:flex;align-items:center;gap:18px;background:#0f1720;color:#fff;border-radius:12px;padding:18px 24px;margin:18px 0}}
 .score b{{font-size:40px;line-height:1}}
 .score span{{opacity:.75;font-size:14px}}
 table{{width:100%;border-collapse:collapse;font-size:13.5px;margin:10px 0 6px}}
 th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid #e6e9ee;vertical-align:top}}
 th{{background:#f2f4f7;font-weight:600}}
 .sev{{display:inline-block;color:#fff;border-radius:5px;padding:2px 8px;font-size:12px}}
 code{{background:#f2f4f7;padding:1px 5px;border-radius:4px;font-family:Consolas,monospace;font-size:12.5px}}
 pre{{background:#f7f8fa;border:1px solid #e6e9ee;border-radius:8px;padding:12px;overflow:auto;font-size:12px}}
 .foot{{margin-top:28px;color:#8894a3;font-size:12px}}
</style></head><body><div class="wrap">
<h1>系统安全检查报告</h1>
<div class="meta">生成时间 {datetime.now():%Y-%m-%d %H:%M:%S} · {e(APP_TITLE)} v{APP_VERSION}</div>
<div class="score"><b>{result.score}</b><div><div style="font-size:18px">{e(result.level)}</div>
<span>严重 {result.summary.get('critical',0)} · 高危 {result.summary.get('high',0)} · 中危 {result.summary.get('medium',0)} · 提示 {result.summary.get('info',0)}</span></div></div>
<h2>本机信息</h2><table>{machine}</table>
<h2>发现的问题</h2>
<table><thead><tr><th>等级</th><th>类别</th><th>问题</th><th>说明</th><th>状态</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
<h2>环境自检</h2>
<table><thead><tr><th>检查项</th><th>状态</th><th>说明</th></tr></thead><tbody>{''.join(env_rows)}</tbody></table>
<h2>建议</h2>
<pre>{e(chr(10).join(l for l in md.splitlines() if l.startswith('- ') or l.startswith('**未发现')))}</pre>
<div class="foot">本报告由 {e(APP_TITLE)} 自动生成。所有处置动作均在本地执行，不联网、不上传任何数据。</div>
</div></body></html>"""


def save_reports(result: ScanResult, fix_outcomes=None, prefix: str | None = None) -> dict:
    from .util import report_dir

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    name = prefix or f"安全检查报告_{hostname()}_{stamp}"
    base = os.path.join(report_dir(), name)
    paths = {"markdown": base + ".md", "html": base + ".html", "json": base + ".json"}
    with open(paths["markdown"], "w", encoding="utf-8") as f:
        f.write(build_markdown(result, fix_outcomes))
    with open(paths["html"], "w", encoding="utf-8") as f:
        f.write(build_html(result, fix_outcomes))
    with open(paths["json"], "w", encoding="utf-8") as f:
        json.dump(build_json(result, fix_outcomes), f, ensure_ascii=False, indent=2)
    return paths
