"""SFguard 入口：GUI / 命令行 / 自检."""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time

from sfguard import APP_TITLE, APP_VERSION


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="SFguard",
        description=f"{APP_TITLE} v{APP_VERSION}",
        add_help=True,
    )
    p.add_argument("--scan", action="store_true", help="命令行体检（不启动界面）")
    p.add_argument("--fix", action="store_true", help="体检并自动修复（需要管理员权限）")
    p.add_argument("--quick", action="store_true", help="快速体检（跳过部分网络/文件检查）")
    p.add_argument("--json", metavar="PATH", help="把结果写入指定 JSON 文件")
    p.add_argument("--report", metavar="DIR", help="导出 Markdown/HTML/JSON 报告到指定目录")
    p.add_argument("--elevate", action="store_true", help="以管理员身份重新启动")
    p.add_argument("--selftest", action="store_true", help="运行内置自检")
    p.add_argument("--no-gui", action="store_true", help="不启动图形界面")
    p.add_argument("--version", action="store_true", help="显示版本")
    return p.parse_args(argv)


def _banner():
    print("=" * 68)
    print(f"  {APP_TITLE}  v{APP_VERSION}")
    print("=" * 68)


def cmd_scan(args) -> int:
    from sfguard import report
    from sfguard.scanner import SEVERITY_LABEL, Scanner
    from sfguard.util import Logger, is_admin, report_dir

    _banner()
    print(f"  管理员权限：{'是' if is_admin() else '否（仅可体检，修复需提权）'}")
    print("-" * 68)
    logger = Logger(echo=True)
    scanner = Scanner(logger)
    result = scanner.run(quick=args.quick)

    print("-" * 68)
    print(f"  安全评分：{result.score}/100（{result.level}）")
    print(f"  严重 {result.summary['critical']} · 高危 {result.summary['high']} · "
          f"中危 {result.summary['medium']} · 低危 {result.summary['low']} · 提示 {result.summary['info']}")
    print("-" * 68)
    if result.findings:
        for f in result.findings:
            print(f"  [{SEVERITY_LABEL.get(f.severity, f.severity)}] ({f.category}) {f.title}")
            print(f"        {f.detail[:150]}")
            if f.evidence:
                first = f.evidence.splitlines()[0]
                print(f"        {first[:150]}")
    else:
        print("  ✅ 未发现异常。")

    paths = {}
    if args.report or args.json:
        if args.report:
            os.makedirs(args.report, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            base = os.path.join(args.report, f"安全检查报告_{stamp}")
            with open(base + ".md", "w", encoding="utf-8") as f:
                f.write(report.build_markdown(result))
            with open(base + ".html", "w", encoding="utf-8") as f:
                f.write(report.build_html(result))
            with open(base + ".json", "w", encoding="utf-8") as f:
                import json

                json.dump(report.build_json(result), f, ensure_ascii=False, indent=2)
            paths.update({"md": base + ".md", "html": base + ".html", "json": base + ".json"})
        if args.json:
            import json

            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report.build_json(result), f, ensure_ascii=False, indent=2)
            paths["json"] = args.json
        for k, v in paths.items():
            print(f"  报告（{k}）：{v}")
    if result.findings:
        print(f"\n  提示：使用 --fix 自动处置，或在图形界面中点击「一键修复」。")
    return 0 if result.score >= 80 else 2


def cmd_fix(args) -> int:
    from sfguard.fixer import Fixer
    from sfguard.report import build_markdown, save_reports
    from sfguard.scanner import SEVERITY_LABEL, Scanner
    from sfguard.util import Logger, is_admin, elevate

    _banner()
    if not is_admin():
        print("  ✗ 修复需要管理员权限，正在请求提权……")
        if elevate(list(sys.argv[1:])):
            return 0
        print("  ✗ 未获得管理员权限，已退出。")
        return 1

    logger = Logger(echo=True)
    print("  [1/3] 体检中……")
    result = Scanner(logger).run(quick=args.quick)
    targets = result.fixable
    if not targets:
        print("  ✓ 没有需要修复的问题。")
        save_reports(result)
        return 0
    print(f"  [2/3] 开始修复 {len(targets)} 项……")
    outcomes = Fixer(logger).fix(targets)
    ok = sum(1 for o in outcomes if o.ok)
    print(f"  [3/3] 修复完成：成功 {ok} / {len(outcomes)}，复检中……")
    after = Scanner(logger).run(quick=True)
    print(f"  复检评分：{after.score}/100（{after.level}），剩余问题 {len(after.findings)} 项")
    paths = save_reports(after, outcomes)
    print(f"  报告：{paths['markdown']}")
    return 0 if after.score >= 80 else 2


def cmd_selftest(args) -> int:
    from sfguard import ioc
    from sfguard.report import build_html, build_json, build_markdown
    from sfguard.scanner import (
        Finding,
        ScanResult,
        _dangerous_exclusion,
        _first_exe,
        Scanner,
    )
    from sfguard.util import Logger, quarantine, sha256_file

    _banner()
    failures = []

    def check(name, cond, detail=""):
        print(f"  {'✅' if cond else '❌'} {name}" + (f"  ({detail})" if detail and not cond else ""))
        if not cond:
            failures.append(name)

    # 1. IoC 数据库
    bad = [h for h in ioc.KNOWN_HASHES if len(h) != 64 or any(c not in "0123456789abcdef" for c in h)]
    check("IoC 哈希格式", not bad, str(bad))

    # 2. 解析辅助函数
    check("解析启动命令行", _first_exe('"C:\\a b\\x.exe" -arg') .lower().endswith("x.exe"))
    check("危险排除项识别", _dangerous_exclusion("C:\\") and not _dangerous_exclusion("C:\\Tools\\ok"))

    s = Scanner(Logger(echo=False))
    xml = ("<Task><Triggers><TimeTrigger><Repetition><Interval>PT5M</Interval></Repetition>"
           "</TimeTrigger></Triggers><Actions><Exec><Command>C:\\Users\\a\\AppData\\Roaming\\"
           "Microsoft\\Windows\\Caches\\1C212048\\NtSvcF753.exe</Command></Exec></Actions></Task>")
    check("计划任务周期解析", s._xml_interval_minutes(xml) == 5)
    check("计划任务 IoC 命中", bool(s._task_xml_hits(xml)))

    # 3. 隔离区（沙箱）
    tmp = tempfile.mkdtemp(prefix="sfguard-test-")
    victim = os.path.join(tmp, "NtSvcF753.exe")
    with open(victim, "wb") as f:
        f.write(b"MZ-fake-test-payload")
    digest = sha256_file(victim)
    ok, dest = quarantine(victim, "自检样本", Logger(echo=False))
    check("文件隔离", ok and not os.path.exists(victim) and os.path.exists(dest), dest)
    check("隔离哈希记录", bool(digest))

    # 4. 沙箱检出：把用户目录重定向到临时沙箱，验证文件层能否抓到木马目录结构
    sandbox = tempfile.mkdtemp(prefix="sfguard-sandbox-")
    keys = ("LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "TEMP")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        cache = os.path.join(sandbox, "Local", r"Microsoft\Windows\Caches\1C212048")
        os.makedirs(cache, exist_ok=True)
        payload = os.path.join(cache, "NtSvcF753.exe")
        with open(payload, "wb") as f:
            f.write(b"MZ" + b"\x00" * 4096)
        with open(os.path.join(cache, "config.src"), "wb") as f:
            f.write(b"\x01\x02test")
        with open(os.path.join(cache, ".o"), "w", encoding="utf-8") as f:
            f.write("Running")
        os.environ["LOCALAPPDATA"] = os.path.join(sandbox, "Local")
        os.environ["APPDATA"] = os.path.join(sandbox, "Roaming")
        os.environ["PROGRAMDATA"] = os.path.join(sandbox, "ProgramData")
        os.environ["TEMP"] = os.path.join(sandbox, "Temp")
        demo = Scanner(Logger(echo=False))
        demo.check_files()
        titles = [f.title for f in demo.result.findings]
        check("沙箱检出木马目录", any("1C212048" in t for t in titles), str(titles)[:200])
        check("沙箱检出可疑载荷", any("可疑文件" in t for t in titles), str(titles)[:200])
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # 5. 修复动作冒烟测试（只做无害操作：结束自己起的临时进程、增删 HKCU 测试值）
    import subprocess

    from sfguard.fixer import Fixer
    from sfguard.util import Logger as _Logger

    dummy = subprocess.Popen(["cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul"],
                             creationflags=0x08000000)
    fixer = Fixer(_Logger(echo=False))
    ok, msg = fixer.do_kill_process({"pid": dummy.pid})
    check("终止进程动作", ok, msg)

    import winreg

    test_key = r"Software\SFguardSelfTest"
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, test_key, 0, winreg.KEY_WRITE) as k:
        winreg.SetValueEx(k, "TestRun", 0, winreg.REG_SZ, "C:\\fake\\path.exe")
    ok, msg = fixer.do_delete_run_value({"hive": "HKCU", "sub": test_key,
                                         "name": "TestRun", "value": "C:\\fake\\path.exe"})
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key)
    except Exception:
        pass
    check("删除启动项动作", ok, msg)
    check("修复动作注册", all(hasattr(fixer, a) for a in (
        "do_clean_defender_policy", "do_restore_uac", "do_clean_hosts",
        "do_quarantine_path", "do_delete_task", "do_repair_defender",
        "do_reset_proxy", "do_disable_service")))

    # 5b. 哈希命中路径（把测试样本的哈希临时注入特征库）
    sample_dir = tempfile.mkdtemp(prefix="sfguard-hash-")
    sample = os.path.join(sample_dir, "NtSvcF753.exe")
    with open(sample, "wb") as f:
        f.write(b"MZ-simulated-known-bad")
    sample_hash = sha256_file(sample) or ""
    ioc.KNOWN_HASHES[sample_hash] = ("NtSvcF753.exe", "自检注入的测试哈希")
    try:
        hs = Scanner(Logger(echo=False))
        hs._inspect_file(sample)
        check("哈希命中检出", any("已知恶意样本" in f.title for f in hs.result.findings),
              str([f.title for f in hs.result.findings])[:150])
    finally:
        ioc.KNOWN_HASHES.pop(sample_hash, None)

    # 6. 报告生成
    result = ScanResult()
    result.findings = [
        Finding("t1", "critical", "进程", "测试严重项", "用于自检的报告内容", "证据行", True, "kill_process"),
        Finding("t2", "info", "环境", "测试提示项", "提示信息"),
    ]
    result.env_checks = []
    result.summary = {"score": 70, "level": "危险", "critical": 1, "high": 0,
                      "medium": 0, "low": 0, "info": 1}
    result.stats = {"进程数": 1, "计划任务数": 1, "服务数": 1, "扫描文件数": 1,
                    "计算哈希文件数": 1, "耗时秒": 0.1}
    md = build_markdown(result)
    html_text = build_html(result)
    js = build_json(result)
    check("Markdown 报告", "系统安全检查报告" in md and "测试严重项" in md)
    check("HTML 报告", html_text.startswith("<!DOCTYPE html>") and "测试严重项" in html_text)
    check("JSON 报告", js["score"] == 70 and len(js["findings"]) == 2)

    # 7. 评分模型
    check("评分模型", ScanResult().score == 100)

    # 8. 依赖完整性
    try:
        import tkinter  # noqa: F401

        check("Tkinter 可用", True)
    except Exception as exc:
        check("Tkinter 可用", False, str(exc))

    print("-" * 68)
    # 清理自检产生的临时文件，避免污染后续正常体检
    import shutil as _shutil

    for name in ("tmp", "sandbox", "sample_dir"):
        d = locals().get(name)
        if d:
            try:
                _shutil.rmtree(d, ignore_errors=True)
            except Exception:
                pass
    if failures:
        print(f"  自检失败 {len(failures)} 项：{', '.join(failures)}")
        return 1
    print("  自检全部通过。")
    return 0


def _init_stdio() -> None:
    """冻结成 exe 后控制台默认是本地代码页，强制 UTF-8 避免中文报错。"""
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass


def main(argv=None) -> int:
    _init_stdio()
    args = parse_args(argv)
    if args.version:
        print(f"{APP_TITLE} v{APP_VERSION}")
        return 0
    if args.elevate:
        from sfguard.util import elevate

        return 0 if elevate([a for a in sys.argv[1:] if a != "--elevate"]) else 1
    if args.selftest:
        return cmd_selftest(args)
    if args.fix:
        return cmd_fix(args)
    if args.scan:
        return cmd_scan(args)
    if args.no_gui:
        return cmd_scan(args)
    try:
        from sfguard.gui import run_gui

        run_gui()
        return 0
    except Exception as exc:
        print(f"图形界面启动失败：{exc}", file=sys.stderr)
        print("已切换到命令行体检模式。", file=sys.stderr)
        return cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
