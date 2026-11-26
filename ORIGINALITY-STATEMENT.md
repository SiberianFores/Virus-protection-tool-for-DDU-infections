# Statement of Originality

**Software name**: SFguard
**Version**: V1.0.0
**Developer / Copyright holder**: SiberianFores
**Release date**: 26 November 2026
**Contact**: 781028500@qq.com

---

## 1. Declaration of originality

1. This software — the executable `SFguard.exe`, all source code, the user-interface design,
   the icon, all user-facing texts, report templates and documentation — was conceived,
   designed and developed independently by **SiberianFores**.
2. No source code, user interface, icon or documentation of any third-party software was
   copied, decompiled, modified or otherwise reused. The software contains no code
   fragments taken from commercial anti-virus products, open-source security projects or
   any other third party's work.
3. All source code under `源码/` (15 files, 4,024 lines of Python / PowerShell) is original
   work and can be built reproducibly with `源码/build.ps1`.
4. The interface layout, the application icon (drawn programmatically by
   `源码/make_icon.py`), all texts and all documents are original creations.
5. The malware indicators embedded in the software (file SHA-256 values, drop paths,
   registry keys, scheduled-task names, ports, domains) come from on-site forensic work on
   the incident and were cross-checked against public threat intelligence (public VirusTotal
   records, Microsoft threat naming, etc.). Such content is factual data and does not
   constitute reproduction of another party's work.
6. The name `SFguard`, the icon and all interface texts use no third-party trademark or
   protected trade dress.

## 2. Third-party components

The following open-source components are used at runtime or build time, under their own
licences, unmodified:

| Component | Purpose | Licence |
|---|---|---|
| Python 3.12 | Runtime | PSF License |
| Tcl/Tk 8.6 | GUI toolkit | BSD-style License |
| PyInstaller 6.x | Single-file packaging | GPL 2.0 with bootloader exception |
| Pillow | Icon generation | HPND License |

When distributed as a single executable, the package embeds unmodified copies of these
runtimes; all rights in them remain with their respective authors.

## 3. Version fingerprint

| Item | Value |
|---|---|
| Version | V1.0.0 |
| Release date | 2026-11-26 |
| Source size | 4,024 lines (`.py` + `.ps1`), 15 files |
| `SFguard.exe` SHA-256 | `5B7F7303F8AB71A42E5FE69A191E25B5DBF770E5DC30AD0B7E2B78C82215C63A` |
| Source-tree fingerprint | `B7138469262A60B81EA4F50FF3CA657F5CF0B7BB4D83FD8B0C499C141D8815A7` |
| Full checksums | see `校验和.txt` |

> The source-tree fingerprint is computed by sorting every file under `源码/` by relative
> path, taking each file's SHA-256, joining the lines `relative/path:SHA-256`, then hashing
> that joined text once more with SHA-256 (upper-case hex). Any code change alters it.

## 4. Important: the malware is still active

**This tool targets a new malware family first observed on 24 November 2026. The family is
highly active and keeps producing new variants — the payload hash changed within two days.
Detection signatures may lag, and this tool may not recognise the newest variants.**

If a scan looks suspicious but no known indicator matches, upload the sample to VirusTotal
for review, or report it through the channels listed in `中毒自查与上报指南.md`.

## 5. Disclaimer

1. This software is provided **"as is"**, without warranty of any kind, express or implied.
2. **The developer accepts no responsibility for any consequences arising from the use of
   this software.** Back up your important data before use and **use it with caution**.
3. **The developer accepts no liability for any modifications to this software
   (including the developer's own subsequent updates and modifications made by third
   parties), nor for their consequences.**
4. The software modifies system settings (including but not limited to security-product
   configuration, UAC, scheduled tasks, startup entries, services, hosts, proxy and firewall
   rules) and moves files judged malicious into quarantine. Automated judgement may produce
   false positives and false negatives.
5. The software inspects only the local machine and repairs it locally. It does not collect
   or upload data and takes no action against any third-party host.
6. If a system has been compromised at administrator or kernel level, no user-mode tool can
   guarantee complete removal; reinstalling the system and changing passwords is the most
   reliable remedy.
7. Using this software constitutes acceptance of the terms above.

---

**Developer**: SiberianFores
**Release date**: 26 November 2026
**Contact**: 781028500@qq.com

> 中文版本：[`原创声明.md`](原创声明.md)
