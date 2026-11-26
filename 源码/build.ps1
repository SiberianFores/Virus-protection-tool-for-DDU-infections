# SFguard 打包脚本（PyInstaller 单文件 + 完整性级别修正）
# 用法： powershell -ExecutionPolicy Bypass -File build.ps1
param(
  [string]$Python = "python",
  [string]$OutDir = "."
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

Write-Host "[1/4] 生成图标与自检 ..."
& $Python make_icon.py
if ($LASTEXITCODE -ne 0) { throw "图标生成失败" }
& $Python main.py --selftest
if ($LASTEXITCODE -ne 0) { throw "自检失败，终止打包" }

Write-Host "[2/4] PyInstaller 打包 ..."
& $Python -m PyInstaller --noconfirm --clean --onefile --console `
  --name SFguard `
  --icon "$root\assets\app.ico" `
  --version-file "$root\version_info.txt" `
  --distpath $OutDir `
  --workpath "..\_build" `
  --specpath "..\_build" `
  "$root\main.py"
if ($LASTEXITCODE -ne 0) { throw "打包失败" }

$exe = Join-Path (Resolve-Path $OutDir) "SFguard.exe"
if (-not (Test-Path $exe)) { throw "未找到 $exe" }

Write-Host "[3/4] 修正完整性级别（若工作目录带 Low 完整性标签，单文件程序会解包失败）..."
icacls $exe /setintegritylevel Medium | Out-Null

Write-Host "[4/4] 冒烟测试 ..."
& $exe --selftest
if ($LASTEXITCODE -ne 0) { throw "打包产物自检失败" }

$item = Get-Item $exe
Write-Host ("完成: {0}  ({1:N1} MB)" -f $item.FullName, ($item.Length / 1MB))
