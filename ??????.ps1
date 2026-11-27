# 重新计算发布校验信息（版本号 / 行数 / 源码树指纹 / exe 哈希）
# 用法： powershell -ExecutionPolicy Bypass -File 生成校验信息.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = Join-Path $root "源码"
$exe = Join-Path $root "SFguard.exe"

$files = Get-ChildItem $src -Recurse -File | Where-Object { $_.FullName -notmatch '__pycache__' } | Sort-Object FullName

$loc = 0
$entries = @()
foreach ($f in $files) {
    $rel = $f.FullName.Substring($src.Length + 1).Replace('\', '/')
    $hash = (Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower()
    $entries += ("{0}:{1}" -f $rel, $hash)
    if ($rel -match '\.(py|ps1)$') {
        $loc += [System.IO.File]::ReadAllLines($f.FullName).Count
    }
}

$sha = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes(($entries -join "`n"))
$tree = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("X2") }) -join ''

Write-Host "版本号            : V1.0.1"
Write-Host "源程序行数        : $loc"
Write-Host "源码文件数        : $($files.Count)"
if (Test-Path $exe) {
    Write-Host "SFguard.exe SHA256: $((Get-FileHash $exe -Algorithm SHA256).Hash)"
}
Write-Host "源码树指纹        : $tree"
Write-Host ""
Write-Host "将上面的行数与指纹同步到 原创声明.md / ORIGINALITY-STATEMENT.md 后，"
Write-Host "再重新生成 校验和.txt 并打包。"
