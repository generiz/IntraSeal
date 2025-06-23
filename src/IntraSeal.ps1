<#
 ███████╗███╗   ██╗████████╗██████╗  █████╗ ███████╗ █████╗ ██╗     
 ██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔══██╗╚══███╔╝██╔══██╗██║     
 █████╗  ██╔██╗ ██║   ██║   ██████╔╝███████║  ███╔╝ ███████║██║     
 ██╔══╝  ██║╚██╗██║   ██║   ██╔═══╝ ██╔══██║ ███╔╝  ██╔══██║██║     
 ███████╗██║ ╚████║   ██║   ██║     ██║  ██║███████╗██║  ██║███████╗
 ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝
 IntraSeal Security Layer v1.1 - Internal QA Isolation Tool
 (c) 2025 Nicolás Pintos www.nicolaspintos.com - Restricted corporate utility
#>

Write-Host "██╗███╗   ██╗████████╗███████╗██████╗ ███████╗███████╗ █████╗ ██╗" -ForegroundColor Cyan
Write-Host "██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗██║" -ForegroundColor Cyan
Write-Host "██║██╔██╗ ██║   ██║   █████╗  ██████╔╝███████╗█████╗  ███████║██║" -ForegroundColor Cyan
Write-Host "██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗╚════██║██╔══╝  ██╔══██║██║" -ForegroundColor Cyan
Write-Host "██║██║ ╚████║   ██║   ███████╗██║  ██║███████║███████╗██║  ██║███████╗" -ForegroundColor Cyan
Write-Host "╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "     IntraSeal v1.1 - INTERNAL SECURITY FRAMEWORK" -ForegroundColor DarkCyan
Write-Host "     (c) 2025 Nicolás Pintos · www.nicolaspintos.com" -ForegroundColor DarkCyan
Write-Host ""

param (
    [string]$TargetFolder = (Get-Location).Path
)

Write-Host "`n🛡️ IntraSeal - Protección interna activada en: $TargetFolder" -ForegroundColor Cyan

function Bloquear-ExeEnFirewall {
    param([string]$exePath)
    $ruleName = "IntraSeal_" + (Split-Path $exePath -Leaf)
    if (-not (Get-NetFirewallApplicationFilter | Where-Object { $_.Program -eq $exePath })) {
        New-NetFirewallRule -DisplayName $ruleName `
            -Direction Outbound `
            -Program $exePath `
            -Action Block `
            -Profile Any `
            -Enabled True `
            -ErrorAction SilentlyContinue
    }
}

function Agregar-ExclusionDefender {
    param([string]$folderPath)
    Add-MpPreference -ExclusionPath $folderPath -ErrorAction SilentlyContinue
}

function Detectar-Antivirus {
    return Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct | Select-Object displayName
}

$executables = Get-ChildItem -Path $TargetFolder -Recurse -Include *.exe -File -ErrorAction SilentlyContinue
Write-Host "`n🔍 Ejecutables encontrados: $($executables.Count)`n" -ForegroundColor Yellow

foreach ($exe in $executables) {
    Write-Host "🚫 Bloqueando salida: $($exe.FullName)" -ForegroundColor DarkGreen
    Bloquear-ExeEnFirewall -exePath $exe.FullName
}

$av = Detectar-Antivirus
$defender = $av | Where-Object { $_.displayName -like "*Defender*" }

if ($defender) {
    Write-Host "`n✅ Windows Defender detectado. Protegiendo carpeta..." -ForegroundColor Green
    Agregar-ExclusionDefender -folderPath $TargetFolder
    Write-Host "🛡️ Carpeta excluida correctamente de Defender."
} else {
    Write-Host "`n⚠️ Windows Defender no está activo." -ForegroundColor Red
    foreach ($a in $av) {
        Write-Host "🔎 Antivirus detectado: $($a.displayName)"
    }
    Write-Host "`n📌 Sugerencia: Agregue manualmente esta carpeta como exclusión de su antivirus: `n$TargetFolder" -ForegroundColor DarkYellow
}

try {
    $Desktop = [Environment]::GetFolderPath("Desktop")
    $LogPath = Join-Path $Desktop "IntraSeal_log.txt"
    $timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $logLines = @()
    $logLines += "$timestamp 🔒 IntraSeal activado en: $TargetFolder"
    $logLines += "$timestamp 🧩 Ejecutables encontrados: $($executables.Count)"
    foreach ($exe in $executables) {
        $logLines += "$timestamp 🚫 Bloqueado: $($exe.FullName)"
    }
    if ($defender) {
        $logLines += "$timestamp ✅ Defender activo. Carpeta excluida: $TargetFolder"
    } else {
        $logLines += "$timestamp ⚠️ Defender no detectado."
        foreach ($a in $av) {
            $logLines += "$timestamp 🔍 Otro AV detectado: $($a.displayName)"
        }
    }
    $logLines += "$timestamp ✔️ Proceso completado correctamente."
    [System.IO.File]::WriteAllLines($LogPath, $logLines, [System.Text.Encoding]::UTF8)
    Write-Host "`n📝 Log guardado en: $LogPath" -ForegroundColor Gray
} catch {
    Write-Host "`n⚠️ No se pudo guardar el log en el escritorio." -ForegroundColor DarkRed
}

Add-Type -AssemblyName PresentationFramework
$popup = [System.Windows.MessageBox]::Show("¿Deseás visitar la web del autor?
www.nicolaspintos.com", "IntraSeal", "YesNo", "Question")
if ($popup -eq "Yes") {
    Start-Process "https://www.nicolaspintos.com"
}
