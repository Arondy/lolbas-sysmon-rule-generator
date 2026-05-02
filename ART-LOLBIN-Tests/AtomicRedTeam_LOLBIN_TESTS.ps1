param(
    [switch]$RunAll,
    [switch]$ListOnly
)

$Script:Config = @{
    AtomicRootFolderName    = "AtomicRedTeam"
    AtomicZipUrl            = "https://github.com/redcanaryco/atomic-red-team/archive/refs/heads/master.zip"
    AtomicYamlPatterns      = @("T*.yaml", "T*.yml")
    TargetPlatform          = "windows"
    LolbinNameKeywords      = @("LOL", "Lolbin", "Lolbas", "Proxy Execution", "Signed Binary")
    LolbinTechniquePrefixes = @("T1218", "T1059", "T1105", "T1547", "T1562", "T1055")
    PythonRunConfigRelativePath = "ART_lolbin_tests\config_generated.json"
    PythonOutputJsonRelativePath = "ART_lolbin_tests\results\run_result.json"
    PythonSysmonChannel = "Microsoft-Windows-Sysmon/Operational"
    PythonMarkerTimeoutSeconds = 20
    PythonMarkerPollIntervalSeconds = 0.5
    PythonMarkerScanLimit = 300
    PythonQueryBatchSize = 128
    PythonGraceSeconds = 0
    PythonAtomicTimeoutSeconds = 60
    PythonRunCleanup = $true
}

function Ensure-PsGalleryTrusted {
    $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue

    if (-not $psGallery) {
        Write-Host "PSGallery не найден, пробуем зарегистрировать по умолчанию..." -ForegroundColor Yellow
        try {
            Register-PSRepository -Default -ErrorAction Stop
            $psGallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Не удалось зарегистрировать PSGallery: $_" -ForegroundColor Yellow
        }
    }

    if ($psGallery -and $psGallery.InstallationPolicy -ne "Trusted") {
        Write-Host "Делаем PSGallery доверенным..." -ForegroundColor Yellow
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
}

function Ensure-InvokeAtomicModule {
    if (-not (Get-Module -ListAvailable -Name Invoke-AtomicRedTeam)) {
        Write-Host "Устанавливаем Invoke-AtomicRedTeam..." -ForegroundColor Yellow
        Install-Module -Name Invoke-AtomicRedTeam, powershell-yaml -Scope CurrentUser -Force -AllowClobber
        Write-Host "Модуль установлен" -ForegroundColor Green
    }
}

function Remove-AtomicZipArtifacts {
    param(
        [Parameter(Mandatory)]
        [string]$AtomicRoot
    )

    foreach ($zipName in @("atomic-red-team.zip", "atomic-red-team-master.zip")) {
        $zipPath = Join-Path -Path $AtomicRoot -ChildPath $zipName
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Resolve-AtomicsPath {
    param(
        [Parameter(Mandatory)]
        [string]$AtomicRoot
    )

    if (-not (Test-Path $AtomicRoot)) {
        return $null
    }

    $candidates = New-Object System.Collections.Generic.List[string]
    $candidates.Add((Join-Path -Path $AtomicRoot -ChildPath "atomics"))

    Get-ChildItem -Path $AtomicRoot -Directory -ErrorAction SilentlyContinue |
        ForEach-Object {
            $candidates.Add((Join-Path -Path $_.FullName -ChildPath "atomics"))
        }

    $existing = $candidates | Where-Object { Test-Path $_ } | Sort-Object -Unique
    if (-not $existing) {
        return $null
    }

    $existing |
        ForEach-Object {
            [PSCustomObject]@{
                Path     = $_
                YamlCount = @(Get-ChildItem -Path $_ -Recurse -File `
                    -Include $Script:Config.AtomicYamlPatterns -ErrorAction SilentlyContinue).Count
            }
        } |
        Sort-Object -Property @{ Expression = "YamlCount"; Descending = $true }, Path |
        Select-Object -First 1 -ExpandProperty Path
}

function Download-AtomicRedTeam {
    param(
        [Parameter(Mandatory)]
        [string]$AtomicRoot
    )

    Write-Host "Скачиваем Atomic Red Team (ZIP)..." -ForegroundColor Yellow

    $zipPath = Join-Path -Path $AtomicRoot -ChildPath "atomic-red-team.zip"

    try {
        New-Item -Path $AtomicRoot -ItemType Directory -Force | Out-Null
        Invoke-WebRequest -Uri $Script:Config.AtomicZipUrl `
            -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        Expand-Archive -Path $zipPath -DestinationPath $AtomicRoot -Force -ErrorAction Stop
    }
    catch {
        Write-Host "Не удалось скачать/распаковать Atomic Red Team в рабочую директорию: $_" -ForegroundColor Red
        return $null
    }
    finally {
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        }
    }

    $atomicsPath = Resolve-AtomicsPath -AtomicRoot $AtomicRoot
    if (-not $atomicsPath) {
        Write-Host "Репозиторий распакован, но папка atomics не найдена." -ForegroundColor Red
        return $null
    }

    Write-Host "Репозиторий скачан и распакован. Используем: $atomicsPath" -ForegroundColor Green
    $atomicsPath
}

function Get-WindowsAtomicTechniques {
    param(
        [Parameter(Mandatory)]
        [string]$AtomicsPath
    )

    $yamlFiles = Get-ChildItem -Path $AtomicsPath -Recurse -File `
        -Include $Script:Config.AtomicYamlPatterns -ErrorAction SilentlyContinue

    if (-not $yamlFiles) {
        return @()
    }

    $results = foreach ($yamlFile in $yamlFiles) {
        try {
            $technique = Get-AtomicTechnique -Path $yamlFile.FullName -ErrorAction Stop
        }
        catch {
            continue
        }

        $windowsTestNumbers = @()
        for ($i = 0; $i -lt $technique.atomic_tests.Count; $i++) {
            if ($technique.atomic_tests[$i].supported_platforms -contains $Script:Config.TargetPlatform) {
                $windowsTestNumbers += [string]($i + 1)
            }
        }

        if ($windowsTestNumbers.Count -eq 0) {
            continue
        }

        [PSCustomObject]@{
            TechniqueID        = Split-Path -Path $yamlFile.DirectoryName -Leaf
            AttackTechnique    = (@($technique.attack_technique) -join ", ")
            Name               = $technique.display_name
            WindowsTestNumbers = $windowsTestNumbers
            WindowsTestsCount  = $windowsTestNumbers.Count
        }
    }

    @($results)
}

function Test-IsLolbinTechnique {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Technique
    )

    foreach ($keyword in $Script:Config.LolbinNameKeywords) {
        if ($Technique.Name -like "*$keyword*") {
            return $true
        }
    }

    foreach ($prefix in $Script:Config.LolbinTechniquePrefixes) {
        if ($Technique.TechniqueID -like "$prefix*" -or $Technique.AttackTechnique -like "*$prefix*") {
            return $true
        }
    }

    return $false
}

function Select-LolbinTechniques {
    param(
        [Parameter(Mandatory)]
        [array]$Techniques
    )

    @(
        $Techniques |
            Where-Object { Test-IsLolbinTechnique -Technique $_ } |
            Sort-Object -Property TechniqueID -Unique
    )
}

function Export-PythonRunConfig {
    param(
        [Parameter(Mandatory)]
        [string]$AtomicsPath,
        [Parameter(Mandatory)]
        [array]$LolbinTechniques
    )

    $rootPath = (Get-Location).Path
    $runConfigPath = Join-Path -Path $rootPath -ChildPath $Script:Config.PythonRunConfigRelativePath
    $outputJsonPath = Join-Path -Path $rootPath -ChildPath $Script:Config.PythonOutputJsonRelativePath

    $tests = @(
        $LolbinTechniques | ForEach-Object {
            $testNumbers = @($_.WindowsTestNumbers | ForEach-Object { [int]$_ })
            [ordered]@{
                technique_id = $_.TechniqueID
                test_numbers = $testNumbers
                repeat = 1
            }
        }
    )

    $runConfig = [ordered]@{
        atomics_path = $AtomicsPath
        output_json_path = $outputJsonPath
        sysmon_channel = $Script:Config.PythonSysmonChannel
        marker_timeout_seconds = $Script:Config.PythonMarkerTimeoutSeconds
        marker_poll_interval_seconds = $Script:Config.PythonMarkerPollIntervalSeconds
        marker_scan_limit = $Script:Config.PythonMarkerScanLimit
        query_batch_size = $Script:Config.PythonQueryBatchSize
        grace_seconds = $Script:Config.PythonGraceSeconds
        atomic_timeout_seconds = $Script:Config.PythonAtomicTimeoutSeconds
        run_cleanup = $Script:Config.PythonRunCleanup
        tests = $tests
    }

    $configDir = Split-Path -Path $runConfigPath -Parent
    if ($configDir -and -not (Test-Path $configDir)) {
        New-Item -Path $configDir -ItemType Directory -Force | Out-Null
    }

    $runConfig | ConvertTo-Json -Depth 8 | Set-Content -Path $runConfigPath -Encoding UTF8
    Write-Host "Сгенерирован конфиг запуска Python: $runConfigPath" -ForegroundColor Green
}

function Show-LolbinSummary {
    param(
        [Parameter(Mandatory)]
        [array]$LolbinTechniques
    )

    Write-Host "`nНайдено $($lolbinTechniques.Count) LOLBin-техник:`n" -ForegroundColor Green

    $lolbinTechniques | ForEach-Object {
        [PSCustomObject]@{
            TechniqueID = $_.TechniqueID
            Name        = $_.Name
            Tests       = $_.WindowsTestsCount
        }
    } | Format-Table -AutoSize
}

function Invoke-LolbinTests {
    param(
        [Parameter(Mandatory)]
        [array]$LolbinTechniques
    )

    Write-Host "`nЗапуск всех LOLBin-тестов..." -ForegroundColor Magenta

    foreach ($tech in $lolbinTechniques) {
        Write-Host "`n[$($tech.TechniqueID)] $($tech.Name)" -ForegroundColor Cyan
        try {
            Invoke-AtomicTest $tech.TechniqueID -TestNumbers $tech.WindowsTestNumbers
            Invoke-AtomicTest $tech.TechniqueID -TestNumbers $tech.WindowsTestNumbers -Cleanup
        }
        catch {
            Write-Host "  Ошибка при запуске $($tech.TechniqueID): $_" -ForegroundColor Red
        }
    }

    Write-Host "`nВсе LOLBin-тесты завершены!" -ForegroundColor Green
}

Write-Host "Atomic Red Team LOLBin Tester" -ForegroundColor Cyan

Ensure-PsGalleryTrusted
Ensure-InvokeAtomicModule
Import-Module Invoke-AtomicRedTeam -Force

$atomicRoot = Join-Path -Path (Get-Location) -ChildPath $Script:Config.AtomicRootFolderName
Remove-AtomicZipArtifacts -AtomicRoot $atomicRoot

$atomicsPath = Resolve-AtomicsPath -AtomicRoot $atomicRoot
if (-not $atomicsPath) {
    $atomicsPath = Download-AtomicRedTeam -AtomicRoot $atomicRoot
    if (-not $atomicsPath) {
        exit 1
    }
}
else {
    Write-Host "Atomic Red Team уже существует. Используем: $atomicsPath" -ForegroundColor Green
}

$PSDefaultParameterValues = @{
    "Invoke-AtomicTest:PathToAtomicsFolder" = $atomicsPath
}

Write-Host "`nПоиск LOLBin / LOLBAS техник..." -ForegroundColor Cyan

$allTechniques = Get-WindowsAtomicTechniques -AtomicsPath $atomicsPath

if ($allTechniques.Count -eq 0) {
    Write-Host "Техники с Windows-тестами не найдены!" -ForegroundColor Red
    exit 1
}

$lolbinTechniques = Select-LolbinTechniques -Techniques $allTechniques

if ($lolbinTechniques.Count -eq 0) {
    Write-Host "LOLBin-тесты не найдены!" -ForegroundColor Red
    exit 1
}

Export-PythonRunConfig -AtomicsPath $atomicsPath -LolbinTechniques $lolbinTechniques

Show-LolbinSummary -LolbinTechniques $lolbinTechniques

if ($ListOnly) {
    Write-Host "`nРежим ListOnly — тесты не запущены." -ForegroundColor Yellow
    exit 0
}

$shouldRun = $RunAll
if (-not $shouldRun) {
    $answer = Read-Host "`nЗапустить ВСЕ найденные LOLBin-тесты? (Y/N)"
    $shouldRun = ($answer -eq "Y" -or $answer -eq "y")
}

if ($shouldRun) {
    Invoke-LolbinTests -LolbinTechniques $lolbinTechniques
}
else {
    Write-Host "Запуск отменён." -ForegroundColor Yellow
}

Write-Host "`nГотово. Теперь можно собирать метрики Sysmon." -ForegroundColor Cyan
