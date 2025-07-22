# Функция для проверки прав администратора
function Is-Admin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

# Функция для поиска файла с учетными данными на всех доступных дисках
function Find-CredentialsFile {
    $drives = Get-PSDrive -PSProvider FileSystem | Select-Object -ExpandProperty Root
    foreach ($drive in $drives) {
        $filePath = Join-Path $drive "start\admin_credentials.txt"
        if (Test-Path $filePath) {
            Write-Log "Файл найден: $filePath"
            return $filePath
        }
    }
    Write-Log "Файл с учетными данными не найден на доступных дисках."
    exit
}

# Функция для чтения учетных данных из файла
function Get-CredentialsFromFile {
    param (
        [string]$FilePath
    )
    try {
        $content = Get-Content -Path $FilePath -ErrorAction Stop
        $username = ($content | Where-Object { $_ -match '^Username=' }) -replace 'Username=', ''
        $password = ($content | Where-Object { $_ -match '^Password=' }) -replace 'Password=', ''

        if ([string]::IsNullOrWhiteSpace($username) -or [string]::IsNullOrWhiteSpace($password)) {
            Write-Log "Ошибка: Файл учетных данных имеет неверный формат."
            exit
        }

        Write-Log "Учетные данные успешно прочитаны."
        return @{
            Username = $username
            Password = $password
        }
    } catch {
        Write-Log "Ошибка при чтении файла учетных данных: $_"
        exit
    }
}

# Функция для записи логов в файл
function Write-Log {
    param (
        [string]$Message
    )
    $logFile = "$env:TEMP\driver_booster_log.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$timestamp] $Message"
    Write-Host $Message
}

# Проверяем, запущен ли скрипт с правами администратора
if (-not (Is-Admin)) {
    Write-Log "Скрипт не запущен с правами администратора. Ищу файл с учетными данными..."

    # Находим файл с учетными данными
    $credentialsFile = Find-CredentialsFile

    # Получаем учетные данные из файла
    $credentials = Get-CredentialsFromFile -FilePath $credentialsFile

    # Создаем защищенную строку пароля
    $securePassword = ConvertTo-SecureString $credentials.Password -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ($credentials.Username, $securePassword)

    # Определяем путь к текущему скрипту
    $scriptPath = $MyInvocation.MyCommand.Path

    # Перезапускаем скрипт с повышенными правами через промежуточный процесс
    try {
        Start-Process powershell.exe -Credential $credential -ArgumentList @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            "& { Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy Bypass', '-File', '$scriptPath') -Verb RunAs }"
        ) -ErrorAction Stop
        Write-Log "Скрипт успешно перезапущен с повышенными правами."
    } catch {
        Write-Log "Ошибка при перезапуске скрипта с повышенными правами: $_"
    }
    exit
}

# Отключаем защиту в реальном времени Windows Defender
try {
    Write-Log "Отключаю защиту в реальном времени Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Log "Защита в реальном времени ОТКЛЮЧЕНА."
} catch {
    Write-Log "Ошибка при отключении защиты в реальном времени: $_"
}

# Запускаем указанное приложение
$applicationPath = "\\nas\Distrib\main_distrib\IOBit Driver Booster Portable\IOBitDriverBoosterPortable.exe"
if (Test-Path $applicationPath) {
    try {
        Write-Log "Запускаю IObit Driver Booster Portable..."
        Start-Process $applicationPath -ErrorAction Stop
        Write-Log "Приложение успешно запущено."
    } catch {
        Write-Log "Ошибка при запуске приложения: $_"
    }
} else {
    Write-Log "Ошибка: Путь к приложению недействителен: $applicationPath"
}