$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$configPath = Join-Path $root "auth-config.json"
$iterations = 310000

function ConvertTo-PlainText {
  param([Security.SecureString]$SecureValue)

  $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)

  try {
    return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
  }
}

if (Test-Path $configPath) {
  $answer = Read-Host "Конфигурация уже существует. Перезаписать её? (да/нет)"

  if ($answer.Trim().ToLowerInvariant() -notin @("да", "д", "yes", "y")) {
    Write-Host "Настройка отменена."
    exit 0
  }
}

$username = (Read-Host "Логин").Trim()

if (-not $username -or $username.Length -gt 128) {
  throw "Логин должен содержать от 1 до 128 символов."
}

$securePassword = Read-Host "Пароль (минимум 12 символов)" -AsSecureString
$secureConfirmation = Read-Host "Повторите пароль" -AsSecureString
$password = ConvertTo-PlainText $securePassword
$confirmation = ConvertTo-PlainText $secureConfirmation

try {
  if ($password.Length -lt 12) {
    throw "Пароль должен содержать минимум 12 символов."
  }

  if (-not [string]::Equals($password, $confirmation, [StringComparison]::Ordinal)) {
    throw "Пароли не совпадают."
  }

  $salt = New-Object byte[] 16
  $sessionSecret = New-Object byte[] 32
  $random = [Security.Cryptography.RandomNumberGenerator]::Create()

  try {
    $random.GetBytes($salt)
    $random.GetBytes($sessionSecret)
  } finally {
    $random.Dispose()
  }

  $derive = [Security.Cryptography.Rfc2898DeriveBytes]::new(
    $password,
    $salt,
    $iterations,
    [Security.Cryptography.HashAlgorithmName]::SHA256
  )

  try {
    $passwordHash = $derive.GetBytes(32)
  } finally {
    $derive.Dispose()
  }

  $config = [ordered]@{
    version = 1
    username = $username
    password = [ordered]@{
      algorithm = "pbkdf2-sha256"
      iterations = $iterations
      salt = [Convert]::ToBase64String($salt)
      hash = [Convert]::ToBase64String($passwordHash)
    }
    sessionSecret = [Convert]::ToBase64String($sessionSecret)
  }

  $json = $config | ConvertTo-Json -Depth 4
  $utf8WithoutBom = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText($configPath, $json, $utf8WithoutBom)

  Write-Host "Авторизация настроена."
  Write-Host "Создан файл: $configPath"
  Write-Host "Теперь запустите build-exe.ps1 для сборки внутренней версии."
} finally {
  $password = $null
  $confirmation = $null
}
