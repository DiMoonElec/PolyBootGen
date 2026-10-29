param(
  [Parameter(Mandatory = $true)][string]$AssemblyPath,
  [string]$FixturesPath
)

$ErrorActionPreference = 'Stop'
if (-not $FixturesPath) {
  $FixturesPath = Join-Path $PSScriptRoot '..\artifacts\test-fixtures'
}
Add-Type -Path (Resolve-Path -LiteralPath $AssemblyPath).Path
$fixtures = (Resolve-Path -LiteralPath $FixturesPath).Path
$cases = @(
  @{ Name = 'v1.xbin'; Format = 1; Slaves = 0 },
  @{ Name = 'single.xbin'; Format = 2; Slaves = 0 },
  @{ Name = 'complex.xbin'; Format = 2; Slaves = 1 }
)
foreach ($case in $cases) {
  try {
    $parsed = [PolyBootCore.UpdateFile.Parser.FirmwareUpdateParser]::Parse((Join-Path $fixtures $case.Name))
  } catch {
    throw ('MCUUpdater must support HASH instead of VER for FORMAT=2. Failed to parse ' + $case.Name + ': ' + $_.Exception.Message)
  }
  if ($parsed.FormatVersion -ne $case.Format -or $parsed.SlaveFirmwares.Count -ne $case.Slaves) {
    throw ('Incorrect parsed structure: ' + $case.Name)
  }
  if ($case.Format -eq 2) {
    if ($parsed.RootFirmware.DeviceId -ne 'DEVICE; MAIN' -or
        [BitConverter]::ToString($parsed.RootFirmware.FirmwareHash).Replace('-', '') -ne 'AACB65E7C9055B105CF02C47024CDF79' -or
        -not ($parsed.Comments -contains 'ROOT ID="DEVICE; MAIN" VERSION=258.772.1286')) {
      throw ('Incorrect ROOT metadata: ' + $case.Name)
    }
    if ($case.Slaves -eq 1 -and ($parsed.SlaveFirmwares[0].DeviceId -ne 'SLAVE' -or
        [BitConverter]::ToString($parsed.SlaveFirmwares[0].FirmwareHash).Replace('-', '') -ne '039058C6F2C0CB492C533B0A4D14EF77' -or
        -not ($parsed.Comments -contains 'SLAVE ID="SLAVE" VERSION=9.8.7'))) {
      throw 'Incorrect SLAVE metadata'
    }
  }
  Write-Output ('PASS: MCUUpdater parser: ' + $case.Name)
}

# A change to the firmware HASH field must invalidate the container SHA256.
$tamperedPath = [System.IO.Path]::GetTempFileName()
try {
  $original = [IO.File]::ReadAllText((Join-Path $fixtures 'single.xbin'))
  $content = $original.Replace('HASH=AACB65E7C9055B105CF02C47024CDF79', 'HASH=AACB65E7C9055B105CF02C47024CDF78')
  if ($content -eq $original) { throw 'Test fixture does not contain the expected HASH' }
  [IO.File]::WriteAllText($tamperedPath, $content, [Text.Encoding]::ASCII)
  $rejected = $false
  try { [void][PolyBootCore.UpdateFile.Parser.FirmwareUpdateParser]::Parse($tamperedPath) }
  catch { $rejected = $true }
  if (-not $rejected) { throw 'MCUUpdater accepted a damaged package' }
  Write-Output 'PASS: MCUUpdater rejects modified metadata without a matching SHA256'
}
finally {
  Remove-Item -LiteralPath $tamperedPath
}
