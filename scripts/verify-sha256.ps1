param(
  [Parameter(Mandatory = $true)]
  [string]$File,

  [Parameter(Mandatory = $true)]
  [string]$ExpectedFilename
)

$line = Get-Content "$PSScriptRoot\..\checksums.txt" |
  Where-Object {
    $_ -match "^[A-Fa-f0-9]{64}\s{2,}$([regex]::Escape($ExpectedFilename))$"
  }

if (@($line).Count -ne 1) {
  throw "Expected exactly one SHA-256 entry for '$ExpectedFilename'."
}

$expected = (($line -split "\s+")[0]).ToUpperInvariant()
$actual = (Get-FileHash -Algorithm SHA256 $File).Hash.ToUpperInvariant()

if ($actual -ne $expected) {
  throw (
    "SHA-256 mismatch for '$ExpectedFilename'. " +
    "Expected $expected; got $actual."
  )
}

Write-Host "SHA-256 verified for $ExpectedFilename"
