# Signs SysmonChecker-<version>.exe with the code signing certificate from Cert:\CurrentUser\My.
# Called by build.cmd after the exe has been copied to the application folder; skipped when the certificate is not present.
# Without -Version the version is read from SysmonChecker.csproj.
param(
    [string[]]$Files,
    [string]$Version,
    [string]$Subject = 'CN=SysmonChecker Code Signing',
    [string]$TimestampServer = 'http://timestamp.digicert.com'
)
$root = Split-Path -Parent $PSScriptRoot
if (-not $Files) {
    if (-not $Version) {
        $m = Select-String -LiteralPath (Join-Path $PSScriptRoot 'SysmonChecker.csproj') -Pattern '<Version>([\d.]+)</Version>' | Select-Object -First 1
        if (-not $m) { throw 'Version not found in SysmonChecker.csproj' }
        $Version = $m.Matches[0].Groups[1].Value
    }
    $Files = @("SysmonChecker-$Version.exe")
}
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.Subject -eq $Subject -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $cert) { Write-Host "Signing skipped: no certificate '$Subject' in Cert:\CurrentUser\My"; exit 0 }
foreach ($f in $Files) {
    $path = Join-Path $root $f
    $r = $null
    # a freshly built exe can be locked for a moment by the antivirus scan
    for ($try = 0; $try -lt 5 -and -not ($r -and $r.SignerCertificate); $try++) {
        if ($try) { Start-Sleep -Seconds 2 }
        try { $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer -ErrorAction Stop } catch { $r = $null }
        if (-not $r -or -not $r.SignerCertificate) {
            # Offline: sign without timestamp (signature then expires with the certificate)
            try { $r = Set-AuthenticodeSignature $path -Certificate $cert -HashAlgorithm SHA256 -ErrorAction Stop } catch { $r = $null }
        }
    }
    Write-Host ("Signed {0}: {1}" -f $f, $(if ($r) { $r.Status } else { 'FAILED' }))
    # without a timestamp the signature becomes invalid when the certificate expires - say so
    if ($r -and $r.SignerCertificate -and -not $r.TimeStamperCertificate) {
        Write-Warning "$f was signed WITHOUT a timestamp ($TimestampServer not reachable) - sign it again when online."
    }
}
