# Run the Telecom Traffic Simulator locally on Windows (dev).
# Usage:  .\run.ps1            (foreground)
#         .\run.ps1 -Background (detached; survives this shell)
param([switch]$Background, [int]$Port = 8080)

Set-Location $PSScriptRoot
python -m pip install -q -r requirements.txt

$args = @("-m","uvicorn","app.main:app","--host","0.0.0.0","--port","$Port")
if ($Background) {
    Start-Process -WindowStyle Hidden -FilePath "python" -ArgumentList $args -WorkingDirectory $PSScriptRoot
    Write-Host "Simulator started in background on http://localhost:$Port"
} else {
    & python @args
}
