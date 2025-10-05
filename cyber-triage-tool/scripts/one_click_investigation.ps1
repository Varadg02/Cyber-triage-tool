param(
  [Parameter(Mandatory=$false)][string]$Target = (Get-Location).Path,
  [Parameter(Mandatory=$false)][string]$OutputDir = "data/cases"
)

Write-Host "Starting one-click investigation..." -ForegroundColor Cyan
python .\main.py --quick-scan "$Target" --output-dir "$OutputDir"

