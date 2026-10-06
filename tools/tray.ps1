# tray.ps1 -- Antinel console tray renderer.
#
# ASCII-only on purpose: Windows PowerShell 5.1 mis-decodes UTF-8 source
# without a BOM, so all Chinese labels are passed in as parameters by Python
# (where the encoding is under our control) and the tray tip is read from
# tray.json with -Encoding UTF8.
#
# Protocol (pure text files, no threads / no pipes / no Win32):
#   in : -State <tray.json>  <- {state, count, tip}
#   out: -Action <file>      <- append one line: open | read_all | quit
#
# The timer polls the state file once a second and swaps the icon + tooltip.
# Icons are pre-generated .ico files (see tools/mk_icons.py); System.Drawing
# loads them directly, so no Pillow and no video decoder are needed.

param(
  [Parameter(Mandatory=$true)][string]$State,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$true)][string]$IconDir,
  [string]$MenuOpen = "Open console",
  [string]$MenuReadAll = "Mark all read",
  [string]$MenuQuit = "Quit tray",
  [string]$DefaultTip = "Antinel"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:lastIcon = ""
$script:utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-Action([string]$a) {
  try {
    [System.IO.File]::AppendAllText($Action, $a + "`n", $script:utf8)
  } catch { }
}

$ni = New-Object System.Windows.Forms.NotifyIcon
$ni.Visible = $true
$ni.Text = $DefaultTip

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$mOpen = $menu.Items.Add($MenuOpen)
$mReadAll = $menu.Items.Add($MenuReadAll)
[void]$menu.Items.Add("-")
$mQuit = $menu.Items.Add($MenuQuit)

$mOpen.add_Click({ Write-Action "open" })
$mReadAll.add_Click({ Write-Action "read_all" })
$mQuit.add_Click({
  $ni.Visible = $false
  $ni.Dispose()
  [System.Windows.Forms.Application]::Exit()
})
$ni.ContextMenuStrip = $menu
$ni.add_MouseClick({ param($s, $e) if ($e.Button -eq "Left") { Write-Action "open" } })

function Update-Tray {
  try {
    if (-not (Test-Path -LiteralPath $State)) { return }
    $j = Get-Content -LiteralPath $State -Raw -Encoding UTF8 | ConvertFrom-Json
    $st = [string]$j.state
    if ([string]::IsNullOrWhiteSpace($st)) { $st = "L0" }
    $ico = Join-Path $IconDir ($st + ".ico")
    if ((Test-Path -LiteralPath $ico) -and ($ico -ne $script:lastIcon)) {
      $old = $ni.Icon
      $ni.Icon = New-Object System.Drawing.Icon($ico)
      if ($old) { $old.Dispose() }
      $script:lastIcon = $ico
    }
    $tip = [string]$j.tip
    if ([string]::IsNullOrWhiteSpace($tip)) { $tip = $DefaultTip }
    if ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }
    $ni.Text = $tip
  } catch { }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.add_Tick({ Update-Tray })
$timer.Start()
Update-Tray

try {
  [System.Windows.Forms.Application]::Run()
} finally {
  $ni.Visible = $false
  $ni.Dispose()
}
