# tray.ps1 -- Antinel console tray renderer.
#
# ASCII-only on purpose: Windows PowerShell 5.1 mis-decodes UTF-8 source
# without a BOM, so all Chinese labels are passed in as parameters by Python
# (where the encoding is under our control) and the tray tip is read from
# tray.json with -Encoding UTF8.
#
# Protocol (pure text files, no threads / no pipes / no Win32):
#   in : -State <tray.json>  <- {state, count, tip, ts}
#
# 0.35.3: "ts" is epoch seconds written by Python. If it goes stale the tray
#   must SAY SO instead of showing the last known state forever -- "no longer
#   updated" must never render as "everything is fine".
#   out: -Action <file>      <- append one line: open | quit
#        (0.35.3: "read_all" removed -- the bulk "Mark all read" item is gone)
#
# The timer polls the state file once a second and swaps the icon + tooltip.
# Icons are pre-generated .ico files (see tools/mk_icons.py); System.Drawing
# loads them directly, so no Pillow and no video decoder are needed.

param(
  [Parameter(Mandatory=$true)][string]$State,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$true)][string]$IconDir,
  [string]$MenuOpen = "Open console",
  [string]$MenuQuit = "Quit tray",
  [string]$DefaultTip = "Antinel",
  [int]$StaleAfterSec = 30,
  [string]$StaleTip = "tray state no longer updated"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:lastIcon = ""
$script:utf8 = New-Object System.Text.UTF8Encoding($false)

# 0.36.0: shield state -> icon file suffix. MUST stay in sync with
# inbox_tray.SHIELD_SUFFIX. Five event states alone can NOT show whether the
# sentinel is on duty -- measured: icon showed R0 written 27 minutes ago while
# guard_posture() said "guarding" and the sentinel was alive (pid 83352).
# That is the icon lying. So the icon is now event-state x sentinel-state,
# with the sentinel state carried as a badge drawn by mk_icons.py.
$SHIELD_SUFFIX = @{
  "on"       = ""
  "unposted" = "-unposted"
  "unknown"  = "-unknown"
  "off"      = "-off"
}

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
[void]$menu.Items.Add("-")
$mQuit = $menu.Items.Add("Quit tray")

$mOpen.add_Click({ Write-Action "open" })
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

    # 0.36.0: pick the combined icon. Falls back to the plain one when the
    # combined file is absent -- and says so via the tooltip, rather than
    # silently pretending the badge is there.
    $sh = ""
    if ($j.PSObject.Properties.Name -contains "shield") { $sh = [string]$j.shield }
    if ([string]::IsNullOrWhiteSpace($sh)) { $sh = "unknown" }
    $sfx = ""
    if ($SHIELD_SUFFIX.ContainsKey($sh)) { $sfx = $SHIELD_SUFFIX[$sh] }
    # 2026-10-20 (founder: "all three places use the logo"): the tray icon is
    # the BRAND mark, static. A posture light is not a logo -- it *changes with
    # the current state*, so using it as the product icon means the icon itself
    # claims "right now nothing is wrong", which is a false statement and, in
    # practice, reads as "a circle" rather than as this product.
    # Posture is still readable: it lives in $tip (hover) and in the panel.
    # Degrade honestly: if the brand .ico is missing, fall back to the old
    # per-state family instead of drawing nothing.
    $brandIco = Join-Path (Split-Path -Parent $IconDir) "logo\antinel.ico"
    if (Test-Path -LiteralPath $brandIco) {
      $ico = $brandIco
      $badgeMissing = $false
    } else {
      $ico = Join-Path $IconDir ($st + $sfx + ".ico")
      if (-not (Test-Path -LiteralPath $ico)) {
        $badgeMissing = $true
        $ico = Join-Path $IconDir ($st + ".ico")
      }
    }

    if ((Test-Path -LiteralPath $ico) -and ($ico -ne $script:lastIcon)) {
      $old = $ni.Icon
      $ni.Icon = New-Object System.Drawing.Icon($ico)
      if ($old) { $old.Dispose() }
      $script:lastIcon = $ico
    }
    $tip = [string]$j.tip
    if ([string]::IsNullOrWhiteSpace($tip)) { $tip = $DefaultTip }
    if ($badgeMissing) { $tip = "$tip; (sentinel state icon not built yet)" }

    # 0.35.3: stale guard -- never render "not updating" as "all good".
    $age = -1
    if ($j.PSObject.Properties.Name -contains "ts") {
      try { $age = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) - [int64]($j.ts) } catch { $age = -1 }
    }
    if (($age -lt 0) -or ($age -gt $StaleAfterSec)) {
      $tip = $StaleTip
      if ($age -ge 0) { $tip = "$StaleTip ${age}s ago" }
      if ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }
    } elseif ($tip.Length -gt 63) { $tip = $tip.Substring(0, 63) }

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
