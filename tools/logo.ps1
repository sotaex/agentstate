# logo.ps1 -- Antinel console: floating sentry mark (minimum presence state).
#
# ASCII-only on purpose (same discipline as tray.ps1): Windows PowerShell 5.1
# mis-decodes UTF-8 source without a BOM, so every Chinese label arrives as a
# parameter from Python, where the encoding is under our control.
#
# Protocol (pure text files, no threads / no pipes / no Win32):
#   in : -State <tray.json>   <- {state, shield, tip, ts}  (same file the tray reads)
#   in : -Quit  <logo.quit>   <- file EXISTS  => this window exits at next poll
#   out: -Action <tray_action.txt> <- append one line: open
#
# 0.50.0: the console's minimum state ("floating"). The console is a big
# window nobody wants on screen all day; the sentry only has to BE there.
# This window draws the SAME five-state motion as the console header logo
# (spec: "Antinel brand motion alarm syntax v1.2"; single source of the
# numbers is inbox_server.LOGO_MOTION -- the guard c_logo_motion_spec_locked
# parses this file and compares them digit by digit).
#
# Motion channels (scaled to a 46px badge, NOT the full 1024 canvas):
#   drawn with System.Drawing (vector), so no .ico files are needed here --
#   the ring color / sweep speed / bob are computed from the same table.
#   ring color  : green (91,130,101) in L0..Ls, dark red (74,38,38) at R0
#   sweep speed : 12 / 8 / 5.5 / 3.5 s per turn (L0 / L1 / L2 / Ls)
#   bob (wave)  : 0 / 2 / 3 / 4 px at 1.4s period (waveR 0/45/70/105 scaled)
#   R0          : gradient BREAK -- coasts 20 deg, then stops forever;
#                 ring drawn dim (alpha .45), exactly like the console.
#
# Click vs drag: movement under 5px and under 1s is a click (write "open"
# and exit); anything larger is a drag (move the window, do NOT open).

param(
  [Parameter(Mandatory=$true)][string]$State,
  [Parameter(Mandatory=$true)][string]$Action,
  [Parameter(Mandatory=$true)][string]$Quit,
  [Parameter(Mandatory=$true)][string]$Title,
  [int]$Size = 46,
  [int]$X = -1,
  [int]$Y = -1,
  [string]$Tip = "Antinel",
  [string]$TipStale = "state has stopped updating",
  [int]$StaleAfterSec = 30
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:utf8 = New-Object System.Text.UTF8Encoding($false)

# --- five-state motion table. NUMBERS MUST MATCH inbox_server.LOGO_MOTION ---
$MOTION = @{
  "L0" = @{ c = @(126,155,132); lap = 12.0; ringO = 1.0;  waveR = 0;   }
  "L1" = @{ c = @(205,194,154); lap = 8.0;  ringO = 1.0;  waveR = 45;  }
  "L2" = @{ c = @(224,180,85);  lap = 5.5;  ringO = 1.0;  waveR = 70;  }
  "LD" = @{ c = @(232,163,61);  lap = 3.5;  ringO = 1.0;  waveR = 105; }
  "R0" = @{ c = @(178,84,84);   lap = 0.0;  ringO = 0.45; waveR = 0;   }
}
$RING_GREEN   = @(91,130,101)
$RING_DARKRED = @(74,38,38)
$LAP_COAST    = 5.5      # R0 coasts at L2 speed, 20 deg, then stops (spec)
#: light state -> motion key (Ls uses the spec's LD) -- same table as
#: inbox_server.LOGO_MODE; keys are ASCII so the file stays ASCII-only.
$MODE = @{ "L0"="L0"; "L1"="L1"; "L2"="L2"; "Ls"="LD"; "R0"="R0"; "dev"="L0" }

function Write-Action([string]$a) {
  try {
    [System.IO.File]::AppendAllText($Action, $a + "`n", $script:utf8)
    return $true
  } catch {
    $script:actionWriteFailed = $true
    return $false
  }
}

# Keep the source ASCII-only for Windows PowerShell 5.1 (no-BOM UTF-8 is ACP-decoded).
$script:actionWriteFailed = $false
$script:actionWriteFailTip = -join [char[]]@(0x5C55,0x5F00,0x5931,0x8D25,0xFF1A,
  0x52A8,0x4F5C,0x5199,0x5165,0x5931,0x8D25,0xFF0C,0x8BF7,0x518D,0x70B9,0x4E00,0x6B21)

# ---------------------------------------------------------------- window ---
$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size($Size, $Size)
# ★ measured on this machine: a borderless Form still carries the system
#   minimum *tracking* width (SM_CXMINTRACK = 136) -- the window came out
#   136x46 even though Size was 46x46. Pin both edges so the badge is exactly
#   $Size x $Size (the finder/geometry math below assumes square).
$form.MinimumSize = New-Object System.Drawing.Size($Size, $Size)
$form.MaximumSize = New-Object System.Drawing.Size($Size, $Size)
$form.FormBorderStyle = "None"
$form.StartPosition = "Manual"
$form.ShowInTaskbar = $false
$form.TopMost = $true
$form.BackColor = [System.Drawing.Color]::Fuchsia
$form.TransparencyKey = [System.Drawing.Color]::Fuchsia
$form.Text = $Title
$wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
# DEFAULT position: right-bottom, just above the taskbar (like an IME bar).
# NOTE: the geometry is computed on SEPARATE lines on purpose. Passing the
# arithmetic straight into New-Object's argument list
# (`New-Object Point($wa.Right - $Size - 8, ...)`) makes the command-argument
# parser read `-$Size` as a *parameter token* named Size -- the expression is
# then split into an [Object[]] and the constructor blows up with
# "op_Subtraction not found on [System.Object[]]". Measured on this machine.
$markX = $wa.Right - $Size - 8
$markY = $wa.Bottom - $Size - 8
if ($X -ge 0 -and $Y -ge 0) {
  $form.Location = New-Object System.Drawing.Point($X, $Y)
} else {
  $form.Location = New-Object System.Drawing.Point($markX, $markY)
}

$script:mode = "L0"
$script:ang = 0.0
$script:coast = 0.0
$script:t0 = [DateTime]::UtcNow
$script:lastPoll = [DateTime]::MinValue
$script:trayStale = $true
$script:tip = $Tip
# NOTE: the window title is NOT the tooltip here -- unlike tray.ps1, the title
# carries the find mark (" Antinel - sentry mark"), so Python can find and
# topmost this window (inbox_window.find_logo_windows). The state tip rides on
# a real ToolTip instead; overwriting .Text would blind the finder.
$tipCtl = New-Object System.Windows.Forms.ToolTip
$tipCtl.SetToolTip($form, $Tip)

$script:dragging = $false
$script:downAt = $null
$script:downPt = [System.Drawing.Point]::Empty
$script:moved = 0

function Read-State {
  # stale guard (same rule as tray.ps1): never render a long-dead state as now
  if (([DateTime]::UtcNow - $script:lastPoll).TotalMilliseconds -lt 250) { return }
  $script:lastPoll = [DateTime]::UtcNow
  try {
    if (-not (Test-Path -LiteralPath $State)) { $script:trayStale = $true; return }
    $j = Get-Content -LiteralPath $State -Raw -Encoding UTF8 | ConvertFrom-Json
    $st = [string]$j.state
    if ([string]::IsNullOrWhiteSpace($st)) { $st = "L0" }
    $k = "L0"
    if ($MODE.ContainsKey($st)) { $k = $MODE[$st] }
    if ($k -ne $script:mode) {
      if ($k -eq "R0") { $script:coast = 20.0 }   # spec: R0 coasts 20 deg then stops
      $script:mode = $k
    }
    $t = [string]$j.tip
    if ([string]::IsNullOrWhiteSpace($t)) { $t = $Tip }
    $script:tip = $t
    $age = -1
    if ($j.PSObject.Properties.Name -contains "ts") {
      try { $age = [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) - [int64]($j.ts) } catch { $age = -1 }
    }
    $script:trayStale = (($age -lt 0) -or ($age -gt $StaleAfterSec))
  } catch { $script:trayStale = $true }
}

function Step([double]$dt) {
  if ($script:mode -eq "R0") {
    if ($script:coast -gt 0) {
      $d = 360.0 / $LAP_COAST * $dt
      if ($d -gt $script:coast) { $d = $script:coast }
      $script:ang = ($script:ang + $d) % 360.0
      $script:coast -= $d
    }
    return
  }
  $lap = 12.0
  if ($MOTION.ContainsKey($script:mode)) { $lap = $MOTION[$script:mode]["lap"] }
  if ($lap -le 0) { return }
  $script:ang = ($script:ang + 360.0 / $lap * $dt) % 360.0
}

$form.add_Paint({
  param($s, $e)
  try {
    $g = $e.Graphics
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $m = $MOTION[$script:mode]
    $c = $m["c"]; $ringO = $m["ringO"]; $waveR = $m["waveR"]
    # bob: wave amplitude scaled to the badge (105px @1024 -> 4px @46)
    $t = (([DateTime]::UtcNow) - $script:t0).TotalSeconds
    $bob = [Math]::Round([Math]::Sin($t * 2 * [Math]::PI / 1.4) * ($waveR / 105.0 * 4.0), 2)
    $cx = [double]($Size / 2.0)
    $cy = [double]($Size / 2.0) + $bob
    $R = [double]($Size / 2.0 - 5.0)
    # base ring: territory color (green / R0 dark red)
    $rc = $RING_GREEN
    if ($script:mode -eq "R0") { $rc = $RING_DARKRED }
    $penRing = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, $rc[0], $rc[1], $rc[2]), 3.0)
    $g.DrawEllipse($penRing, [float]($cx - $R), [float]($cy - $R), [float](2 * $R), [float](2 * $R))
    $penRing.Dispose()
    # rotating sweep: state color, ring opacity (R0 dims to .45 = gradient break)
    $a = [int]([Math]::Round(255 * $ringO))
    $penArc = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb($a, $c[0], $c[1], $c[2]), 3.0)
    $g.DrawArc($penArc, [float]($cx - $R), [float]($cy - $R), [float](2 * $R), [float](2 * $R), [float]$script:ang, 100.0)
    $penArc.Dispose()
    # center dot
    $br = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, $c[0], $c[1], $c[2]))
    $g.FillEllipse($br, [float]($cx - 3.5), [float]($cy - 3.5), 7.0, 7.0)
    $br.Dispose()
  } catch { }
})

function Quit-Now {
  try { $form.Close() } catch { }
  [System.Windows.Forms.Application]::Exit()
}

$form.add_MouseDown({
  param($s, $e)
  if ($e.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
  $script:dragging = $true
  $script:downAt = [DateTime]::UtcNow
  $script:downPt = $e.Location
  $script:moved = 0
})
$form.add_MouseMove({
  param($s, $e)
  if (-not $script:dragging) { return }
  $dx = $e.X - $script:downPt.X
  $dy = $e.Y - $script:downPt.Y
  $script:moved = [Math]::Max($script:moved, [Math]::Max([Math]::Abs($dx), [Math]::Abs($dy)))
  $np = $form.PointToScreen([System.Drawing.Point]::new($e.X, $e.Y))
  $nx = $np.X - $script:downPt.X
  $ny = $np.Y - $script:downPt.Y
  if ($nx -lt $wa.Left) { $nx = $wa.Left }
  if ($ny -lt $wa.Top) { $ny = $wa.Top }
  if ($nx + $Size -gt $wa.Right) { $nx = $wa.Right - $Size }
  if ($ny + $Size -gt $wa.Bottom) { $ny = $wa.Bottom - $Size }
  $form.Location = New-Object System.Drawing.Point($nx, $ny)
})
$form.add_MouseUp({
  param($s, $e)
  if (-not $script:dragging) { return }
  $script:dragging = $false
  $dt = (([DateTime]::UtcNow) - $script:downAt).TotalSeconds
  if (($script:moved -le 5) -and ($dt -le 1.0)) {
    if (Write-Action "open") { Quit-Now }
  }
})

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 40
$last = [DateTime]::UtcNow
$timer.add_Tick({
  if (Test-Path -LiteralPath $Quit) { Quit-Now }
  Read-State
  $now = [DateTime]::UtcNow
  $dt = ($now - $last).TotalSeconds
  $last = $now
  if ($dt -lt 0) { $dt = 0 }
  if ($dt -gt 0.25) { $dt = 0.25 }
  Step $dt
  $form.Invalidate()
  $tp = $script:tip
  if ($script:trayStale) { $tp = $TipStale }
  if ($script:actionWriteFailed) { $tp = $script:actionWriteFailTip }
  if ($tp.Length -gt 63) { $tp = $tp.Substring(0, 63) }
  try { $tipCtl.SetToolTip($form, $tp) } catch { }
})
$timer.Start()

try {
  [System.Windows.Forms.Application]::Run($form)
} finally {
  $timer.Stop()
  try { $form.Dispose() } catch { }
}
